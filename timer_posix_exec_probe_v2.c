/*
 * timer_posix_exec_probe_v2.c
 *
 * Controlled Linux/Android userspace probe for a process CPU timer across
 * execve() initiated by a non-leader pthread.
 *
 * This tests API outcomes only. It does not prove or disprove a kernel UAF.
 *
 * Build:
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *     -Wconversion -Wshadow -pthread timer_posix_exec_probe_v2.c \
 *     -o timer_posix_exec_probe_v2
 *
 * Run:
 *   ./timer_posix_exec_probe_v2 [cycles]
 *
 * Default: 20 cycles; maximum: 1000.
 */

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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_CYCLES 20
#define MAX_CYCLES 1000
#define CHILD_TIMEOUT_MS 5000
#define HELPER_ARG "--exec-helper"
#define TIMER_SIGNAL SIGUSR1
#define TIMER_NS 1000000L
#define CPU_BURN_NS 10000000LL

static atomic_int worker_ready;
static atomic_int allow_exec;
static char *self_path;
static char **helper_argv;
static char *exec_argv_storage[3];
static int status_pipe_fd = -1;

static int parse_cycles(int argc, char **argv)
{
    char *end = NULL;
    long value;

    if (argc == 1)
        return DEFAULT_CYCLES;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [cycles]\n", argv[0]);
        return -1;
    }

    errno = 0;
    value = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' ||
        value < 1 || value > MAX_CYCLES) {
        fprintf(stderr, "cycles must be in the range 1..%d\n", MAX_CYCLES);
        return -1;
    }

    return (int)value;
}

static int burn_process_cpu_for(long long duration_ns)
{
    struct timespec start;
    struct timespec now;

    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start) != 0)
        return -1;

    do {
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now) != 0)
            return -1;

        long long elapsed =
            ((long long)now.tv_sec - (long long)start.tv_sec) * 1000000000LL +
            ((long long)now.tv_nsec - (long long)start.tv_nsec);
        if (elapsed >= duration_ns)
            break;

        sched_yield();
    } while (1);

    return 0;
}

static void *exec_worker(void *unused)
{
    (void)unused;

    atomic_store_explicit(&worker_ready, 1, memory_order_release);
    while (atomic_load_explicit(&allow_exec, memory_order_acquire) == 0)
        sched_yield();

    execv(self_path, helper_argv);

    int saved_errno = errno;
    dprintf(STDERR_FILENO, "ERROR execv: errno=%d (%s)\n",
            saved_errno, strerror(saved_errno));
    _exit(120);
}

static int write_status_byte(char value)
{
    ssize_t written;

    do {
        written = write(status_pipe_fd, &value, 1);
    } while (written < 0 && errno == EINTR);

    return written == 1 ? 0 : -1;
}

static void child_cycle(void)
{
    sigset_t blocked;
    siginfo_t signal_info;
    struct sigevent event;
    struct itimerspec setting;
    struct timespec wait_timeout = { .tv_sec = 0, .tv_nsec = 100000000L };
    timer_t timer_id;
    pthread_t worker;
    int rc;
    int signal_seen = 0;

    sigemptyset(&blocked);
    sigaddset(&blocked, TIMER_SIGNAL);
    if (pthread_sigmask(SIG_BLOCK, &blocked, NULL) != 0) {
        dprintf(STDERR_FILENO, "ERROR pthread_sigmask\n");
        _exit(10);
    }

    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = TIMER_SIGNAL;

    if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &event, &timer_id) != 0) {
        int saved_errno = errno;
        dprintf(STDERR_FILENO, "ERROR timer_create: errno=%d (%s)\n",
                saved_errno, strerror(saved_errno));
        _exit(11);
    }

    memset(&setting, 0, sizeof(setting));
    setting.it_value.tv_nsec = TIMER_NS;
    if (timer_settime(timer_id, 0, &setting, NULL) != 0) {
        int saved_errno = errno;
        dprintf(STDERR_FILENO, "ERROR timer_settime: errno=%d (%s)\n",
                saved_errno, strerror(saved_errno));
        (void)timer_delete(timer_id);
        _exit(12);
    }

    atomic_store_explicit(&worker_ready, 0, memory_order_relaxed);
    atomic_store_explicit(&allow_exec, 0, memory_order_relaxed);

    rc = pthread_create(&worker, NULL, exec_worker, NULL);
    if (rc != 0) {
        dprintf(STDERR_FILENO, "ERROR pthread_create: errno=%d (%s)\n",
                rc, strerror(rc));
        (void)timer_delete(timer_id);
        _exit(13);
    }

    while (atomic_load_explicit(&worker_ready, memory_order_acquire) == 0)
        sched_yield();

    /*
     * The signal is blocked in all threads and is consumed synchronously.
     * CPU time is burned so the process CPU timer can expire while the
     * non-leader waits to exec. Standard signals may coalesce.
     */
    if (burn_process_cpu_for(CPU_BURN_NS) != 0) {
        dprintf(STDERR_FILENO, "ERROR clock_gettime while burning CPU\n");
        (void)write_status_byte('E');
        close(status_pipe_fd);
        _exit(14);
    }

    int sig = sigtimedwait(&blocked, &signal_info, &wait_timeout);
    if (sig == TIMER_SIGNAL) {
        signal_seen = 1;
    } else if (sig < 0 && errno != EAGAIN && errno != EINTR) {
        int saved_errno = errno;
        dprintf(STDERR_FILENO, "ERROR sigtimedwait: errno=%d (%s)\n",
                saved_errno, strerror(saved_errno));
        (void)write_status_byte('E');
        close(status_pipe_fd);
        _exit(15);
    }

    if (write_status_byte(signal_seen ? 'S' : 'T') != 0) {
        dprintf(STDERR_FILENO, "ERROR writing status pipe\n");
        close(status_pipe_fd);
        _exit(16);
    }

    /* Do not delete the timer here: execve() is the lifecycle under test. */
    close(status_pipe_fd);
    atomic_store_explicit(&allow_exec, 1, memory_order_release);

    /*
     * A successful exec replaces this image. The helper exits with status 0.
     * If execv fails, exec_worker exits with status 120.
     */
    for (;;)
        pause();
}

static int read_status_pipe(int fd, char *value)
{
    ssize_t n;

    do {
        n = read(fd, value, 1);
    } while (n < 0 && errno == EINTR);

    close(fd);
    return n == 1 ? 0 : -1;
}

static int run_one_cycle(int cycle)
{
    int pipefd[2];
    pid_t child;
    int status = 0;
    int elapsed_ms = 0;
    char timer_status = '?';

    if (pipe(pipefd) != 0) {
        printf("RESULT cycle=%d pipe=FAIL errno=%d\n", cycle, errno);
        return -1;
    }

    child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        printf("RESULT cycle=%d fork=FAIL errno=%d\n", cycle, saved_errno);
        return -1;
    }

    if (child == 0) {
        close(pipefd[0]);
        status_pipe_fd = pipefd[1];
        child_cycle();
        _exit(99);
    }

    close(pipefd[1]);

    while (elapsed_ms < CHILD_TIMEOUT_MS) {
        pid_t result = waitpid(child, &status, WNOHANG);

        if (result == child)
            break;

        if (result < 0) {
            if (errno == EINTR)
                continue;
            printf("RESULT cycle=%d waitpid=FAIL errno=%d\n", cycle, errno);
            close(pipefd[0]);
            return -1;
        }

        struct timespec pause_time = { .tv_sec = 0, .tv_nsec = 10000000L };
        while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR)
            ;
        elapsed_ms += 10;
    }

    if (elapsed_ms >= CHILD_TIMEOUT_MS) {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
            ;
        close(pipefd[0]);
        printf("RESULT cycle=%d status=INCOMPLETE reason=timeout timeout_ms=%d\n",
               cycle, CHILD_TIMEOUT_MS);
        return -1;
    }

    if (read_status_pipe(pipefd[0], &timer_status) != 0) {
        printf("RESULT cycle=%d status=INCOMPLETE reason=no_timer_status\n",
               cycle);
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (timer_status == 'S') {
            printf("RESULT cycle=%d nonleader_exec=PASS timer_signal=SEEN helper_exit=0\n",
                   cycle);
            return 0;
        }

        if (timer_status == 'T') {
            printf("RESULT cycle=%d nonleader_exec=PASS timer_signal=NOT_SEEN helper_exit=0\n",
                   cycle);
            return 1;
        }

        printf("RESULT cycle=%d status=INCOMPLETE reason=timer_status_%c helper_exit=0\n",
               cycle, timer_status);
        return -1;
    }

    if (WIFEXITED(status)) {
        printf("RESULT cycle=%d nonleader_exec=FAIL child_exit=%d timer_status=%c\n",
               cycle, WEXITSTATUS(status), timer_status);
    } else if (WIFSIGNALED(status)) {
        printf("RESULT cycle=%d nonleader_exec=FAIL child_signal=%d timer_status=%c\n",
               cycle, WTERMSIG(status), timer_status);
    } else {
        printf("RESULT cycle=%d status=INCOMPLETE reason=unknown_child_status\n",
               cycle);
    }

    return -2;
}

int main(int argc, char **argv)
{
    int cycles;
    int failures = 0;
    int incomplete = 0;
    int signal_seen = 0;
    int signal_not_seen = 0;
    int i;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc == 2 && strcmp(argv[1], HELPER_ARG) == 0) {
        puts("HELPER exec_image_started=1");
        return 0;
    }

    self_path = argv[0];
    exec_argv_storage[0] = self_path;
    exec_argv_storage[1] = (char *)HELPER_ARG;
    exec_argv_storage[2] = NULL;
    helper_argv = exec_argv_storage;

    cycles = parse_cycles(argc, argv);
    if (cycles < 1)
        return 2;

    printf("POSIX CPU timer non-leader exec probe v2\n");
    printf("PID=%ld cycles=%d timer_signal=SIGUSR1 timer_cpu_ns=%ld timeout_ms=%d\n",
           (long)getpid(), cycles, TIMER_NS, CHILD_TIMEOUT_MS);
    puts("Scope: userspace API outcomes only; not a kernel UAF proof.");

    for (i = 1; i <= cycles; ++i) {
        int rc = run_one_cycle(i);

        if (rc == -2) {
            ++failures;
        } else if (rc < 0) {
            ++incomplete;
        } else if (rc > 0) {
            ++signal_not_seen;
        } else {
            ++signal_seen;
        }
    }

    printf("SUMMARY cycles=%d signal_seen=%d signal_not_seen=%d failures=%d incomplete=%d status=%s\n",
           cycles, signal_seen, signal_not_seen, failures, incomplete,
           (failures == 0 && incomplete == 0 && signal_not_seen == 0) ?
               "PASS" : "CHECK");

    puts("NOTE: PASS covers only the observed userspace/API checks.");
    puts("NOTE: It does not prove kernel memory safety or absence of a UAF.");
    puts("NOTE: Standard signals may coalesce; this test checks one expiry signal per cycle.");

    return (failures == 0 && incomplete == 0 && signal_not_seen == 0) ? 0 : 1;
}
