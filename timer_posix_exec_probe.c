/*
 * timer_posix_exec_probe.c
 *
 * Controlled userspace probe for POSIX CPU timers around execve() initiated
 * by a non-leader thread on Linux/Android.
 *
 * Purpose:
 *   - Create and arm a process CPU timer in a child process.
 *   - Have a non-leader pthread exec this same binary.
 *   - Confirm the new image starts and exits normally.
 *   - Record syscall/API outcomes only; do not infer kernel memory safety.
 *
 * This program does NOT dereference kernel addresses, attempt exploitation,
 * or prove/disprove a use-after-free. A PASS means only that the tested
 * userspace operations completed as expected.
 *
 * Build (Android NDK):
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *     -Wconversion -Wshadow -pthread timer_posix_exec_probe.c \
 *     -o timer_posix_exec_probe
 *
 * Run:
 *   ./timer_posix_exec_probe [cycles]
 *
 * Suggested first run: 20 cycles. Increase only after reviewing device logs.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
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
#define HELPER_ARG "--exec-helper"
#define TIMER_SIGNAL SIGUSR1

static volatile sig_atomic_t timer_signals;
static atomic_int worker_ready;
static char *self_path;

static void timer_handler(int signo)
{
    (void)signo;
    if (timer_signals < 1000000)
        ++timer_signals;
}

static int parse_cycles(int argc, char **argv)
{
    char *end = NULL;
    long value;

    if (argc < 2)
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

static void burn_cpu_for_about_one_ms(void)
{
    struct timespec start;
    struct timespec now;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start) != 0)
        return;

    do {
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now) != 0)
            return;
    } while ((now.tv_sec - start.tv_sec) * INT64_C(1000000000) +
             (now.tv_nsec - start.tv_nsec) < INT64_C(1000000));
}

static void *exec_worker(void *opaque)
{
    char **exec_argv = (char **)opaque;

    atomic_store_explicit(&worker_ready, 1, memory_order_release);

    /*
     * A short wall-clock delay gives the leader a chance to consume CPU and
     * approach timer expiry. This is intentionally a small, bounded probe.
     */
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000L };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        /* Resume the remaining delay. */
    }

    execv(self_path, exec_argv);

    /* Reached only if execv failed. */
    dprintf(STDERR_FILENO, "ERROR execv: %s\n", strerror(errno));
    _exit(120);
}

static int run_one_cycle(int cycle)
{
    pid_t child = fork();
    int status = 0;

    if (child < 0) {
        printf("RESULT cycle=%d fork=FAIL errno=%d\n", cycle, errno);
        return -1;
    }

    if (child == 0) {
        struct sigaction action;
        struct sigevent event;
        struct itimerspec setting;
        timer_t timer_id;
        pthread_t worker;
        char *exec_argv[3];
        int rc;

        memset(&action, 0, sizeof(action));
        action.sa_handler = timer_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        if (sigaction(TIMER_SIGNAL, &action, NULL) != 0) {
            dprintf(STDERR_FILENO, "ERROR sigaction: %s\n", strerror(errno));
            _exit(10);
        }

        memset(&event, 0, sizeof(event));
        event.sigev_notify = SIGEV_SIGNAL;
        event.sigev_signo = TIMER_SIGNAL;

        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &event, &timer_id) != 0) {
            dprintf(STDERR_FILENO, "ERROR timer_create: %s\n", strerror(errno));
            _exit(11);
        }

        memset(&setting, 0, sizeof(setting));
        setting.it_value.tv_nsec = 1000000L; /* 1 ms process CPU time */
        if (timer_settime(timer_id, 0, &setting, NULL) != 0) {
            dprintf(STDERR_FILENO, "ERROR timer_settime: %s\n", strerror(errno));
            (void)timer_delete(timer_id);
            _exit(12);
        }

        atomic_store_explicit(&worker_ready, 0, memory_order_relaxed);
        exec_argv[0] = self_path;
        exec_argv[1] = (char *)HELPER_ARG;
        exec_argv[2] = NULL;

        rc = pthread_create(&worker, NULL, exec_worker, exec_argv);
        if (rc != 0) {
            dprintf(STDERR_FILENO, "ERROR pthread_create: %s\n", strerror(rc));
            (void)timer_delete(timer_id);
            _exit(13);
        }

        while (!atomic_load_explicit(&worker_ready, memory_order_acquire)) {
            /* Wait briefly for the non-leader thread to start. */
            sched_yield();
        }

        /*
         * Consume a small amount of leader-thread CPU while the other thread
         * proceeds to execv(). The exec replaces the multithreaded process.
         */
        burn_cpu_for_about_one_ms();

        /*
         * Keep the leader alive until the worker execs. A successful exec
         * replaces this process image; if execv fails, the worker calls
         * _exit(120), terminating the process with a visible failure status.
         */
        for (;;)
            burn_cpu_for_about_one_ms();
    }

    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        printf("RESULT cycle=%d waitpid=FAIL errno=%d\n", cycle, errno);
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("RESULT cycle=%d nonleader_exec=PASS helper_started=1\n", cycle);
        return 0;
    }

    if (WIFEXITED(status)) {
        printf("RESULT cycle=%d nonleader_exec=FAIL child_exit=%d\n",
               cycle, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("RESULT cycle=%d nonleader_exec=FAIL child_signal=%d\n",
               cycle, WTERMSIG(status));
    } else {
        printf("RESULT cycle=%d nonleader_exec=FAIL child_status=unknown\n",
               cycle);
    }
    return -1;
}

int main(int argc, char **argv)
{
    int cycles;
    int failures = 0;
    int i;

    if (argc == 2 && strcmp(argv[1], HELPER_ARG) == 0) {
        puts("HELPER exec_image_started=1");
        return 0;
    }

    self_path = argv[0];
    cycles = parse_cycles(argc, argv);
    if (cycles < 1)
        return 2;

    printf("POSIX CPU timer non-leader exec probe\n");
    printf("PID=%ld cycles=%d timer_signal=SIGUSR1 timer_cpu_ns=1000000\n",
           (long)getpid(), cycles);
    puts("Scope: userspace API outcomes only; not a kernel UAF proof.");

    for (i = 1; i <= cycles; ++i) {
        if (run_one_cycle(i) != 0)
            ++failures;
    }

    printf("SUMMARY cycles=%d failures=%d status=%s\n",
           cycles, failures, failures == 0 ? "PASS" : "FAIL");
    puts("NOTE: PASS does not prove timer cleanup internals or memory safety.");
    puts("NOTE: Standard signals can coalesce; signal counts are not exact.");
    return failures == 0 ? 0 : 1;
}
