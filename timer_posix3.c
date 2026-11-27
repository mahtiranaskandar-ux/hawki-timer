/*
 * timer_posix.c - Numeric diagnostics for POSIX CPU timers on Android ARM64.
 *
 * Measures user-visible behavior only. It does NOT read kernel struct offsets,
 * prove kernel memory safety, or establish that a particular kernel path ran.
 *
 * Build (Android NDK):
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *       -Wconversion -Wshadow -pthread timer_posix.c -o timer_posix
 *
 * Run:
 *   ./timer_posix             # 10 iterations per clock
 *   ./timer_posix 500         # 500 iterations per clock
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ITERATIONS 10
#define MAX_ITERATIONS 10000
#define TIMER_NS 20000000L
#define WALL_TIMEOUT_NS 3000000000LL

static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t last_signal;

static void on_timer_signal(int signo)
{
    last_signal = signo;
    signal_count++;
}

static int64_t timespec_to_ns(struct timespec ts)
{
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static double ns_to_seconds(int64_t ns)
{
    return (double)ns / 1000000000.0;
}

static int get_clock_ns(clockid_t id, int64_t *out)
{
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0)
        return -1;
    *out = timespec_to_ns(ts);
    return 0;
}

static void print_errno(const char *what)
{
    fprintf(stderr, "ERROR: %s failed: errno=%d (%s)\n",
            what, errno, strerror(errno));
}

static int run_one(clockid_t clock_id, const char *clock_name,
                   int iteration, int *failures, int *incomplete)
{
    struct sigevent sev;
    struct itimerspec spec;
    struct itimerspec remaining;
    timer_t timer_id;
    int64_t cpu_start_ns, cpu_end_ns, wall_start_ns, wall_end_ns;
    int64_t cpu_delta_ns, wall_delta_ns, remaining_ns = -1;
    sig_atomic_t signals_before = signal_count;
    sig_atomic_t signals_after;
    int create_rc, set_rc, get_rc, delete_rc;
    int saved_errno;
    int saw_signal = 0;
    int timed_out = 0;
    int result = 0;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;

    if (get_clock_ns(clock_id, &cpu_start_ns) != 0 ||
        get_clock_ns(CLOCK_MONOTONIC, &wall_start_ns) != 0) {
        print_errno("clock_gettime(start)");
        (*incomplete)++;
        return -1;
    }

    create_rc = timer_create(clock_id, &sev, &timer_id);
    if (create_rc != 0) {
        print_errno("timer_create");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=timer_create\n",
               clock_name, iteration);
        (*incomplete)++;
        return -1;
    }

    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_sec = TIMER_NS / 1000000000L;
    spec.it_value.tv_nsec = TIMER_NS % 1000000000L;

    set_rc = timer_settime(timer_id, 0, &spec, NULL);
    if (set_rc != 0) {
        print_errno("timer_settime");
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    /*
     * Consume CPU in the calling thread so both process and thread CPU clocks
     * can advance. The monotonic deadline bounds a stuck test.
     */
    while (signal_count == signals_before) {
        int64_t now_wall_ns, now_cpu_ns;
        if (get_clock_ns(CLOCK_MONOTONIC, &now_wall_ns) != 0 ||
            get_clock_ns(clock_id, &now_cpu_ns) != 0) {
            print_errno("clock_gettime(wait)");
            (*incomplete)++;
            result = -1;
            goto cleanup;
        }
        if (now_wall_ns - wall_start_ns >= WALL_TIMEOUT_NS) {
            timed_out = 1;
            break;
        }
        if (now_cpu_ns - cpu_start_ns > WALL_TIMEOUT_NS * 2) {
            timed_out = 1;
            break;
        }
    }

    saw_signal = (signal_count != signals_before);
    signals_after = signal_count;

    if (get_clock_ns(clock_id, &cpu_end_ns) != 0 ||
        get_clock_ns(CLOCK_MONOTONIC, &wall_end_ns) != 0) {
        print_errno("clock_gettime(end)");
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    cpu_delta_ns = cpu_end_ns - cpu_start_ns;
    wall_delta_ns = wall_end_ns - wall_start_ns;

    memset(&remaining, 0, sizeof(remaining));
    get_rc = timer_gettime(timer_id, &remaining);
    saved_errno = errno;
    if (get_rc == 0) {
        remaining_ns = timespec_to_ns(remaining.it_value);
    } else {
        errno = saved_errno;
        print_errno("timer_gettime");
        (*incomplete)++;
        result = -1;
    }

    printf("SAMPLE clock=%s iter=%d timer_id=%ld "
           "cpu_start_ns=%" PRId64 " cpu_end_ns=%" PRId64
           " cpu_delta_ns=%" PRId64 " cpu_delta_s=%.9f "
           "wall_start_ns=%" PRId64 " wall_end_ns=%" PRId64
           " wall_delta_ns=%" PRId64 " wall_delta_s=%.9f "
           "requested_ns=%ld remaining_ns=%" PRId64
           " signal_count_before=%d signal_count_after=%d "
           "last_signal=%d timed_out=%d\n",
           clock_name, iteration, (long)timer_id,
           cpu_start_ns, cpu_end_ns, cpu_delta_ns,
           ns_to_seconds(cpu_delta_ns),
           wall_start_ns, wall_end_ns, wall_delta_ns,
           ns_to_seconds(wall_delta_ns),
           TIMER_NS, remaining_ns,
           (int)signals_before, (int)signals_after,
           (int)last_signal, timed_out);

    if (!saw_signal || timed_out) {
        printf("RESULT clock=%s iter=%d status=FAIL reason=%s\n",
               clock_name, iteration,
               timed_out ? "wall_timeout" : "signal_not_observed");
        (*failures)++;
        result = -1;
    } else if (cpu_delta_ns < TIMER_NS) {
        printf("RESULT clock=%s iter=%d status=INCONCLUSIVE "
               "reason=signal_before_measured_delta_threshold\n",
               clock_name, iteration);
        (*incomplete)++;
    } else {
        printf("RESULT clock=%s iter=%d status=PASS\n",
               clock_name, iteration);
    }

cleanup:
    delete_rc = timer_delete(timer_id);
    if (delete_rc != 0) {
        print_errno("timer_delete");
        printf("CLEANUP clock=%s iter=%d timer_delete=FAIL\n",
               clock_name, iteration);
        (*failures)++;
        result = -1;
    } else {
        printf("CLEANUP clock=%s iter=%d timer_delete=PASS\n",
               clock_name, iteration);
    }
    return result;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    int iterations = DEFAULT_ITERATIONS;
    int failures = 0, incomplete = 0, executed = 0;
    const clockid_t clocks[] = {
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID
    };
    const char *names[] = {
        "CLOCK_PROCESS_CPUTIME_ID",
        "CLOCK_THREAD_CPUTIME_ID"
    };
    size_t i;
    int j;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [iterations_per_clock]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        char *end = NULL;
        long parsed;
        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (errno != 0 || end == argv[1] || *end != '\0' ||
            parsed < 1 || parsed > MAX_ITERATIONS) {
            fprintf(stderr, "iterations must be 1..%d\n", MAX_ITERATIONS);
            return 2;
        }
        iterations = (int)parsed;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_timer_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        print_errno("sigaction(SIGUSR1)");
        return 2;
    }

    printf("META arch=runtime-detected-by-build iterations_per_clock=%d "
           "timer_request_ns=%ld wall_timeout_ns=%" PRId64
           " pid=%ld\n",
           iterations, TIMER_NS, (int64_t)WALL_TIMEOUT_NS, (long)getpid());
    printf("NOTE offsets=userspace-measured-time-deltas; "
           "kernel-structure-offsets-not-accessible-from-this-test\n");

    for (i = 0; i < sizeof(clocks) / sizeof(clocks[0]); i++) {
        int64_t resolution_ns = -1;
        struct timespec res;
        if (clock_getres(clocks[i], &res) == 0)
            resolution_ns = timespec_to_ns(res);
        printf("CLOCK_INFO clock=%s resolution_ns=%" PRId64 "\n",
               names[i], resolution_ns);

        for (j = 1; j <= iterations; j++) {
            (void)run_one(clocks[i], names[i], j, &failures, &incomplete);
            executed++;
        }
    }

    printf("SUMMARY executed=%d failures=%d incomplete=%d "
           "signals_total=%d status=%s\n",
           executed, failures, incomplete, (int)signal_count,
           failures ? "FAIL" : (incomplete ? "INCONCLUSIVE" : "PASS"));

    return failures ? 1 : (incomplete ? 2 : 0);
}
