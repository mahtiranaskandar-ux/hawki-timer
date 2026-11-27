/*
 * timer_posix4.c - Numeric diagnostics for POSIX CPU timers on Android ARM64.
 *
 * Measures userspace-observed CPU and monotonic time only.
 * It does not inspect kernel structures or prove/disprove a kernel UAF.
 *
 * Build with Android NDK:
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *       -Wconversion -Wshadow -pthread timer_posix4.c -o timer_posix4
 *
 * Run:
 *   ./timer_posix4          # 10 iterations per clock
 *   ./timer_posix4 500      # 500 iterations per clock
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
#define TIMER_NS INT64_C(20000000)
#define WALL_TIMEOUT_NS INT64_C(3000000000)

static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t last_signal;

static void on_timer_signal(int signo)
{
    last_signal = signo;
    signal_count++;
}

static int64_t timespec_to_ns(struct timespec ts)
{
    return (int64_t)ts.tv_sec * INT64_C(1000000000) + (int64_t)ts.tv_nsec;
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
    int err = errno;
    fprintf(stderr, "ERROR: %s failed: errno=%d (%s)\n",
            what, err, strerror(err));
}

static int run_one(clockid_t clock_id, const char *clock_name, int iteration,
                   int *failures, int *incomplete)
{
    struct sigevent sev;
    struct itimerspec spec;
    struct itimerspec remaining;
    timer_t timer_id;
    int64_t cpu_start_ns = 0;
    int64_t cpu_end_ns = 0;
    int64_t wall_start_ns = 0;
    int64_t wall_end_ns = 0;
    int64_t cpu_delta_ns = -1;
    int64_t wall_delta_ns = -1;
    int64_t remaining_ns = -1;
    sig_atomic_t signals_before;
    sig_atomic_t signals_after;
    int timed_out = 0;
    int saw_signal;
    int result = 0;
    int get_rc;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;

    /* Snapshot before creating this timer; tests run serially. */
    signals_before = signal_count;

    if (timer_create(clock_id, &sev, &timer_id) != 0) {
        print_errno("timer_create");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=timer_create\n",
               clock_name, iteration);
        (*incomplete)++;
        return -1;
    }

    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_sec = (time_t)(TIMER_NS / INT64_C(1000000000));
    spec.it_value.tv_nsec = (long)(TIMER_NS % INT64_C(1000000000));

    if (timer_settime(timer_id, 0, &spec, NULL) != 0) {
        print_errno("timer_settime");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=timer_settime\n",
               clock_name, iteration);
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    /*
     * Establish measurement baselines after arming the timer. The timer is
     * already running, so a small amount of setup/measurement overhead remains.
     * The measured deltas include signal-delivery and scheduling latency.
     */
    if (get_clock_ns(clock_id, &cpu_start_ns) != 0 ||
        get_clock_ns(CLOCK_MONOTONIC, &wall_start_ns) != 0) {
        print_errno("clock_gettime(baseline)");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=baseline\n",
               clock_name, iteration);
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    while (signal_count == signals_before) {
        int64_t now_wall_ns;
        int64_t now_cpu_ns;

        if (get_clock_ns(CLOCK_MONOTONIC, &now_wall_ns) != 0 ||
            get_clock_ns(clock_id, &now_cpu_ns) != 0) {
            print_errno("clock_gettime(wait)");
            printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=wait_clock\n",
                   clock_name, iteration);
            (*incomplete)++;
            result = -1;
            goto cleanup;
        }

        if (now_wall_ns - wall_start_ns >= WALL_TIMEOUT_NS ||
            now_cpu_ns - cpu_start_ns >= WALL_TIMEOUT_NS * 2) {
            timed_out = 1;
            break;
        }
    }

    saw_signal = (signal_count != signals_before);
    signals_after = signal_count;

    if (get_clock_ns(clock_id, &cpu_end_ns) != 0 ||
        get_clock_ns(CLOCK_MONOTONIC, &wall_end_ns) != 0) {
        print_errno("clock_gettime(end)");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=end_clock\n",
               clock_name, iteration);
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    cpu_delta_ns = cpu_end_ns - cpu_start_ns;
    wall_delta_ns = wall_end_ns - wall_start_ns;

    memset(&remaining, 0, sizeof(remaining));
    get_rc = timer_gettime(timer_id, &remaining);
    if (get_rc == 0) {
        remaining_ns = timespec_to_ns(remaining.it_value);
    } else {
        print_errno("timer_gettime");
        printf("RESULT clock=%s iter=%d status=INCOMPLETE stage=timer_gettime\n",
               clock_name, iteration);
        (*incomplete)++;
        result = -1;
        goto cleanup;
    }

    printf("SAMPLE clock=%s iter=%d requested_ns=%" PRId64
           " cpu_baseline_ns=%" PRId64 " cpu_observed_ns=%" PRId64
           " cpu_delta_ns=%" PRId64 " cpu_delta_ms=%.6f"
           " wall_baseline_ns=%" PRId64 " wall_observed_ns=%" PRId64
           " wall_delta_ns=%" PRId64 " wall_delta_ms=%.6f"
           " remaining_ns=%" PRId64 " signal_count_before=%d"
           " signal_count_after=%d last_signal=%d timed_out=%d\n",
           clock_name, iteration, TIMER_NS,
           cpu_start_ns, cpu_end_ns, cpu_delta_ns,
           (double)cpu_delta_ns / 1000000.0,
           wall_start_ns, wall_end_ns, wall_delta_ns,
           (double)wall_delta_ns / 1000000.0,
           remaining_ns, (int)signals_before, (int)signals_after,
           (int)last_signal, timed_out);

    if (timed_out || !saw_signal) {
        printf("RESULT clock=%s iter=%d status=FAIL reason=%s\n",
               clock_name, iteration,
               timed_out ? "timeout" : "signal_not_observed");
        (*failures)++;
        result = -1;
    } else if (cpu_delta_ns < TIMER_NS) {
        printf("RESULT clock=%s iter=%d status=INCONCLUSIVE "
               "reason=observed_cpu_delta_below_request\n",
               clock_name, iteration);
        (*incomplete)++;
    } else {
        printf("RESULT clock=%s iter=%d status=PASS\n",
               clock_name, iteration);
    }

cleanup:
    if (timer_delete(timer_id) != 0) {
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
    struct sigaction old_sa;
    int iterations = DEFAULT_ITERATIONS;
    int failures = 0;
    int incomplete = 0;
    int executed = 0;
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

    if (sigaction(SIGUSR1, &sa, &old_sa) != 0) {
        print_errno("sigaction(SIGUSR1)");
        return 2;
    }

    printf("META iterations_per_clock=%d timer_request_ns=%" PRId64
           " wall_timeout_ns=%" PRId64 " pid=%ld\n",
           iterations, TIMER_NS, WALL_TIMEOUT_NS, (long)getpid());
    printf("NOTE measurement=userspace_observed; baseline=after_timer_settime;"
           " includes_signal_delivery_and_scheduling_latency;"
           " kernel_structure_offsets=not_measured\n");

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

    if (sigaction(SIGUSR1, &old_sa, NULL) != 0) {
        print_errno("sigaction(restore SIGUSR1)");
        failures++;
    }

    printf("SUMMARY executed=%d failures=%d incomplete=%d signals_total=%d "
           "status=%s\n",
           executed, failures, incomplete, (int)signal_count,
           failures ? "FAIL" : (incomplete ? "INCONCLUSIVE" : "PASS"));

    return failures ? 1 : (incomplete ? 2 : 0);
}
