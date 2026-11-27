#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CPU_TIMER_NS       20000000L
#define WALL_TIMEOUT_SEC   3
#define STRESS_CYCLES      500

static volatile sig_atomic_t timer_signal_count;

static void timer_handler(int signo)
{
    (void)signo;
    if (timer_signal_count < 1000000)
        ++timer_signal_count;
}

static double timespec_seconds(const struct timespec *ts)
{
    return (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000.0;
}

static int check_timespec_nonnegative(const struct timespec *ts)
{
    return ts->tv_sec >= 0 && ts->tv_nsec >= 0 &&
           ts->tv_nsec < 1000000000L;
}

static int wait_for_timer_signal(void)
{
    struct timespec start, now;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        fprintf(stderr, "[FAIL] clock_gettime(CLOCK_MONOTONIC): %s\n",
                strerror(errno));
        return -1;
    }

    /*
     * This bounded loop intentionally consumes CPU so CPU-time timers can
     * expire. It does not access kernel memory or attempt to trigger a fault.
     */
    while (timer_signal_count == 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            fprintf(stderr, "[FAIL] clock_gettime while waiting: %s\n",
                    strerror(errno));
            return -1;
        }

        if (now.tv_sec - start.tv_sec >= WALL_TIMEOUT_SEC) {
            fprintf(stderr,
                    "[INCONCLUSIVE] no timer signal within %d wall seconds\n",
                    WALL_TIMEOUT_SEC);
            return 1;
        }
    }

    return 0;
}

static int test_cpu_clock(clockid_t clock_id, const char *name)
{
    timer_t timer;
    struct sigevent sev;
    struct itimerspec setting, current, disarmed;
    struct sigaction action, old_action;
    struct timespec cpu_before, cpu_after;
    int handler_installed = 0;
    int timer_created = 0;
    int result = -1;
    int wait_result;

    printf("\n[TEST] %s\n", name);

    if (clock_gettime(clock_id, &cpu_before) != 0) {
        printf("[UNSUPPORTED] clock_gettime: %s\n", strerror(errno));
        return -1;
    }
    if (!check_timespec_nonnegative(&cpu_before)) {
        printf("[FAIL] invalid CPU clock timespec\n");
        return -1;
    }
    printf("[PASS] clock_gettime: %.6f CPU seconds\n",
           timespec_seconds(&cpu_before));

    memset(&action, 0, sizeof(action));
    action.sa_handler = timer_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(SIGUSR1, &action, &old_action) != 0) {
        printf("[FAIL] sigaction: %s\n", strerror(errno));
        return -1;
    }
    handler_installed = 1;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;

    if (timer_create(clock_id, &sev, &timer) != 0) {
        printf("[FAIL] timer_create: %s\n", strerror(errno));
        goto cleanup;
    }
    timer_created = 1;
    printf("[PASS] timer_create\n");

    memset(&setting, 0, sizeof(setting));
    setting.it_value.tv_nsec = CPU_TIMER_NS;
    timer_signal_count = 0;

    if (timer_settime(timer, 0, &setting, NULL) != 0) {
        printf("[FAIL] timer_settime: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("[PASS] timer_settime (%ld ns CPU time)\n", CPU_TIMER_NS);

    memset(&current, 0, sizeof(current));
    if (timer_gettime(timer, &current) != 0) {
        printf("[FAIL] timer_gettime: %s\n", strerror(errno));
        goto cleanup;
    }
    if (!check_timespec_nonnegative(&current.it_value) ||
        !check_timespec_nonnegative(&current.it_interval)) {
        printf("[FAIL] timer_gettime returned invalid timespec\n");
        goto cleanup;
    }
    printf("[PASS] timer_gettime; remaining=%ld.%09ld s\n",
           (long)current.it_value.tv_sec, current.it_value.tv_nsec);

    wait_result = wait_for_timer_signal();
    if (wait_result != 0) {
        result = wait_result;
        goto cleanup;
    }
    printf("[PASS] CPU timer signal received (%d signal)\n",
           (int)timer_signal_count);

    if (clock_gettime(clock_id, &cpu_after) != 0) {
        printf("[FAIL] second clock_gettime: %s\n", strerror(errno));
        goto cleanup;
    }
    if (cpu_after.tv_sec < cpu_before.tv_sec ||
        (cpu_after.tv_sec == cpu_before.tv_sec &&
         cpu_after.tv_nsec < cpu_before.tv_nsec)) {
        printf("[FAIL] CPU clock moved backwards\n");
        goto cleanup;
    }
    printf("[PASS] CPU clock remained monotonic\n");

    /* Explicitly disarm the timer and verify the zero value is accepted. */
    memset(&disarmed, 0, sizeof(disarmed));
    if (timer_settime(timer, 0, &disarmed, NULL) != 0) {
        printf("[FAIL] timer_settime(disarm): %s\n", strerror(errno));
        goto cleanup;
    }
    if (timer_gettime(timer, &current) != 0) {
        printf("[FAIL] timer_gettime after disarm: %s\n", strerror(errno));
        goto cleanup;
    }
    if (current.it_value.tv_sec != 0 || current.it_value.tv_nsec != 0) {
        printf("[FAIL] timer still reports time remaining after disarm\n");
        goto cleanup;
    }
    printf("[PASS] timer disarm and zero remaining time\n");

    result = 0;

cleanup:
    if (timer_created) {
        /* Disarm before deletion so cleanup is deterministic. */
        memset(&disarmed, 0, sizeof(disarmed));
        if (timer_settime(timer, 0, &disarmed, NULL) != 0) {
            printf("[FAIL] cleanup timer_settime(disarm): %s\n",
                   strerror(errno));
            result = -1;
        }

        if (timer_delete(timer) == 0) {
            printf("[PASS] timer_delete\n");
        } else {
            printf("[FAIL] timer_delete: %s\n", strerror(errno));
            result = -1;
        }
    }

    if (handler_installed && sigaction(SIGUSR1, &old_action, NULL) != 0) {
        printf("[FAIL] restore sigaction: %s\n", strerror(errno));
        result = -1;
    }

    return result;
}

static int test_create_delete_stress(clockid_t clock_id,
                                     const char *name, int cycles)
{
    int i;

    printf("\n[TEST] create/delete stress: %s (%d cycles)\n", name, cycles);

    for (i = 0; i < cycles; ++i) {
        timer_t timer;
        struct sigevent sev;
        struct itimerspec setting;

        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;

        if (timer_create(clock_id, &sev, &timer) != 0) {
            printf("[FAIL] timer_create at cycle %d: %s\n",
                   i, strerror(errno));
            return -1;
        }

        memset(&setting, 0, sizeof(setting));
        setting.it_value.tv_nsec = 1000000L; /* 1 ms CPU time */

        if (timer_settime(timer, 0, &setting, NULL) != 0) {
            int saved_errno = errno;
            (void)timer_delete(timer);
            printf("[FAIL] timer_settime at cycle %d: %s\n",
                   i, strerror(saved_errno));
            return -1;
        }

        if (timer_delete(timer) != 0) {
            printf("[FAIL] timer_delete at cycle %d: %s\n",
                   i, strerror(errno));
            return -1;
        }
    }

    printf("[PASS] %d create/set/delete cycles completed\n", cycles);
    return 0;
}

int main(void)
{
    int failures = 0;
    int incomplete = 0;
    int result;

    printf("POSIX CPU timer diagnostic (Android ARM64)\n");
    printf("PID: %ld\n", (long)getpid());
    printf("Stress cycles per clock: %d\n", STRESS_CYCLES);

    result = test_cpu_clock(CLOCK_PROCESS_CPUTIME_ID,
                            "process CPU clock");
    if (result < 0)
        ++failures;
    else if (result > 0)
        ++incomplete;

    result = test_cpu_clock(CLOCK_THREAD_CPUTIME_ID,
                            "thread CPU clock");
    if (result < 0)
        ++failures;
    else if (result > 0)
        ++incomplete;

    if (test_create_delete_stress(CLOCK_PROCESS_CPUTIME_ID,
                                  "process CPU clock", STRESS_CYCLES) != 0)
        ++failures;

    if (test_create_delete_stress(CLOCK_THREAD_CPUTIME_ID,
                                  "thread CPU clock", STRESS_CYCLES) != 0)
        ++failures;

    printf("\n========== SUMMARY ==========\n");
    printf("Failed test groups: %d\n", failures);
    printf("Incomplete test groups: %d\n", incomplete);
    printf("This test does not prove or disprove a kernel UAF.\n");

    return failures ? 1 : (incomplete ? 2 : 0);
}
