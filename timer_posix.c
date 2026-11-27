
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t timer_fired = 0;

static void timer_handler(int signo)
{
    (void)signo;
    timer_fired = 1;
}

static double seconds(const struct timespec *t)
{
    return (double)t->tv_sec + (double)t->tv_nsec / 1e9;
}

static int test_cpu_clock(clockid_t clock_id, const char *name)
{
    timer_t timer;
    struct sigevent sev;
    struct itimerspec its;
    struct itimerspec current;
    struct sigaction sa;
    struct timespec start, now, cpu;
    int created = 0;
    int result = -1;

    printf("\n[TEST] %s\n", name);

    if (clock_gettime(clock_id, &cpu) != 0) {
        printf("[UNSUPPORTED] clock_gettime: %s\n",
               strerror(errno));
        return -1;
    }

    printf("[PASS] clock_gettime: %.6f CPU seconds\n",
           seconds(&cpu));

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timer_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("[FAIL] sigaction: %s\n", strerror(errno));
        return -1;
    }

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;

    if (timer_create(clock_id, &sev, &timer) != 0) {
        printf("[FAIL] timer_create: %s\n", strerror(errno));
        return -1;
    }

    created = 1;
    printf("[PASS] timer_create\n");

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 20000000L; /* 20 ms CPU time */

    timer_fired = 0;

    if (timer_settime(timer, 0, &its, NULL) != 0) {
        printf("[FAIL] timer_settime: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("[PASS] timer_settime\n");

    if (timer_gettime(timer, &current) != 0) {
        printf("[FAIL] timer_gettime: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("[PASS] timer_gettime; remaining=%ld.%09ld s\n",
           (long)current.it_value.tv_sec,
           current.it_value.tv_nsec);

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        printf("[FAIL] monotonic clock: %s\n", strerror(errno));
        goto cleanup;
    }

    /*
     * Bounded CPU-time wait. No kernel memory access,
     * raw syscalls, or attempts to trigger a kernel fault.
     */
    while (!timer_fired) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            goto cleanup;

        if (seconds(&now) - seconds(&start) > 3.0) {
            printf("[INCONCLUSIVE] signal not received in 3 s\n");
            goto cleanup;
        }
    }

    printf("[PASS] CPU timer signal received\n");
    result = 0;

cleanup:
    if (created) {
        if (timer_delete(timer) == 0)
            printf("[PASS] timer_delete\n");
        else {
            printf("[FAIL] timer_delete: %s\n",
                   strerror(errno));
            result = -1;
        }
    }

    return result;
}

int main(void)
{
    int failures = 0;

    printf("POSIX CPU timer diagnostic\n");
    printf("PID: %ld\n", (long)getpid());

    if (test_cpu_clock(CLOCK_PROCESS_CPUTIME_ID,
                       "process CPU clock") != 0)
        failures++;

    if (test_cpu_clock(CLOCK_THREAD_CPUTIME_ID,
                       "thread CPU clock") != 0)
        failures++;

    printf("\n========== SUMMARY ==========\n");
    printf("Tests with incomplete or failed results: %d\n",
           failures);
    printf("This test does not prove or disprove a kernel UAF.\n");

    return failures ? 1 : 0;
}
