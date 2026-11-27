/*
 * timer_posix_lifecycle.c
 *
 * Concurrent POSIX CPU-timer lifecycle stress test for Android ARM64.
 * Exercises create, arm, gettime, disarm, rearm, and delete.
 *
 * This is a userspace stress test. A clean run does NOT prove kernel
 * memory safety or prove/disprove a use-after-free vulnerability.
 *
 * Build:
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *       -Wconversion -Wshadow -pthread timer_posix_lifecycle.c \
 *       -o timer_posix_lifecycle
 *
 * Run:
 *   ./timer_posix_lifecycle            # 2000 cycles per worker
 *   ./timer_posix_lifecycle 10000      # 10000 cycles per worker
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_CYCLES 2000
#define MAX_CYCLES 100000
#define WORKERS 4
#define TIMER_NS 100000L

struct worker_result {
    int worker_id;
    clockid_t clock_id;
    const char *clock_name;
    int cycles;
    uint64_t create_ok;
    uint64_t set_ok;
    uint64_t get_ok;
    uint64_t disarm_ok;
    uint64_t rearm_ok;
    uint64_t delete_ok;
    uint64_t errors;
};

static void noop_signal_handler(int signo)
{
    (void)signo;
}

static int64_t ts_to_ns(const struct timespec *ts)
{
    return (int64_t)ts->tv_sec * INT64_C(1000000000) + (int64_t)ts->tv_nsec;
}

static void burn_thread_cpu_ns(int64_t target_ns)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start) != 0)
        return;
    do {
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now) != 0)
            return;
    } while (ts_to_ns(&now) - ts_to_ns(&start) < target_ns);
}

static int set_timer_ns(timer_t timer_id, int64_t ns)
{
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    if (ns > 0) {
        spec.it_value.tv_sec = (time_t)(ns / INT64_C(1000000000));
        spec.it_value.tv_nsec = (long)(ns % INT64_C(1000000000));
    }
    return timer_settime(timer_id, 0, &spec, NULL);
}

static void *worker_main(void *opaque)
{
    struct worker_result *r = (struct worker_result *)opaque;
    int i;

    for (i = 0; i < r->cycles; i++) {
        struct sigevent sev;
        struct itimerspec current;
        timer_t timer_id;

        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGUSR1;

        if (timer_create(r->clock_id, &sev, &timer_id) != 0) {
            r->errors++;
            continue;
        }
        r->create_ok++;

        if (set_timer_ns(timer_id, TIMER_NS) != 0) {
            r->errors++;
            if (timer_delete(timer_id) == 0)
                r->delete_ok++;
            else
                r->errors++;
            continue;
        }
        r->set_ok++;

        if (timer_gettime(timer_id, &current) == 0)
            r->get_ok++;
        else
            r->errors++;

        /*
         * Periodically let the CPU timer approach/ pass expiration before
         * changing its state. Other cycles exercise prompt disarm/delete.
         */
        if ((i % 4) == 0)
            burn_thread_cpu_ns(INT64_C(250000));
        else {
            if (set_timer_ns(timer_id, 0) == 0)
                r->disarm_ok++;
            else
                r->errors++;
        }

        if (timer_gettime(timer_id, &current) == 0)
            r->get_ok++;
        else
            r->errors++;

        if ((i % 3) == 0) {
            if (set_timer_ns(timer_id, TIMER_NS) == 0) {
                r->rearm_ok++;
                burn_thread_cpu_ns(INT64_C(150000));
            } else {
                r->errors++;
            }
        }

        if (timer_delete(timer_id) == 0)
            r->delete_ok++;
        else
            r->errors++;
    }

    return NULL;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    pthread_t threads[WORKERS];
    struct worker_result results[WORKERS];
    int cycles = DEFAULT_CYCLES;
    int i, created = 0;
    int started[WORKERS] = {0, 0, 0, 0};
    uint64_t total_errors = 0, total_create = 0, total_delete = 0;
    uint64_t total_set = 0, total_get = 0, total_disarm = 0, total_rearm = 0;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [cycles_per_worker]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        char *end = NULL;
        long parsed;
        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (errno != 0 || end == argv[1] || *end != '\0' ||
            parsed < 1 || parsed > MAX_CYCLES) {
            fprintf(stderr, "cycles must be 1..%d\n", MAX_CYCLES);
            return 2;
        }
        cycles = (int)parsed;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = noop_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
                errno, strerror(errno));
        return 2;
    }

    printf("META workers=%d cycles_per_worker=%d timer_ns=%" PRId64
           " clocks=process_cpu,thread_cpu signal=SIGUSR1\n",
           WORKERS, cycles, (int64_t)TIMER_NS);
    printf("NOTE concurrent_lifecycle_stress=yes; userspace_only=yes; "
           "kernel_UAF_conclusion=not_possible_from_this_test\n");

    for (i = 0; i < WORKERS; i++) {
        results[i].worker_id = i;
        results[i].clock_id = (i % 2 == 0) ?
            CLOCK_PROCESS_CPUTIME_ID : CLOCK_THREAD_CPUTIME_ID;
        results[i].clock_name = (i % 2 == 0) ?
            "CLOCK_PROCESS_CPUTIME_ID" : "CLOCK_THREAD_CPUTIME_ID";
        results[i].cycles = cycles;
        results[i].create_ok = 0;
        results[i].set_ok = 0;
        results[i].get_ok = 0;
        results[i].disarm_ok = 0;
        results[i].rearm_ok = 0;
        results[i].delete_ok = 0;
        results[i].errors = 0;

        {
            int rc = pthread_create(&threads[i], NULL, worker_main, &results[i]);
            if (rc != 0) {
                fprintf(stderr, "ERROR pthread_create worker=%d rc=%d (%s)\n",
                        i, rc, strerror(rc));
                total_errors++;
                continue;
            }
            created++;
            started[i] = 1;
        }
    }

    for (i = 0; i < WORKERS; i++) {
        if (started[i]) {
            int rc = pthread_join(threads[i], NULL);
            if (rc != 0) {
                fprintf(stderr, "ERROR pthread_join worker=%d rc=%d (%s)\n",
                        i, rc, strerror(rc));
                total_errors++;
            }
        }
    }

    for (i = 0; i < WORKERS; i++) {
        printf("WORKER id=%d clock=%s cycles=%d create_ok=%" PRIu64
               " set_ok=%" PRIu64 " get_ok=%" PRIu64
               " disarm_ok=%" PRIu64 " rearm_ok=%" PRIu64
               " delete_ok=%" PRIu64 " errors=%" PRIu64 "\n",
               results[i].worker_id, results[i].clock_name, results[i].cycles,
               results[i].create_ok, results[i].set_ok, results[i].get_ok,
               results[i].disarm_ok, results[i].rearm_ok,
               results[i].delete_ok, results[i].errors);

        total_create += results[i].create_ok;
        total_set += results[i].set_ok;
        total_get += results[i].get_ok;
        total_disarm += results[i].disarm_ok;
        total_rearm += results[i].rearm_ok;
        total_delete += results[i].delete_ok;
        total_errors += results[i].errors;
    }

    printf("SUMMARY workers_created=%d cycles_requested=%d create_ok=%" PRIu64
           " set_ok=%" PRIu64 " get_ok=%" PRIu64
           " disarm_ok=%" PRIu64 " rearm_ok=%" PRIu64
           " delete_ok=%" PRIu64 " errors=%" PRIu64 " status=%s\n",
           created, cycles, total_create, total_set, total_get,
           total_disarm, total_rearm, total_delete, total_errors,
           (total_errors == 0 && created == WORKERS) ? "PASS" : "FAIL");

    return (total_errors == 0 && created == WORKERS) ? 0 : 1;
}
