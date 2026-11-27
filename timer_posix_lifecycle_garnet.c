/*
 * timer_posix_lifecycle_garnet.c
 *
 * Target metadata from the supplied analysis report:
 *   Device: Xiaomi Redmi Note 13 Pro 5G (garnet), ARM64 little-endian
 *   Kernel: 5.10.246-android12-9-00021-gc9ff65e4f0d7-ab15866348
 *
 * This is a USERSPACE POSIX CPU timer lifecycle test.
 * Kernel addresses below are recorded as metadata only. This program never
 * dereferences kernel addresses and does not claim to prove or exploit a UAF.
 *
 * Coverage:
 *   1. create / arm / timer_gettime
 *   2. disarm / timer_gettime zero-value verification
 *   3. rearm near/after expected expiry, then delete
 *   4. concurrent workers using process and thread CPU clocks
 *   5. best-effort signal accounting (SIGUSR1 can coalesce)
 *   6. machine-readable summary and a log-friendly META line
 *
 * Not covered/proven:
 *   - Exact expiration count (standard signals may coalesce)
 *   - Absence of kernel warnings, crashes, or memory-safety bugs
 *   - Internal RB-tree/refcount correctness; requires matching kernel source
 *     and kernel-side diagnostics such as available dmesg/logcat.
 *
 * Build:
 *   aarch64-linux-android34-clang -O2 -std=gnu11 -Wall -Wextra \
 *     -Wconversion -Wshadow -pthread timer_posix_lifecycle_garnet.c \
 *     -o timer_posix_lifecycle_garnet
 *
 * Run:
 *   ./timer_posix_lifecycle_garnet 2000 > lifecycle.log 2>&1
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_CYCLES 2000
#define MAX_CYCLES 100000
#define WORKERS 4
#define TIMER_NS INT64_C(100000)
#define EXPIRY_BURN_NS INT64_C(250000)
#define REARM_BURN_NS INT64_C(150000)
#define TIMER_SIGNAL SIGUSR1
#define COLLECTOR_STOP_SIGNAL SIGUSR2

#define KERNEL_VERSION "5.10.246-android12-9-00021-gc9ff65e4f0d7-ab15866348"
#define DEVICE_NAME "Xiaomi Redmi Note 13 Pro 5G (garnet)"
#define SYM_POSIX_CPU_TIMER_CREATE "0xffffffc00828212c"
#define SYM_POSIX_CPU_TIMER_SET    "0xffffffc008282528"
#define SYM_POSIX_CPU_TIMER_DEL    "0xffffffc008282bf4"
#define SYM_CPU_TIMER_FIRE         "0xffffffc0082815f0"
#define SYM_CPU_TIMER_REARM        "0xffffffc0082816b0"
#define SYM_RUN_POSIX_CPU_TIMERS   "0xffffffc008280898"
#define SYM_COLLECT_POSIX_CPUTIMERS "0xffffffc008280d60"
#define SYM_CHECK_PROCESS_TIMERS   "0xffffffc0082810e4"
#define SYM_POSIX_CPU_TIMERS_EXIT  "0xffffffc008280410"
#define SYM_POSIX_CPU_TIMERS_EXIT_GROUP "0xffffffc008280654"
#define SYM_DO_CPU_NANOSLEEP       "0xffffffc008283218"

struct worker_result {
    int worker_id;
    clockid_t clock_id;
    const char *clock_name;
    int cycles;
    uint64_t create_ok, set_ok, get_ok, disarm_ok, rearm_ok, delete_ok;
    uint64_t disarm_zero_ok, initial_nonzero_seen, expiry_race_cycles;
    uint64_t errors;
};

struct signal_stats {
    _Atomic uint64_t received[WORKERS];
    _Atomic uint64_t unexpected;
    _Atomic uint64_t overrun_sum[WORKERS];
};

static struct signal_stats g_signals;
static sigset_t g_wait_set;

static int64_t timespec_ns(const struct timespec *ts)
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
    } while (timespec_ns(&now) - timespec_ns(&start) < target_ns);
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

static int timer_value_is_zero(const struct itimerspec *it)
{
    return it->it_value.tv_sec == 0 && it->it_value.tv_nsec == 0;
}

static void *signal_collector(void *unused)
{
    (void)unused;

    for (;;) {
        siginfo_t info;
        int sig;
        memset(&info, 0, sizeof(info));
        sig = sigwaitinfo(&g_wait_set, &info);

        if (sig == COLLECTOR_STOP_SIGNAL)
            break;
        if (sig < 0) {
            if (errno == EINTR)
                continue;
            atomic_fetch_add(&g_signals.unexpected, 1);
            continue;
        }
        if (sig == TIMER_SIGNAL) {
            int id = info.si_value.sival_int;
            if (id >= 0 && id < WORKERS) {
                atomic_fetch_add(&g_signals.received[id], 1);
                if (info.si_overrun > 0)
                    atomic_fetch_add(&g_signals.overrun_sum[id],
                                     (uint64_t)info.si_overrun);
            } else {
                atomic_fetch_add(&g_signals.unexpected, 1);
            }
        } else {
            atomic_fetch_add(&g_signals.unexpected, 1);
        }
    }
    return NULL;
}

static void *worker_main(void *opaque)
{
    struct worker_result *r = (struct worker_result *)opaque;

    for (int i = 0; i < r->cycles; i++) {
        struct sigevent sev;
        struct itimerspec current;
        timer_t timer_id;
        int race = ((i % 4) == 0);

        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = TIMER_SIGNAL;
        sev.sigev_value.sival_int = r->worker_id;

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

        if (timer_gettime(timer_id, &current) == 0) {
            r->get_ok++;
            if (current.it_value.tv_sec != 0 || current.it_value.tv_nsec != 0)
                r->initial_nonzero_seen++;
        } else {
            r->errors++;
        }

        if (race) {
            /*
             * Move CPU time beyond the initial expiry, then rearm. The exact
             * race timing depends on scheduling and kernel implementation.
             */
            r->expiry_race_cycles++;
            burn_thread_cpu_ns(EXPIRY_BURN_NS);
            if (set_timer_ns(timer_id, TIMER_NS) == 0)
                r->rearm_ok++;
            else
                r->errors++;
            burn_thread_cpu_ns(REARM_BURN_NS);
        } else {
            if (set_timer_ns(timer_id, 0) == 0) {
                r->disarm_ok++;
                if (timer_gettime(timer_id, &current) == 0) {
                    r->get_ok++;
                    if (timer_value_is_zero(&current))
                        r->disarm_zero_ok++;
                    else
                        r->errors++;
                } else {
                    r->errors++;
                }
            } else {
                r->errors++;
            }
        }

        /*
         * Deletion may overlap with an already-triggered expiration.
         * Do not call timer_gettime after timer_delete: the timer ID is no
         * longer valid and probing it would not be a portable API check.
         */
        if (timer_delete(timer_id) == 0)
            r->delete_ok++;
        else
            r->errors++;
    }

    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t workers[WORKERS], collector;
    struct worker_result results[WORKERS];
    sigset_t block_set;
    int cycles = DEFAULT_CYCLES;
    int started[WORKERS] = {0};
    int created = 0;
    uint64_t total_errors = 0, total_create = 0, total_set = 0, total_get = 0;
    uint64_t total_disarm = 0, total_rearm = 0, total_delete = 0;
    uint64_t total_zero = 0, total_nonzero = 0, total_race = 0;
    int rc;

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

    sigemptyset(&g_wait_set);
    sigaddset(&g_wait_set, TIMER_SIGNAL);
    sigaddset(&g_wait_set, COLLECTOR_STOP_SIGNAL);
    sigemptyset(&block_set);
    sigaddset(&block_set, TIMER_SIGNAL);
    sigaddset(&block_set, COLLECTOR_STOP_SIGNAL);

    rc = pthread_sigmask(SIG_BLOCK, &block_set, NULL);
    if (rc != 0) {
        fprintf(stderr, "ERROR pthread_sigmask rc=%d (%s)\n", rc, strerror(rc));
        return 2;
    }

    printf("META device=\"%s\" arch=ARM64 kernel=\"%s\" cycles_per_worker=%d "
           "workers=%d timer_ns=%" PRId64 " signal=SIGUSR1\n",
           DEVICE_NAME, KERNEL_VERSION, cycles, WORKERS, TIMER_NS);
    printf("KERNEL_SYMBOLS posix_cpu_timer_create=%s posix_cpu_timer_set=%s "
           "posix_cpu_timer_del=%s cpu_timer_fire=%s posix_cpu_timer_rearm=%s\n",
           SYM_POSIX_CPU_TIMER_CREATE, SYM_POSIX_CPU_TIMER_SET,
           SYM_POSIX_CPU_TIMER_DEL, SYM_CPU_TIMER_FIRE, SYM_CPU_TIMER_REARM);
    printf("KERNEL_PATHS run_posix_cpu_timers=%s collect_posix_cputimers=%s "
           "check_process_timers=%s posix_cpu_timers_exit=%s "
           "posix_cpu_timers_exit_group=%s do_cpu_nanosleep=%s\n",
           SYM_RUN_POSIX_CPU_TIMERS, SYM_COLLECT_POSIX_CPUTIMERS,
           SYM_CHECK_PROCESS_TIMERS, SYM_POSIX_CPU_TIMERS_EXIT,
           SYM_POSIX_CPU_TIMERS_EXIT_GROUP, SYM_DO_CPU_NANOSLEEP);
    printf("CHECKS create_arm_gettime_disarm_gettime_rearm_delete=yes "
           "concurrent_workers=yes expiry_race_best_effort=yes "
           "signal_accounting_best_effort=yes\n");
    printf("LIMIT kernel_addresses_metadata_only=yes standard_signal_coalescing=yes "
           "exact_expiration_count=no userspace_UAF_proof=no\n");
    fflush(stdout);

    rc = pthread_create(&collector, NULL, signal_collector, NULL);
    if (rc != 0) {
        fprintf(stderr, "ERROR collector_create rc=%d (%s)\n", rc, strerror(rc));
        return 2;
    }

    for (int i = 0; i < WORKERS; i++) {
        results[i] = (struct worker_result){0};
        results[i].worker_id = i;
        results[i].clock_id = (i % 2 == 0) ?
            CLOCK_PROCESS_CPUTIME_ID : CLOCK_THREAD_CPUTIME_ID;
        results[i].clock_name = (i % 2 == 0) ?
            "CLOCK_PROCESS_CPUTIME_ID" : "CLOCK_THREAD_CPUTIME_ID";
        results[i].cycles = cycles;

        rc = pthread_create(&workers[i], NULL, worker_main, &results[i]);
        if (rc != 0) {
            fprintf(stderr, "ERROR worker_create id=%d rc=%d (%s)\n",
                    i, rc, strerror(rc));
            total_errors++;
        } else {
            started[i] = 1;
            created++;
        }
    }

    for (int i = 0; i < WORKERS; i++) {
        if (started[i]) {
            rc = pthread_join(workers[i], NULL);
            if (rc != 0) {
                fprintf(stderr, "ERROR worker_join id=%d rc=%d (%s)\n",
                        i, rc, strerror(rc));
                total_errors++;
            }
        }
    }

    /*
     * Stop the collector only after workers finish. A stop signal can still
     * be selected before queued SIGUSR1 notifications; counts are best-effort.
     */
    (void)pthread_kill(collector, COLLECTOR_STOP_SIGNAL);
    rc = pthread_join(collector, NULL);
    if (rc != 0) {
        fprintf(stderr, "ERROR collector_join rc=%d (%s)\n", rc, strerror(rc));
        total_errors++;
    }

    for (int i = 0; i < WORKERS; i++) {
        uint64_t received = atomic_load(&g_signals.received[i]);
        uint64_t overruns = atomic_load(&g_signals.overrun_sum[i]);

        printf("WORKER id=%d clock=%s cycles=%d create_ok=%" PRIu64
               " set_ok=%" PRIu64 " get_ok=%" PRIu64
               " disarm_ok=%" PRIu64 " rearm_ok=%" PRIu64
               " delete_ok=%" PRIu64 " disarm_zero_ok=%" PRIu64
               " initial_nonzero_seen=%" PRIu64
               " expiry_race_cycles=%" PRIu64 " signals_received=%" PRIu64
               " signal_overrun_sum=%" PRIu64 " errors=%" PRIu64 "\n",
               results[i].worker_id, results[i].clock_name, results[i].cycles,
               results[i].create_ok, results[i].set_ok, results[i].get_ok,
               results[i].disarm_ok, results[i].rearm_ok, results[i].delete_ok,
               results[i].disarm_zero_ok, results[i].initial_nonzero_seen,
               results[i].expiry_race_cycles, received, overruns,
               results[i].errors);

        total_create += results[i].create_ok;
        total_set += results[i].set_ok;
        total_get += results[i].get_ok;
        total_disarm += results[i].disarm_ok;
        total_rearm += results[i].rearm_ok;
        total_delete += results[i].delete_ok;
        total_zero += results[i].disarm_zero_ok;
        total_nonzero += results[i].initial_nonzero_seen;
        total_race += results[i].expiry_race_cycles;
        total_errors += results[i].errors;
    }

    printf("SIGNALS received_total=%" PRIu64 " unexpected=%" PRIu64
           " note=best_effort_standard_signals_may_coalesce\n",
           atomic_load(&g_signals.received[0]) +
           atomic_load(&g_signals.received[1]) +
           atomic_load(&g_signals.received[2]) +
           atomic_load(&g_signals.received[3]),
           atomic_load(&g_signals.unexpected));

    printf("SUMMARY workers_created=%d cycles_requested=%d create_ok=%" PRIu64
           " set_ok=%" PRIu64 " get_ok=%" PRIu64 " disarm_ok=%" PRIu64
           " rearm_ok=%" PRIu64 " delete_ok=%" PRIu64
           " disarm_zero_ok=%" PRIu64 " initial_nonzero_seen=%" PRIu64
           " expiry_race_cycles=%" PRIu64 " errors=%" PRIu64 " status=%s\n",
           created, cycles, total_create, total_set, total_get, total_disarm,
           total_rearm, total_delete, total_zero, total_nonzero, total_race,
           total_errors,
           (total_errors == 0 && created == WORKERS &&
            total_zero == total_disarm) ? "PASS" : "FAIL");
    printf("NOTE PASS_means_API_checks_only_not_proof_of_kernel_memory_safety\n");

    return (total_errors == 0 && created == WORKERS &&
            total_zero == total_disarm) ? 0 : 1;
}
