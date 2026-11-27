/*
 * POSIX CPU timer diagnostic for Android/Linux (bionic, API 34+).
 *
 * Covers public userspace interfaces:
 *   - CLOCK_PROCESS_CPUTIME_ID / CLOCK_THREAD_CPUTIME_ID
 *   - timer_create / timer_settime / timer_gettime / timer_delete
 *   - SIGEV_SIGNAL delivery for process/thread CPU timers
 *   - bounded sequential and multi-threaded timer lifecycle stress
 *
 * This does NOT inspect kernel structs, RB trees, refcounts, kmem_cache,
 * posix_cpu_timers_exit(), or prove/disprove a kernel use-after-free.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef STRESS_ITERS
#define STRESS_ITERS 500
#endif
#ifndef WORKER_COUNT
#define WORKER_COUNT 4
#endif

static atomic_int failures = 0;
static atomic_int incomplete = 0;

#define PASS(msg) do { printf("[PASS] %s\n", msg); } while (0)
#define FAIL(msg) do { printf("[FAIL] %s (errno=%d: %s)\n", msg, errno, strerror(errno)); atomic_fetch_add(&failures, 1); } while (0)
#define NOTE(msg) do { printf("[INFO] %s\n", msg); } while (0)

static double ts_seconds(const struct timespec *ts) {
    return (double)ts->tv_sec + (double)ts->tv_nsec / 1e9;
}

static void burn_cpu_ns(long ns) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start) != 0) return;
    do {
        for (volatile unsigned int i = 0; i < 10000; ++i) { }
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now) != 0) return;
    } while ((now.tv_sec - start.tv_sec) * 1000000000L +
             (now.tv_nsec - start.tv_nsec) < ns);
}

static int check_clock(clockid_t id, const char *label) {
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0) {
        printf("[FAIL] %s clock_gettime: errno=%d (%s)\n", label, errno, strerror(errno));
        atomic_fetch_add(&failures, 1);
        return -1;
    }
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L) {
        printf("[FAIL] %s returned invalid timespec\n", label);
        atomic_fetch_add(&failures, 1);
        return -1;
    }
    printf("[PASS] %s clock_gettime: %.6f CPU seconds\n", label, ts_seconds(&ts));
    return 0;
}

static int timer_api_cycle(clockid_t clock_id, const char *label, int signal_test) {
    timer_t tid;
    struct sigevent sev;
    struct itimerspec its, cur;
    memset(&sev, 0, sizeof(sev));
    memset(&its, 0, sizeof(its));
    memset(&cur, 0, sizeof(cur));

    if (signal_test) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
            printf("[FAIL] %s: pthread_sigmask failed\n", label);
            atomic_fetch_add(&failures, 1);
            return -1;
        }
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGUSR1;
    } else {
        sev.sigev_notify = SIGEV_NONE;
    }

    if (timer_create(clock_id, &sev, &tid) != 0) {
        printf("[FAIL] %s timer_create: errno=%d (%s)\n", label, errno, strerror(errno));
        atomic_fetch_add(&failures, 1);
        return -1;
    }
    printf("[PASS] %s timer_create\n", label);

    /* CPU time, not wall time. */
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 20 * 1000 * 1000;
    if (timer_settime(tid, 0, &its, NULL) != 0) {
        printf("[FAIL] %s timer_settime: errno=%d (%s)\n", label, errno, strerror(errno));
        atomic_fetch_add(&failures, 1);
        timer_delete(tid);
        return -1;
    }
    printf("[PASS] %s timer_settime\n", label);

    if (timer_gettime(tid, &cur) != 0) {
        printf("[FAIL] %s timer_gettime: errno=%d (%s)\n", label, errno, strerror(errno));
        atomic_fetch_add(&failures, 1);
        timer_delete(tid);
        return -1;
    }
    printf("[PASS] %s timer_gettime; remaining=%ld.%09ld s\n",
           label, (long)cur.it_value.tv_sec, cur.it_value.tv_nsec);

    if (signal_test) {
        sigset_t set;
        struct timespec timeout = { .tv_sec = 3, .tv_nsec = 0 };
        siginfo_t info;
        int sig;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);

        /* Consume CPU so the CPU-time timer can expire. */
        burn_cpu_ns(100 * 1000 * 1000L);
        do {
            sig = sigtimedwait(&set, &info, &timeout);
        } while (sig < 0 && errno == EINTR);

        if (sig == SIGUSR1) {
            printf("[PASS] %s CPU timer signal received\n", label);
        } else {
            printf("[FAIL] %s signal not received (result=%d errno=%d: %s)\n",
                   label, sig, errno, strerror(errno));
            atomic_fetch_add(&failures, 1);
        }
    } else {
        /* Exercise expiry/collection without signal delivery. */
        burn_cpu_ns(30 * 1000 * 1000L);
        if (timer_gettime(tid, &cur) != 0) {
            printf("[FAIL] %s timer_gettime after CPU work\n", label);
            atomic_fetch_add(&failures, 1);
        }
    }

    if (timer_delete(tid) != 0) {
        printf("[FAIL] %s timer_delete: errno=%d (%s)\n", label, errno, strerror(errno));
        atomic_fetch_add(&failures, 1);
        return -1;
    }
    printf("[PASS] %s timer_delete\n", label);

    if (signal_test) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        /* Drain a possible duplicate/pending notification before later tests. */
        struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
        sigtimedwait(&set, NULL, &zero);
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    }
    return 0;
}

static void *worker_main(void *arg) {
    long worker_id = (long)arg;
    char label[80];

    for (int i = 0; i < STRESS_ITERS; ++i) {
        timer_t tid;
        struct sigevent sev;
        struct itimerspec its, cur;
        memset(&sev, 0, sizeof(sev));
        memset(&its, 0, sizeof(its));
        memset(&cur, 0, sizeof(cur));
        sev.sigev_notify = SIGEV_NONE;

        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tid) != 0) {
            fprintf(stderr, "[FAIL] worker %ld iteration %d timer_create: %s\n",
                    worker_id, i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            return NULL;
        }
        its.it_value.tv_nsec = 1000000L; /* 1 ms of this thread's CPU time */
        if (timer_settime(tid, 0, &its, NULL) != 0) {
            fprintf(stderr, "[FAIL] worker %ld iteration %d timer_settime: %s\n",
                    worker_id, i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            timer_delete(tid);
            return NULL;
        }

        burn_cpu_ns(1500000L);
        if (timer_gettime(tid, &cur) != 0) {
            fprintf(stderr, "[FAIL] worker %ld iteration %d timer_gettime: %s\n",
                    worker_id, i, strerror(errno));
            atomic_fetch_add(&failures, 1);
        }
        if (timer_delete(tid) != 0) {
            fprintf(stderr, "[FAIL] worker %ld iteration %d timer_delete: %s\n",
                    worker_id, i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            return NULL;
        }
    }

    snprintf(label, sizeof(label), "worker %ld completed %d timer cycles", worker_id, STRESS_ITERS);
    printf("[PASS] %s\n", label);
    return NULL;
}

static void sequential_stress(void) {
    NOTE("Sequential process CPU timer lifecycle stress");
    for (int i = 0; i < STRESS_ITERS; ++i) {
        timer_t tid;
        struct sigevent sev;
        struct itimerspec its, cur;
        memset(&sev, 0, sizeof(sev));
        memset(&its, 0, sizeof(its));
        memset(&cur, 0, sizeof(cur));
        sev.sigev_notify = SIGEV_NONE;

        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &tid) != 0) {
            printf("[FAIL] sequential iteration %d timer_create: %s\n", i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            return;
        }
        its.it_value.tv_nsec = 1000000L;
        if (timer_settime(tid, 0, &its, NULL) != 0) {
            printf("[FAIL] sequential iteration %d timer_settime: %s\n", i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            timer_delete(tid);
            return;
        }
        burn_cpu_ns(1500000L);
        if (timer_gettime(tid, &cur) != 0) {
            printf("[FAIL] sequential iteration %d timer_gettime: %s\n", i, strerror(errno));
            atomic_fetch_add(&failures, 1);
        }
        if (timer_delete(tid) != 0) {
            printf("[FAIL] sequential iteration %d timer_delete: %s\n", i, strerror(errno));
            atomic_fetch_add(&failures, 1);
            return;
        }
    }
    printf("[PASS] sequential process timer cycles: %d\n", STRESS_ITERS);
}

static void concurrent_stress(void) {
    pthread_t workers[WORKER_COUNT];
    int created = 0;
    NOTE("Concurrent per-thread CPU timer lifecycle stress");
    for (long i = 0; i < WORKER_COUNT; ++i) {
        int rc = pthread_create(&workers[i], NULL, worker_main, (void *)i);
        if (rc != 0) {
            printf("[FAIL] pthread_create worker %ld: %s\n", i, strerror(rc));
            atomic_fetch_add(&failures, 1);
            break;
        }
        ++created;
    }
    for (int i = 0; i < created; ++i) {
        int rc = pthread_join(workers[i], NULL);
        if (rc != 0) {
            printf("[FAIL] pthread_join worker %d: %s\n", i, strerror(rc));
            atomic_fetch_add(&failures, 1);
        }
    }
    if (created == WORKER_COUNT) PASS("all concurrent workers joined");
    else atomic_fetch_add(&incomplete, 1);
}

int main(void) {
    printf("POSIX CPU timer diagnostic (Android/Linux)\n");
    printf("PID: %ld | workers=%d | iterations/worker=%d\n",
           (long)getpid(), WORKER_COUNT, STRESS_ITERS);
    printf("This is a userspace diagnostic, not a kernel UAF proof.\n\n");

    puts("[TEST] CPU clocks");
    check_clock(CLOCK_PROCESS_CPUTIME_ID, "process CPU");
    check_clock(CLOCK_THREAD_CPUTIME_ID, "thread CPU");

    puts("\n[TEST] Basic process CPU timer + signal");
    timer_api_cycle(CLOCK_PROCESS_CPUTIME_ID, "process timer", 1);

    puts("\n[TEST] Basic thread CPU timer + signal");
    timer_api_cycle(CLOCK_THREAD_CPUTIME_ID, "thread timer", 1);

    puts("\n[TEST] Sequential lifecycle stress");
    sequential_stress();

    puts("\n[TEST] Concurrent lifecycle stress");
    concurrent_stress();

    puts("\n========== SUMMARY ==========\n");
    printf("Failures: %d\n", atomic_load(&failures));
    printf("Incomplete test groups: %d\n", atomic_load(&incomplete));
    puts("Coverage: CPU clocks, timer create/set/get/delete, signal delivery,");
    puts("          expiry, sequential lifecycle, concurrent thread lifecycle.");
    puts("Not covered: internal RB-tree/refcount state, kmem_cache lifetime,");
    puts("             posix_cpu_timers_exit internals, or non-leader exec race.");
    puts("A clean run does not prove or disprove a kernel use-after-free.");

    return (atomic_load(&failures) == 0 && atomic_load(&incomplete) == 0) ? 0 : 1;
}
