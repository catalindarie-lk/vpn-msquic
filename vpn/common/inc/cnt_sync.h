#ifndef CNT_SYNC_H
#define CNT_SYNC_H

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Thread-safe synchronizing countdown latch.
 * 
 * Provides an atomic performance layer coupled with condition-variable notifications
 * to block execution streams until the underlying asynchronous operations drop to zero.
 */
typedef struct {
    _Atomic uint_fast64_t value; /**< Atomic internal tracking counter value */
    pthread_mutex_t mutex;       /**< Synchronizing mutex shielding condition changes */
    pthread_cond_t cond;         /**< Condition latch signaling waiting workers */
} cnt_sync_t;

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize a synchronization counter instance.
 *
 * Configures the underlying conditional signaling componentry to utilize CLOCK_MONOTONIC 
 * to safeguard timed tracking operations against system wall-clock adjustments.
 *
 * @param c       Pointer to the counter instance structure.
 * @param initial Seed starting value for the counter.
 *
 * @return 0 on success, -1 on invalid parameter configuration (errno set), aborts on kernel allocation failure.
 */
static inline int cnt_sync_init(cnt_sync_t *c, uint_fast64_t initial) {
    if (c == NULL) {
        errno = EINVAL;
        return -1;
    }

    atomic_init(&c->value, initial);

    pthread_condattr_t attr;
    int rc = pthread_condattr_init(&attr);
    if (rc != 0) {
        errno = rc;
        return -1;
    }

    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc != 0) {
        (void)pthread_condattr_destroy(&attr);
        errno = rc;
        return -1;
    }

    rc = pthread_mutex_init(&c->mutex, NULL);
    if (rc != 0) {
        (void)pthread_condattr_destroy(&attr);
        errno = rc;
        return -1;
    }

    rc = pthread_cond_init(&c->cond, &attr);
    if (rc != 0) {
        (void)pthread_mutex_destroy(&c->mutex);
        (void)pthread_condattr_destroy(&attr);
        errno = rc;
        return -1;
    }

    (void)pthread_condattr_destroy(&attr);
    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Destroy a synchronization counter instance.
 *
 * @param c Pointer to the target counter structure.
 *
 * @warning The caller must guarantee no remaining worker threads are currently blocking on the instance.
 */
static inline void cnt_sync_destroy(cnt_sync_t *c) {
    if (c == NULL) {
        return;
    }

    if (pthread_cond_destroy(&c->cond) != 0) {
        FATAL("pthread_cond_destroy failed");
    }
    if (pthread_mutex_destroy(&c->mutex) != 0) {
        FATAL("pthread_mutex_destroy failed");
    }

    // Completely poison active state targets to catch illegal stale access loops
    atomic_store_explicit(&c->value, UINT_FAST64_MAX, memory_order_relaxed);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Increment the sync counter.
 *
 * Uses relaxed memory sequencing for maximum execution performance profiles.
 *
 * @param c Pointer to the counter structure.
 *
 * @return Updated tracking integer value.
 */
static inline uint_fast64_t cnt_sync_inc(cnt_sync_t *c) {
    if (c == NULL) {
        FATAL("cnt_sync_inc called with NULL instance");
    }
    return atomic_fetch_add_explicit(&c->value, 1, memory_order_relaxed) + 1;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Decrement the sync counter.
 *
 * Broadcasts a wakeup signal across matching wait handles once the value structural threshold reaches zero.
 *
 * @param c Pointer to the counter structure.
 *
 * @return Updated tracking integer value.
 */
static inline uint_fast64_t cnt_sync_dec(cnt_sync_t *c) {
    if (c == NULL) {
        FATAL("cnt_sync_dec called with NULL instance");
    }

    // Lock must be held *during* structural transition checking to fix destruction race paths
    int rc = pthread_mutex_lock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    uint_fast64_t old = atomic_fetch_sub_explicit(&c->value, 1, memory_order_acq_rel);

    if (old == 0) {
        (void)fprintf(stderr, "Critical logic anomaly: system synchronization underflow detected\n");
        abort();
    }

    uint_fast64_t new_val = old - 1;

    if (new_val == 0) {
        rc = pthread_cond_broadcast(&c->cond);
        if (rc != 0) {
            FATAL("pthread_cond_broadcast failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return new_val;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Retrieve a synchronized current value snapshot.
 *
 * @param c Pointer to the counter structure.
 *
 * @return Instantaneous snapshot tracking value.
 */
static inline uint_fast64_t cnt_sync_get(cnt_sync_t *c) {
    if (c == NULL) {
        FATAL("cnt_sync_get called with NULL instance");
    }
    return atomic_load_explicit(&c->value, memory_order_acquire);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block execution context indefinitely until counter reaches zero.
 *
 * @param c Pointer to the counter structure.
 *
 * @code
 * cnt_sync_wait_zero(&sync_latch);
 * // Execution advances safely here once processing tasks are clear
 * @endcode
 */
static inline void cnt_sync_wait_zero(cnt_sync_t *c) {
    if (c == NULL) {
        FATAL("cnt_sync_wait_zero called with NULL instance");
    }

    int rc = pthread_mutex_lock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (atomic_load_explicit(&c->value, memory_order_acquire) != 0) {
        rc = pthread_cond_wait(&c->cond, &c->mutex);
        if (rc != 0) {
            FATAL("pthread_cond_wait failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block execution context until counter reaches zero or timeout expires.
 *
 * @param c          Pointer to the counter structure.
 * @param timeout_ms Max threshold window time to wait (expressed in milliseconds).
 *
 * @return 0 if the latch dropped to zero, -1 on timeout limit hit or argument error (errno set).
 *
 * @code
 * if (cnt_sync_wait_zero_ms(&sync_latch, 5000) == -1) {
 *     if (errno == ETIMEDOUT) {
 *         // Handle fallback for lagging worker thread loops safely
 *     }
 * }
 * @endcode
 */
static inline int cnt_sync_wait_zero_ms(cnt_sync_t *c, uint64_t timeout_ms) {
    if (c == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }

    // 1. Calculate explicit monotonic timeouts defensively against value wrap-arounds
    uint64_t sec_add = timeout_ms / 1000;
    uint64_t nsec_add = (timeout_ms % 1000) * 1000000ULL;

    if (ts.tv_sec > (INT64_MAX - (int64_t)sec_add)) {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec += (time_t)sec_add;
    ts.tv_nsec += (long)nsec_add;

    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    // 2. Perform checked conditional timed loop sequence
    int rc = pthread_mutex_lock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (atomic_load_explicit(&c->value, memory_order_acquire) != 0) {
        int wait_rc = pthread_cond_timedwait(&c->cond, &c->mutex, &ts);
        
        if (wait_rc != 0) {
            rc = pthread_mutex_unlock(&c->mutex);
            if (rc != 0) {
                FATAL("pthread_mutex_unlock failed with code %d", rc);
            }
            errno = wait_rc; // ETIMEDOUT or system constraints
            return -1;
        }
    }

    rc = pthread_mutex_unlock(&c->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* CNT_SYNC_H */