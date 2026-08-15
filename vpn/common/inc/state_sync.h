#ifndef STATE_SYNC_H
#define STATE_SYNC_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Thread-safe synchronized state engine machine.
 *
 * Facilitates multi-threaded state coordination by letting worker context threads
 * block until a specific state variable criteria, range, or bitwise threshold matches.
 */
typedef struct state_sync {
    int state;             /**< The encapsulated underlying synchronized state primitive */
    pthread_mutex_t lock;  /**< Structural mutex protecting state transitions */
    pthread_cond_t cond;   /**< Condition variable orchestrating state change wakeups */
} state_sync_t;

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Internal helper to safely add milliseconds to a monotonic timespec structure.
 *
 * @param ts         Pointer to the target timespec instance.
 * @param timeout_ms The relative execution delay offset window in milliseconds.
 *
 * @return 0 on successful addition, -1 on integer overflow safety exception (errno set).
 */
static inline int state_sync_timespec_add_ms(struct timespec *ts, uint32_t timeout_ms) {
    uint64_t sec_add = timeout_ms / 1000;
    uint64_t nsec_add = (timeout_ms % 1000) * 1000000ULL;

    // Guard against potential epoch type variable wrapping
    if (ts->tv_sec > (INT64_MAX - (int64_t)sec_add)) {
        return -EINVAL;
    }

    ts->tv_sec += (time_t)sec_add;
    ts->tv_nsec += (long)nsec_add;

    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize a synchronized state engine instance.
 *
 * @param s             Pointer to the state synchronization tracking block.
 * @param initial_state Starting value assigned to the state tracker.
 *
 * @return 0 on success, -1 on invalid argument structure (errno set), aborts on kernel init failure.
 */
static inline int state_sync_init(state_sync_t *s, int initial_state) {
    if (s == NULL) {
        return -EINVAL;
    }

    s->state = initial_state;

    int rc = pthread_mutex_init(&s->lock, NULL);
    if (rc != 0) {
        return -rc;
    }

    pthread_condattr_t attr;
    rc = pthread_condattr_init(&attr);
    if (rc != 0) {
        (void)pthread_mutex_destroy(&s->lock);
        return -rc;
    }

    // Set monotonic source execution to guarantee timing safety against clock skew
    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc != 0) {
        (void)pthread_condattr_destroy(&attr);
        (void)pthread_mutex_destroy(&s->lock);
        return -rc;
    }

    rc = pthread_cond_init(&s->cond, &attr);
    if (rc != 0) {
        (void)pthread_condattr_destroy(&attr);
        (void)pthread_mutex_destroy(&s->lock);
        return -rc;
    }

    (void)pthread_condattr_destroy(&attr);
    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Destroy a synchronized state engine instance.
 *
 * @param s Pointer to the active state synchronization tracking block.
 *
 * @warning The caller must guarantee no threads are currently actively blocking or signaling this instance.
 */
static inline void state_sync_destroy(state_sync_t *s) {
    if (s == NULL) {
        return;
    }

    if (pthread_cond_destroy(&s->cond) != 0) {
        FATAL("pthread_cond_destroy failed");
    }
    if (pthread_mutex_destroy(&s->lock) != 0) {
        FATAL("pthread_mutex_destroy failed");
    }

    // Explicitly poison state values to trap any illegal use-after-free access attempts
    s->state = -1;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Thread-safely update the internal tracking engine state.
 *
 * Broadcasts a wakeup notice to all blocked listening workers if a true state alteration occurs.
 *
 * @param s         Pointer to the state synchronization tracking block.
 * @param new_state The targeted value to update across execution handles.
 */
static inline void state_sync_set(state_sync_t *s, int new_state) {
    if (s == NULL) {
        FATAL("state_sync_set called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    if (s->state != new_state) {
        s->state = new_state;

        rc = pthread_cond_broadcast(&s->cond);
        if (rc != 0) {
            FATAL("pthread_cond_broadcast failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Snapshot the instantaneous state value.
 *
 * @param s Pointer to the state synchronization tracking block.
 *
 * @return Int current state value.
 */
static inline int state_sync_get(state_sync_t *s) {
    if (s == NULL) {
        FATAL("state_sync_get called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    int val = s->state;

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return val;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Perform a synchronized exact-match check against current state.
 *
 * @param s     Pointer to the state synchronization tracking block.
 * @param state Target value to compare against.
 *
 * @return true if matches exactly, false otherwise.
 */
static inline bool state_sync_check(state_sync_t *s, int state) {
    if (s == NULL) {
        FATAL("state_sync_check called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    bool result = (s->state == state);

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return result;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block indefinitely until state matches target value exactly.
 *
 * @param s      Pointer to the state synchronization tracking block.
 * @param target Targeted configuration integer value to release block loops.
 *
 * @code
 * state_sync_wait(&engine_state, STATE_CONNECTED);
 * // Execution advances safely once state matches target
 * @endcode
 */
static inline void state_sync_wait(state_sync_t *s, int target) {
    if (s == NULL) {
        FATAL("state_sync_wait called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (s->state != target) {
        rc = pthread_cond_wait(&s->cond, &s->lock);
        if (rc != 0) {
            FATAL("pthread_cond_wait failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block execution until state matches target or timeout expires.
 *
 * @param s          Pointer to the state synchronization tracking block.
 * @param target     Targeted state criteria necessary to clear constraint evaluation.
 * @param timeout_ms Relative length to stall waiting threads in milliseconds.
 *
 * @return 0 on success matching value target, -1 on timeout limit hit or system constraint fault (errno set).
 *
 * @code
 * if (state_sync_wait_ms(&engine_state, STATE_READY, 2500) == -1) {
 *     if (errno == ETIMEDOUT) {
 *         // Handle recovery or retry logic paths cleanly
 *     }
 * }
 * @endcode
 */
static inline int state_sync_wait_ms(state_sync_t *s, int target, uint32_t timeout_ms) {
    if (s == NULL) {
        return -EINVAL;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -ECANCELED;
    }

    if (state_sync_timespec_add_ms(&ts, timeout_ms) != 0) {
        return -ECANCELED;
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (s->state != target) {
        int wait_rc = pthread_cond_timedwait(&s->cond, &s->lock, &ts);

        if (wait_rc != 0) {
            rc = pthread_mutex_unlock(&s->lock);
            if (rc != 0) {
                FATAL("pthread_mutex_unlock failed with code %d", rc);
            }
            return -ETIMEDOUT;
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return 0;
}

static inline int state_sync_wait_ms_abort(state_sync_t *s, int target, int abort_state, uint32_t timeout_ms) {
    if (s == NULL) {
        return -EINVAL;
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    // Fast-path check before timespec calculation
    if (s->state == target) {
        pthread_mutex_unlock(&s->lock);
        return 0;
    }
    if (s->state == abort_state) {
        pthread_mutex_unlock(&s->lock);
        return -ECONNABORTED; // Immediate abort return
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || 
        state_sync_timespec_add_ms(&ts, timeout_ms) != 0) {
        pthread_mutex_unlock(&s->lock);
        return -ECANCELED;
    }

    while (s->state != target) {
        // If state changed to abort state during a wake-up, return immediately
        if (s->state == abort_state) {
            pthread_mutex_unlock(&s->lock);
            return -ECONNABORTED;
        }

        int wait_rc = pthread_cond_timedwait(&s->cond, &s->lock, &ts);
        if (wait_rc != 0) {
            // Check state once more in case state was updated right as timer expired
            if (s->state == target) {
                break;
            }
            if (s->state == abort_state) {
                pthread_mutex_unlock(&s->lock);
                return -ECONNABORTED;
            }

            pthread_mutex_unlock(&s->lock);
            return -ETIMEDOUT;
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block indefinitely until internal state engine values hit either of two distinct outcomes.
 *
 * @param s Pointer to the state synchronization tracking block.
 * @param a First value selection option.
 * @param b Second value selection option.
 */
static inline void state_sync_wait_for_any(state_sync_t *s, int a, int b) {
    if (s == NULL) {
        FATAL("state_sync_wait_for_any called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (s->state != a && s->state != b) {
        rc = pthread_cond_wait(&s->cond, &s->lock);
        if (rc != 0) {
            FATAL("pthread_cond_wait failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Block execution streams while state continues to match target condition.
 *
 * Delivers inverse conditional validation loops, stalling callers as long as specified state persists.
 *
 * @param s     Pointer to the state synchronization tracking block.
 * @param value State identity parameter that acts as the block criteria.
 */
static inline void state_sync_wait_while(state_sync_t *s, int value) {
    if (s == NULL) {
        FATAL("state_sync_wait_while called with NULL instance");
    }

    int rc = pthread_mutex_lock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (s->state == value) {
        rc = pthread_cond_wait(&s->cond, &s->lock);
        if (rc != 0) {
            FATAL("pthread_cond_wait failed with code %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&s->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* STATE_SYNC_H */