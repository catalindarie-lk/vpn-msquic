#ifndef LF_QUEUE_H
#define LF_QUEUE_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <semaphore.h>
#include <errno.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Bounded, Blocking, Lock-Free SPSC FIFO Queue.
 *
 * This queue uses C11 atomics for the data path to eliminate mutex contention.
 * It integrates a POSIX semaphore to handle blocking/sleeping seamlessly,
 * ensuring 0% CPU utilization when the queue is empty or full.
 *
 * Constraints:
 * - 1 Producer thread and 1 Consumer thread ONLY.
 * - Capacity MUST be a power of 2.
 */
typedef struct lf_queue {
    size_t capacity;       /**< Maximum elements the queue can hold (Power of 2) */
    size_t mask;           /**< Bitwise mask (capacity - 1) */
    void **ptr;            /**< Internal storage pointer array */

    _Alignas(64) _Atomic size_t tail; /**< Modified exclusively by PRODUCER */
    _Alignas(64) _Atomic size_t head; /**< Modified exclusively by CONSUMER */

    // OS signaling primitives for sleeping/waking
    sem_t items_sem;       /**< Tracks available items to pop (blocks consumer) */
} lf_queue_t;

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize the blocking lock-free queue.
 */
static inline int lf_queue_init(lf_queue_t *q, const size_t size) {
    if (q == NULL || size == 0) {
        errno = EINVAL;
        return -1;
    }

    // Capacity must be a power of two
    if ((size & (size - 1)) != 0) {
        (void)fprintf(stderr, "[QUEUE ERROR] Capacity %zu must be a power of 2.\n", size);
        errno = EINVAL;
        return -1;
    }

    q->capacity = size;
    q->mask = size - 1;

    q->ptr = (void **)malloc(size * sizeof(void *));
    if (q->ptr == NULL) {
        errno = ENOMEM;
        return -1;
    }
    (void)memset(q->ptr, 0, size * sizeof(void *));

    atomic_init(&q->tail, 0);
    atomic_init(&q->head, 0);

    // Initialize semaphore to 0 (queue starts empty)
    if (sem_init(&q->items_sem, 0, 0) != 0) {
        free(q->ptr);
        q->ptr = NULL;
        return -1;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue. Non-blocking fallback version.
 */
static inline int lf_queue_try_push(lf_queue_t *q, void *ptr) {
    if (q == NULL || q->ptr == NULL || ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    size_t current_tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t current_head = atomic_load_explicit(&q->head, memory_order_acquire);

    if ((current_tail - current_head) >= q->capacity) {
        errno = EAGAIN;
        return -1;
    }

    q->ptr[current_tail & q->mask] = ptr;
    atomic_store_explicit(&q->tail, current_tail + 1, memory_order_release);

    // Increment semaphore to wake up consumer if it's sleeping
    sem_post(&q->items_sem);
    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue (Blocking variant).
 * If the queue is full, it will yield/pause via hardware hint wrappers.
 */
static inline int lf_queue_wait_push(lf_queue_t *q, void *ptr) {
    while (lf_queue_try_push(q, ptr) == -1) {
        if (errno != EAGAIN) return -1;
#if defined(__x86_64__)
        __builtin_ia32_pause();
#endif
    }
    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Pop an element from the queue (True Blocking via OS Sleep).
 *
 * If the queue is empty, the thread goes to sleep inside the kernel via sem_wait.
 * It consumes 0% CPU while waiting.
 */
static inline void *lf_queue_wait_pop(lf_queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // 1. Block/Sleep inside the OS kernel if semaphore count is 0.
    // Handles signal interruptions (EINTR) automatically by looping.
    while (sem_wait(&q->items_sem) == -1) {
        if (errno != EINTR) {
            return NULL;
        }
    }

    // 2. Once woken up, we are GUARANTEED an item is available in the ring buffer.
    // We can extract it using pure atomic calculations.
    size_t current_head = atomic_load_explicit(&q->head, memory_order_relaxed);
    
    void *entry = q->ptr[current_head & q->mask];
    q->ptr[current_head & q->mask] = NULL; 

    atomic_store_explicit(&q->head, current_head + 1, memory_order_release);
    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Non-blocking pop.
 */
static inline void *lf_queue_try_pop(lf_queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // 1. Secure the token first. If empty, returns -1 and sets EAGAIN cleanly.
    while (sem_trywait(&q->items_sem) == -1) {
        if (errno != EINTR) return NULL; 
    }

    // 2. Safely extract because the token guarantees an item is waiting for us
    size_t current_head = atomic_load_explicit(&q->head, memory_order_relaxed);
    
    void *entry = q->ptr[current_head & q->mask];
    q->ptr[current_head & q->mask] = NULL;

    atomic_store_explicit(&q->head, current_head + 1, memory_order_release);
    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Return current queue depth.
 */
static inline ssize_t lf_queue_get_pending(lf_queue_t *q) {
    if (q == NULL || q->ptr == NULL) return -1;
    size_t current_head = atomic_load_explicit(&q->head, memory_order_acquire);
    size_t current_tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    return (ssize_t)(current_tail - current_head);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Teardown allocation resources and destroy semaphore handles.
 */
static inline int lf_queue_destroy(lf_queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    sem_destroy(&q->items_sem);
    free(q->ptr);
    q->ptr = NULL;
    q->capacity = 0;
    q->mask = 0;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // LF_QUEUE_H 