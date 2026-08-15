#ifndef LF_POOL_H
#define LF_POOL_H

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
 * @brief Node prefix embedded directly before the user payload block.
 */
typedef struct lf_pool_block_t {
    uint32_t next_idx;         /**< Array index of the next free chunk slot */
} lf_pool_block_t;

/**
 * @brief 64-bit Combined Head Tag for ABA Elimination.
 * Packs a 32-bit index and a 32-bit generation counter into a single 
 * register to allow atomic CAS loops without 128-bit instructions.
 */
typedef union {
    uint64_t raw;
    struct {
        uint32_t next_idx;     /**< Free list head index */
        uint32_t generation;   /**< Protection wrapper against the ABA problem */
    } split;
} lf_pool_head_t;

/**
 * @brief Fixed-Size, Pre-allocated, Blocking, Lock-Free Memory Pool.
 *
 * This pool pre-allocates its entire capacity up front as a contiguous memory arena.
 * Tracking uses an atomic Treiber stack (free-list) via 64-bit atomic CAS operations.
 * A POSIX semaphore handles blocking threads cleanly at 0% CPU when the pool runs dry.
 */
typedef struct lf_pool {
    size_t block_size;         /**< Footprint of the payload requested by the user */
    size_t real_block_size;    /**< Total block size including header and alignment gaps */
    size_t capacity;           /**< Maximum aggregate chunks permitted */
    void *raw_memory;          /**< Contiguous chunk of pre-allocated arena space */

    _Alignas(64) _Atomic uint64_t head;       /**< Atomic free-list stack top tracker */
    _Alignas(64) _Atomic size_t in_use;       /**< Telemetry count tracking checked-out blocks */

    sem_t blocks_sem;          /**< Manages thread sleeping/waking via kernel signaling */
} lf_pool_t;

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize and pre-allocate the lock-free memory pool.
 *
 * @param p          Pointer to the lf_pool instance.
 * @param block_size Individual byte allocation size for each chunk payload.
 * @param capacity   Total number of blocks to pre-allocate. Cannot be 0.
 *
 * @return 0 on success, -1 on configuration errors (errno set).
 */
static inline int lf_pool_init(lf_pool_t *p, size_t block_size, size_t capacity) {
    if (p == NULL || block_size == 0 || capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    if (capacity >= UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }

    (void)memset(p, 0, sizeof(*p));
    p->block_size = block_size;
    p->capacity = capacity;

    // Calculate total block size incorporating the intrusive prefix header
    size_t allocation_size = sizeof(lf_pool_block_t) + block_size;
    allocation_size = (allocation_size + 7) & ~7; // Strict 8-byte pointer boundary alignment
    p->real_block_size = allocation_size;

    // 1. NON-LAZY: Allocate the entire memory space right now
    p->raw_memory = malloc(capacity * p->real_block_size);
    if (p->raw_memory == NULL) {
        errno = ENOMEM;
        return -1;
    }
    (void)memset(p->raw_memory, 0, capacity * p->real_block_size);

    // 2. Link all slots together into an internal free-list array index chain
    for (size_t i = 0; i < capacity - 1; i++) {
        lf_pool_block_t *b = (lf_pool_block_t *)((char *)p->raw_memory + (i * p->real_block_size));
        b->next_idx = (uint32_t)(i + 1);
    }
    // Terminal element points to the end sentinel
    lf_pool_block_t *last = (lf_pool_block_t *)((char *)p->raw_memory + ((capacity - 1) * p->real_block_size));
    last->next_idx = UINT32_MAX;

    // 3. Set up the initial atomic tracking register (Index 0, Gen 0)
    lf_pool_head_t init_head;
    init_head.split.next_idx = 0;
    init_head.split.generation = 0;
    atomic_init(&p->head, init_head.raw);
    atomic_init(&p->in_use, 0);

    // 4. Seed the semaphore with the exact pre-allocated allocation capacity
    if (sem_init(&p->blocks_sem, 0, (unsigned int)capacity) != 0) {
        free(p->raw_memory);
        p->raw_memory = NULL;
        return -1;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Destroy the memory pool and release the pre-allocated arena.
 */
static inline int lf_pool_destroy(lf_pool_t *p) {
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }

    size_t leaking = atomic_load_explicit(&p->in_use, memory_order_relaxed);
    if (leaking != 0) {
        (void)fprintf(stderr, "[lf_pool] WARNING: %zu blocks still checked out during destruction\n", leaking);
    }

    sem_destroy(&p->blocks_sem);
    
    if (p->raw_memory) {
        free(p->raw_memory);
        p->raw_memory = NULL;
    }

    p->block_size = 0;
    p->real_block_size = 0;
    p->capacity = 0;
    atomic_store(&p->head, 0);
    atomic_store(&p->in_use, 0);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Check out an element from the pool (Non-blocking execution).
 * Perfect for your MSQuic thread. If no blocks are ready, it returns NULL instantly.
 */
static inline void *lf_pool_try_get(lf_pool_t *p) {
    if (p == NULL || p->raw_memory == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // Secure an allocation token from the semaphore safely
    while (sem_trywait(&p->blocks_sem) == -1) {
        if (errno != EINTR) {
            return NULL; // Returns NULL with errno = EAGAIN if pool has run dry
        }
    }

    lf_pool_head_t old_head;
    lf_pool_head_t new_head;
    old_head.raw = atomic_load_explicit(&p->head, memory_order_relaxed);

    // Pop the index from the free list stack top using atomic CAS loop
    do {
        if (old_head.split.next_idx == UINT32_MAX) {
            sem_post(&p->blocks_sem); // Refund token on edge case logic anomaly
            errno = EAGAIN;
            return NULL;
        }

        lf_pool_block_t *b = (lf_pool_block_t *)((char *)p->raw_memory + (old_head.split.next_idx * p->real_block_size));
        new_head.split.next_idx = b->next_idx;
        new_head.split.generation = old_head.split.generation + 1;

    } while (!atomic_compare_exchange_weak_explicit(
                &p->head, &old_head.raw, new_head.raw, 
                memory_order_acquire, memory_order_relaxed));

    atomic_fetch_add_explicit(&p->in_use, 1, memory_order_relaxed);

    lf_pool_block_t *final_block = (lf_pool_block_t *)((char *)p->raw_memory + (old_head.split.next_idx * p->real_block_size));
    
    // Offset pointer by 1 structure unit to return the address trailing the header
    return (void *)(final_block + 1);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Check out an element from the pool (Blocking execution via OS Sleep).
 *
 * If empty, the calling thread sleeps inside the kernel at 0% CPU until a block returns.
 */
static inline void *lf_pool_wait_get(lf_pool_t *p) {
    if (p == NULL || p->raw_memory == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // Suspend execution in the kernel if the semaphore pool count is zero
    while (sem_wait(&p->blocks_sem) == -1) {
        if (errno != EINTR) {
            return NULL;
        }
    }

    lf_pool_head_t old_head;
    lf_pool_head_t new_head;
    old_head.raw = atomic_load_explicit(&p->head, memory_order_relaxed);

    // Execute atomic pop sequence
    do {
        lf_pool_block_t *b = (lf_pool_block_t *)((char *)p->raw_memory + (old_head.split.next_idx * p->real_block_size));
        new_head.split.next_idx = b->next_idx;
        new_head.split.generation = old_head.split.generation + 1;

    } while (!atomic_compare_exchange_weak_explicit(
                &p->head, &old_head.raw, new_head.raw, 
                memory_order_acquire, memory_order_relaxed));

    atomic_fetch_add_explicit(&p->in_use, 1, memory_order_relaxed);

    lf_pool_block_t *final_block = (lf_pool_block_t *)((char *)p->raw_memory + (old_head.split.next_idx * p->real_block_size));
    return (void *)(final_block + 1);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Reclaim a block pointer back into the pool.
 * Wakes up any thread sleeping inside lf_pool_wait_get().
 */
static inline void lf_pool_put(lf_pool_t *p, void *ptr) {
    if (p == NULL || p->raw_memory == NULL || ptr == NULL) {
        return;
    }

    // Shift pointer offset backward by 1 lf_pool_block_t size to reveal control block
    lf_pool_block_t *b = ((lf_pool_block_t *)ptr) - 1;

    // Resolve where this block lives inside the continuous memory arena array
    char *block_bytes = (char *)b;
    char *arena_bytes = (char *)p->raw_memory;
    uint32_t block_index = (uint32_t)((block_bytes - arena_bytes) / p->real_block_size);

    lf_pool_head_t old_head;
    lf_pool_head_t new_head;
    old_head.raw = atomic_load_explicit(&p->head, memory_order_relaxed);

    // Push the block onto the free list top lock-free
    do {
        b->next_idx = old_head.split.next_idx;
        new_head.split.next_idx = block_index;
        new_head.split.generation = old_head.split.generation + 1;

    } while (!atomic_compare_exchange_weak_explicit(
                &p->head, &old_head.raw, new_head.raw, 
                memory_order_release, memory_order_relaxed));

    atomic_fetch_sub_explicit(&p->in_use, 1, memory_order_relaxed);

    // Kick the semaphore to alert waiting consumer threads
    sem_post(&p->blocks_sem);
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Retrieve a synchronized snapshot of currently active checked out blocks.
 */
static inline ssize_t lf_pool_get_used(lf_pool_t *p) {
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return (ssize_t)atomic_load_explicit(&p->in_use, memory_order_relaxed);
}

#ifdef __cplusplus
}
#endif

#endif // LF_POOL_H