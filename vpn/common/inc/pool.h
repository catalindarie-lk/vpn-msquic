
#ifndef POOL_H
#define POOL_H

#if defined(__linux__)

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALIGN_UP(size, align) (((size) + ((align) - 1)) & ~((align) - 1))

typedef struct pool_t pool_t;

/**
 * @brief Header prepended to every memory payload.
 */
typedef struct pool_block_t {
    struct pool_block_t *next;
    pool_t *pool;
} pool_block_t;

typedef struct pool_t {
    size_t block_size;       /**< Raw user payload size */
    size_t cap;              /**< Upper node limit (0 = unlimited) */
    size_t total_blocks;     /**< Total nodes allocated */
    ssize_t in_use;          /**< Currently checked-out blocks */
    size_t allocators;       /**< Active threads currently in malloc() */
    
    uint8_t _pad1[24];
    pool_block_t *free_list; /**< Recycled node stack */
    uint8_t _pad2[56];
    pthread_mutex_t lock;
    uint8_t pad3[24];
    pthread_cond_t cond;     /**< Signaled on put() or destroy() */
} pool_t;


/**
 * @brief Initialize a dynamically allocated memory pool instance.
 *
 * @param block_size Byte payload size requested per unit.
 * @param cap Maximum capacity permitted (0 for uncapped).
 * @return Pointer to allocated pool instance, or NULL on error.
 */
static inline pool_t *pool_init(size_t block_size, size_t cap) {
    if (block_size == 0) {
        errno = EINVAL;
        return NULL;
    }

    if (block_size > (SIZE_MAX - sizeof(pool_block_t))) {
        errno = EINVAL;
        return NULL;
    }

    /* Ensure size is a multiple of 64 bytes */
    size_t alloc_size = ALIGN_UP(sizeof(pool_t), 64);
    pool_t *p = (pool_t *)aligned_alloc(64, alloc_size);
    if (p == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    (void)memset(p, 0, sizeof(*p));
    p->block_size = block_size;
    p->cap = cap;

    if (pthread_mutex_init(&p->lock, NULL) != 0) {
        free(p);
        errno = ENOMEM;
        return NULL;
    }

    if (pthread_cond_init(&p->cond, NULL) != 0) {
        (void)pthread_mutex_destroy(&p->lock);
        free(p);
        errno = ENOMEM;
        return NULL;
    }

    return p;
}

/**
 * @brief Non-blocking checkout of an element from the pool.
 *
 * @param p Pointer to pool instance.
 * @return Pointer to payload, or NULL if empty/exhausted.
 */
static inline void *pool_try_get(pool_t *p) {
    if (p == NULL) {
        errno = EINVAL;
        return NULL;
    }

    int rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    pool_block_t *b = p->free_list;

    if (b != NULL) {
        p->free_list = b->next;
        b->pool = p;
        p->in_use++;
        rc = pthread_mutex_unlock(&p->lock);
        if (rc != 0) {
            FATAL("pthread_mutex_unlock failed with code %d", rc);
        }
        return (void *)(b + 1);
    }

    if (p->cap != 0 && p->total_blocks >= p->cap) {
        rc = pthread_mutex_unlock(&p->lock);
        if (rc != 0) {
            FATAL("pthread_mutex_unlock failed with code %d", rc);
        }
        errno = EAGAIN;
        return NULL;
    }

    p->total_blocks++;

    rc = pthread_mutex_unlock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    // size_t allocation_size = sizeof(pool_block_t) + p->block_size;
    // b = (pool_block_t *)malloc(allocation_size);

    size_t alloc_size = ALIGN_UP(sizeof(pool_block_t) + p->block_size, 64);
    b = (pool_block_t *)aligned_alloc(64, alloc_size);

    if (b == NULL) {
        (void)pthread_mutex_lock(&p->lock);
        p->total_blocks--;
        (void)pthread_mutex_unlock(&p->lock);
        errno = ENOMEM;
        return NULL;
    }

    rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }
    b->pool = p;
    p->in_use++;
    rc = pthread_mutex_unlock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return (void *)(b + 1);
}


/**
 * @brief Blocking checkout of an element from the pool.
 *
 * @param p Pointer to pool instance.
 * @return Pointer to payload, or NULL on allocation error.
 */
static inline void *pool_wait_get(pool_t *p) {
    if (p == NULL) {
        errno = EINVAL;
        return NULL;
    }

    int rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    while (1) {
        pool_block_t *b = p->free_list;

        if (b != NULL) {
            p->free_list = b->next;
            b->pool = p;
            p->in_use++;
            rc = pthread_mutex_unlock(&p->lock);
            if (rc != 0) {
                FATAL("pthread_mutex_unlock failed with code %d", rc);
            }
            return (void *)(b + 1);
        }

        if (p->cap == 0 || p->total_blocks < p->cap) {
            p->total_blocks++;
            rc = pthread_mutex_unlock(&p->lock);
            if (rc != 0) {
                FATAL("pthread_mutex_unlock failed with code %d", rc);
            }

            // size_t allocation_size = sizeof(pool_block_t) + p->block_size;
            // b = (pool_block_t *)malloc(allocation_size);

            size_t alloc_size = ALIGN_UP(sizeof(pool_block_t) + p->block_size, 64);
            b = (pool_block_t *)aligned_alloc(64, alloc_size);

            if (b == NULL) {
                (void)pthread_mutex_lock(&p->lock);
                p->total_blocks--;
                (void)pthread_mutex_unlock(&p->lock);
                errno = ENOMEM;
                return NULL;
            }

            rc = pthread_mutex_lock(&p->lock);
            if (rc != 0) {
                FATAL("pthread_mutex_lock failed with code %d", rc);
            }
            b->pool = p;
            p->in_use++;
            rc = pthread_mutex_unlock(&p->lock);
            if (rc != 0) {
                FATAL("pthread_mutex_unlock failed with code %d", rc);
            }
            return (void *)(b + 1);
        }

        rc = pthread_cond_wait(&p->cond, &p->lock);
        if (rc != 0) {
            FATAL("pthread_cond_wait failed with code %d", rc);
        }
    }
}


/**
 * @brief Reclaim a block pointer back into the pool.
 *
 * @param ptr Address of user block payload being returned.
 */
static inline void pool_put(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    pool_block_t *b = ((pool_block_t *)ptr) - 1;
    pool_t *p = b->pool;

    int rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    p->in_use--;

    if (p->in_use < 0) {
        FATAL("Critical logic anomaly: structural pool underflow detected");
    }

    b->next = p->free_list;
    p->free_list = b;

    rc = pthread_cond_signal(&p->cond);
    if (rc != 0) {
        FATAL("pthread_cond_signal failed with code %d", rc);
    }

    rc = pthread_mutex_unlock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }
}

/**
 * @brief Destroy memory pool and clear all allocated blocks.
 *
 * @param p Pointer to pool instance.
 * @return 0 on success, or negative error code on invalid argument.
 */
static inline int pool_destroy(pool_t *p) {
    if (p == NULL) {
        return -EINVAL;
    }

    int rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }
    if (p->in_use != 0) {
        (void)fprintf(stderr,
                      "[pool] WARNING: %zd blocks checked out on destroy\n",
                      p->in_use);
    }
    rc = pthread_mutex_unlock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    if (pthread_cond_destroy(&p->cond) != 0) {
        FATAL("pthread_cond_destroy failed");
    }
    if (pthread_mutex_destroy(&p->lock) != 0) {
        FATAL("pthread_mutex_destroy failed");
    }

    pool_block_t *b = p->free_list;
    while (b != NULL) {
        pool_block_t *next = b->next;
        free(b);
        b = next;
    }

    p->free_list = NULL;
    p->total_blocks = 0;
    p->in_use = 0;
    p->block_size = 0;
    p->cap = 0;

    free(p);
    return 0;
}

/**
 * @brief Retrieve snapshot count of checked out blocks.
 *
 * @param p Pointer to pool instance.
 * @return Number of checked out elements, or -1 on error.
 */
static inline ssize_t pool_get_used(pool_t *p) {
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }

    int rc = pthread_mutex_lock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    ssize_t active_blocks = p->in_use;

    rc = pthread_mutex_unlock(&p->lock);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return active_blocks;
}

#ifdef __cplusplus
}
#endif

// END LINUX

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// START WINDOWS
#elif defined(_WIN32) || defined(_WIN64)

#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALIGN_UP(size, align) (((size) + ((align) - 1)) & ~((align) - 1))

typedef struct pool_t pool_t;

/**
 * @brief Header prepended to every memory payload.
 */
typedef struct pool_block_t {
    struct pool_block_t *next;
    pool_t *pool;
} pool_block_t;

typedef struct pool_t {
    size_t block_size;       /**< Raw user payload size */
    size_t cap;              /**< Upper node limit (0 = unlimited) */
    size_t total_blocks;     /**< Total nodes allocated */
    SSIZE_T in_use;          /**< Currently checked-out blocks */
    size_t allocators;       /**< Active threads currently in malloc() */
    
    uint8_t _pad1[24];
    pool_block_t *free_list; /**< Recycled node stack */
    uint8_t _pad2[56];
    CRITICAL_SECTION lock;   /**< Replaces pthread_mutex_t */
    uint8_t _pad3[24];
    CONDITION_VARIABLE cond; /**< Replaces pthread_cond_t */
} pool_t;

static inline pool_t *pool_init(size_t block_size, size_t cap) {
    if (block_size == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (block_size > (SIZE_MAX - sizeof(pool_block_t))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Ensure total allocation size is a multiple of 64 bytes */
    size_t alloc_size = ALIGN_UP(sizeof(pool_t), 64);
    
    /* Windows requires _aligned_malloc for specific alignment */
    pool_t *p = (pool_t *)_aligned_malloc(alloc_size, 64);
    if (p == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    (void)memset(p, 0, sizeof(*p));
    p->block_size = block_size;
    p->cap = cap;

    InitializeCriticalSection(&p->lock);
    InitializeConditionVariable(&p->cond);

    return p;
}

static inline void *pool_try_get(pool_t *p) {
    if (p == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    EnterCriticalSection(&p->lock);

    /* 1. Reuse from free list */
    pool_block_t *b = p->free_list;
    if (b != NULL) {
        p->free_list = b->next;
        b->pool = p;
        p->in_use++;
        LeaveCriticalSection(&p->lock);
        return (void *)(b + 1);
    }

    /* 2. Check capacity */
    if (p->cap != 0 && p->total_blocks >= p->cap) {
        LeaveCriticalSection(&p->lock);
        SetLastError(ERROR_BUSY);
        return NULL;
    }

    size_t alloc_size = sizeof(pool_block_t) + p->block_size;
    p->allocators++;

    LeaveCriticalSection(&p->lock);

    /* Allocate memory */
    b = (pool_block_t *)malloc(alloc_size);

    EnterCriticalSection(&p->lock);

    p->allocators--;

    if (b == NULL) {
        WakeAllConditionVariable(&p->cond);
        LeaveCriticalSection(&p->lock);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    /* Double-check capacity overrun */
    if (p->cap != 0 && p->total_blocks >= p->cap) {
        free(b);
        WakeAllConditionVariable(&p->cond);
        LeaveCriticalSection(&p->lock);
        SetLastError(ERROR_BUSY);
        return NULL;
    }

    p->total_blocks++;
    p->in_use++;
    b->pool = p;

    LeaveCriticalSection(&p->lock);

    return (void *)(b + 1);
}

static inline void *pool_wait_get(pool_t *p) {
    if (p == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    EnterCriticalSection(&p->lock);

    while (1) {
        /* 1. Reuse from free list */
        pool_block_t *b = p->free_list;
        if (b != NULL) {
            p->free_list = b->next;
            b->pool = p;
            p->in_use++;
            LeaveCriticalSection(&p->lock);
            return (void *)(b + 1);
        }

        /* 2. Expand capacity if allowed */
        if (p->cap == 0 || p->total_blocks < p->cap) {
            size_t alloc_size = sizeof(pool_block_t) + p->block_size;
            p->allocators++;

            LeaveCriticalSection(&p->lock);

            b = (pool_block_t *)malloc(alloc_size);

            EnterCriticalSection(&p->lock);

            p->allocators--;

            if (b == NULL) {
                /* On allocation failure, wait for an existing block to free up */
                SleepConditionVariableCS(&p->cond, &p->lock, INFINITE);
                continue;
            }

            if (p->cap != 0 && p->total_blocks >= p->cap) {
                free(b);
                WakeAllConditionVariable(&p->cond);
                continue;
            }

            p->total_blocks++;
            p->in_use++;
            b->pool = p;

            LeaveCriticalSection(&p->lock);
            return (void *)(b + 1);
        }

        /* 3. Wait on capacity */
        SleepConditionVariableCS(&p->cond, &p->lock, INFINITE);
    }
}

static inline void pool_put(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    pool_block_t *b = ((pool_block_t *)ptr) - 1;
    pool_t *p = b->pool;

    EnterCriticalSection(&p->lock);

    p->in_use--;
    if (p->in_use < 0) {
        FATAL("Critical logic anomaly: structural pool underflow detected");
    }

    b->next = p->free_list;
    p->free_list = b;

    WakeConditionVariable(&p->cond);

    LeaveCriticalSection(&p->lock);
}

static inline int pool_destroy(pool_t *p) {
    if (p == NULL) {
        return -ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&p->lock);

    /* Wait for active allocators to leave malloc() */
    while (p->allocators > 0) {
        SleepConditionVariableCS(&p->cond, &p->lock, INFINITE);
    }

    if (p->in_use != 0) {
        (void)fprintf(stderr,
                      "[pool] WARNING: %Id blocks checked out on destroy\n",
                      p->in_use);
    }

    pool_block_t *b = p->free_list;
    while (b != NULL) {
        pool_block_t *next = b->next;
        free(b);
        b = next;
    }

    LeaveCriticalSection(&p->lock);

    DeleteCriticalSection(&p->lock);
    /* Condition variables on Windows do not require explicit destruction */

    /* Must use _aligned_free since pool_init used _aligned_malloc */
    _aligned_free(p);
    return 0;
}

static inline SSIZE_T pool_get_used(pool_t *p) {
    if (p == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    EnterCriticalSection(&p->lock);

    SSIZE_T active_blocks = p->in_use;

    LeaveCriticalSection(&p->lock);

    return active_blocks;
}

#ifdef __cplusplus
}
#endif

// END WINDOWS

#else
    // Other operating systems
#endif


#endif /* POOL_H */