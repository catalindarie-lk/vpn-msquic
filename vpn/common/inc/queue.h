#ifndef QUEUE_H
#define QUEUE_H

#if defined(__linux__)

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>

#include "utils.h"

#ifndef SEM_VALUE_MAX
#define SEM_VALUE_MAX INT_MAX
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Thread-safe bounded FIFO queue.
 *
 * This queue is designed for producer-consumer scenarios with multiple threads.
 * It uses:
 *  - a mutex to protect internal state
 *  - two semaphores:
 *      - push_semaphore: tracks available space (free slots)
 *      - pop_semaphore:  tracks available items (queued elements)
 *
 * The queue stores generic pointers (void*). Ownership of the pointed-to memory
 * is NOT managed by the queue (caller is responsible).
 *
 * Behavior:
 *  - queue_wait_push(): blocks if the queue is full
 *  - queue_try_push(): non-blocking, fails if full
 *  - queue_wait_pop(): blocks if the queue is empty
 *  - queue_try_pop(): non-blocking, returns NULL if empty
 */
typedef struct queue_t {
    size_t size;          /**< Maximum number of elements the queue can hold */
    void **ptr;           /**< Circular buffer storing elements (void*) */

    size_t head;          /**< Index of next element to pop */
    size_t tail;          /**< Index of next slot to push */
    size_t pending;       /**< Current number of elements in the queue */

    pthread_mutex_t mutex; /**< Protects access to head/tail/pending */

    /**
     * @brief Semaphore tracking available space.
     *
     * Initialized to 'size'.
     * Decremented on push, incremented on pop.
     */
    sem_t push_semaphore;

    /**
     * @brief Semaphore tracking available items.
     *
     * Initialized to 0.
     * Incremented on push, decremented on pop.
     */
    sem_t pop_semaphore;

} queue_t;



//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize a queue with a maximum capacity.
 *
 * @param size Maximum number of elements the queue can hold.
 *
 * @return Pointer to dynamically allocated queue_t on success, NULL on invalid arguments/allocation failure (errno set), aborts on system initialization failure.
 */
static inline queue_t *queue_init(const size_t size) {

    if (size == 0) {
        errno = EINVAL;
        return NULL;
    }

    if (size > (size_t)SEM_VALUE_MAX) {
        errno = EINVAL;
        return NULL;
    }

    queue_t *q = (queue_t*)malloc(sizeof(queue_t));
    if (!q) {
        errno = ENOMEM;
        return NULL;
    }

    q->size = size;

    // 2. Allocate circular buffer storage
    q->ptr = (void **)malloc(size * sizeof(void *));
    if (q->ptr == NULL) {
        free(q);
        errno = ENOMEM;
        return NULL;
    }

    (void)memset(q->ptr, 0, size * sizeof(void *));

    q->head = 0;
    q->tail = 0;
    q->pending = 0;

    // 3. Initialize OS primitives with sequential cleanup unwinding
    int rc = pthread_mutex_init(&q->mutex, NULL);
    if (rc != 0) {
        free(q->ptr);
        q->ptr = NULL;
        free(q);
        FATAL("pthread_mutex_init failed with code %d", rc);
    }

    // Semaphore tracking number of available items (initially empty)
    rc = sem_init(&q->pop_semaphore, 0, 0);
    if (rc != 0) {
        (void)pthread_mutex_destroy(&q->mutex);
        free(q->ptr);
        q->ptr = NULL;
        free(q);
        FATAL("sem_init (pop_semaphore) failed with code %d", rc);
    }

    // Semaphore tracking free slots (initially full capacity)
    rc = sem_init(&q->push_semaphore, 0, (unsigned int)size);
    if (rc != 0) {
        (void)sem_destroy(&q->pop_semaphore);
        (void)pthread_mutex_destroy(&q->mutex);
        free(q->ptr);
        q->ptr = NULL;
        free(q);
        FATAL("sem_init (push_semaphore) failed with code %d", rc);
    }

    return q;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue (blocking).
 *
 * Waits until space is available if the queue is full.
 *
 * @param q   Pointer to queue structure.
 * @param ptr Pointer to the element to insert.
 *
 * @return 0 on success, -1 on failure (errno set), aborts on system corruption.
 *
 * @note This function can be interrupted by system signals, returning -1 with 
 *       errno set to EINTR.
 *
 * @code
 * // Recommended usage pattern handling signal interruptions:
 * while (queue_wait_push(my_queue, data) == -1) {
 *     if (errno == EINTR) {
 *         continue; // Interrupted by a signal; retry the push safely
 *     }
 *     // Handle other unrecoverable errors here
 *     break;
 * }
 * @endcode
 *
 * @threadsafe Yes
 */
static inline int queue_wait_push(queue_t *q, void *ptr) {
    // 1. Validate inputs immediately before attempting synchronization
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* 
     * 2. Wait until a free slot is available.
     * If sem_wait is interrupted by a signal (EINTR), it returns -1.
     * We pass this error back to the caller cleanly.
     */
    int rc = sem_wait(&q->push_semaphore);
    if (rc == -1) {
        return -1; 
    }

    // 3. Lock and protect shared state modifications
    rc = pthread_mutex_lock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    // 4. Insert element into the circular buffer safely
    q->ptr[q->tail] = ptr;
    q->tail = (q->tail + 1) % q->size;
    q->pending++;

    // 5. Unlock state
    rc = pthread_mutex_unlock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    // 6. Signal to waiting consumers that a new item is ready
    rc = sem_post(&q->pop_semaphore);
    if (rc == -1) {
        FATAL("sem_post (pop_semaphore) failed; errno: %d", errno);
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Pop an element from the queue (blocking).
 *
 * Waits until an element is available if the queue is empty.
 *
 * @param q Pointer to queue structure.
 *
 * @return Pointer to the retrieved element on success, NULL on failure (errno set), 
 *         aborts on system corruption.
 *
 * @note This function can be interrupted by system signals, returning NULL with 
 *       errno set to EINTR.
 *
 * @code
 * // Recommended usage pattern handling signal interruptions:
 * void *data = NULL;
 * while ((data = queue_wait_pop(my_queue)) == NULL) {
 *     if (errno == EINTR) {
 *         continue; // Interrupted by a signal; retry the pop safely
 *     }
 *     // Handle other unrecoverable errors here (e.g., EINVAL)
 *     break;
 * }
 * @endcode
 *
 * @threadsafe Yes
 */
static inline void *queue_wait_pop(queue_t *q) {
    // 1. Validate inputs immediately before attempting synchronization
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* 
     * 2. Wait until an item is available.
     * If sem_wait is interrupted by a signal (EINTR), it returns -1.
     * We pass this error back to the caller cleanly.
     */
    int rc = sem_wait(&q->pop_semaphore);
    if (rc == -1) {
        return NULL;
    }

    // 3. Lock and protect shared state modifications
    rc = pthread_mutex_lock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    // 4. Remove element from the circular buffer safely
    void *entry = q->ptr[q->head];
    q->ptr[q->head] = NULL; // Clear slot to avoid stale reference bugs
    q->head = (q->head + 1) % q->size;
    q->pending--;

    // 5. Unlock state
    rc = pthread_mutex_unlock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    // 6. Signal to waiting producers that a free slot has opened up
    rc = sem_post(&q->push_semaphore);
    if (rc == -1) {
        FATAL("sem_post (push_semaphore) failed; errno: %d", errno);
    }

    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue (non-blocking).
 *
 * Fails immediately if the queue is full.
 *
 * @param q   Pointer to queue structure.
 * @param ptr Pointer to the element to insert.
 *
 * @return 0 on success, -1 if the queue is full or on failure (errno set),
 *         aborts on system corruption.
 *
 * @note If the queue is full, this function returns -1 with errno set to EAGAIN.
 *       Unlike blocking variants, it will never return -1 with errno set to EINTR.
 *
 * @code
 * // Recommended usage pattern for non-blocking push:
 * int rc = queue_try_push(my_queue, data);
 * if (rc == -1) {
 *     if (errno == EAGAIN) {
 *         // Queue is currently full; handle backpressure or retry later
 *     } else {
 *         // Handle actual invalid argument errors (EINVAL)
 *     }
 * }
 * @endcode
 *
 * @threadsafe Yes
 */
static inline int queue_try_push(queue_t *q, void *ptr) {
    // 1. Validate inputs immediately before attempting synchronization
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* 
     * 2. Try to reserve a free slot without blocking.
     * If no slots are available, sem_trywait returns -1 and sets errno = EAGAIN natively.
     * We pass this back to the caller cleanly as a status indicator.
     */
    int rc = sem_trywait(&q->push_semaphore);
    if (rc == -1) {
        return -1; 
    }

    // 3. Lock and protect shared state modifications
    rc = pthread_mutex_lock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    // 4. Insert element into the circular buffer safely
    q->ptr[q->tail] = ptr;
    q->tail = (q->tail + 1) % q->size;
    q->pending++;

    // 5. Unlock state
    rc = pthread_mutex_unlock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    // 6. Signal to waiting consumers that a new item is ready
    rc = sem_post(&q->pop_semaphore);
    if (rc == -1) {
        FATAL("sem_post (pop_semaphore) failed; errno: %d", errno);
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Pop an element from the queue (non-blocking).
 *
 * Fails immediately if the queue is empty.
 *
 * @param q Pointer to queue structure.
 *
 * @return Pointer to the retrieved element on success, NULL if the queue is empty 
 *         or on failure (errno set), aborts on system corruption.
 *
 * @note If the queue is empty, this function returns NULL with errno set to EAGAIN.
 *       Unlike blocking variants, it will never return NULL with errno set to EINTR.
 *
 * @code
 * // Recommended usage pattern for non-blocking pop:
 * void *data = queue_try_pop(my_queue);
 * if (data == NULL) {
 *     if (errno == EAGAIN) {
 *         // Guaranteed by POSIX to the sem_trywait() to set errno to EAGAIN
 *         // Queue is currently empty; process other work or try again later
 *     } else {
 *         // Handle actual invalid argument errors (EINVAL)
 *     }
 * }
 * @endcode
 *
 * @threadsafe Yes
 */
static inline void *queue_try_pop(queue_t *q) {
    // 1. Validate inputs immediately before attempting synchronization
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* 
     * 2. Try to reserve an available item without blocking.
     * If no items are pending, sem_trywait returns -1 and sets errno = EAGAIN natively.
     * We pass this back to the caller cleanly as a status indicator.
     */
    int rc = sem_trywait(&q->pop_semaphore);
    if (rc == -1) {
        return NULL; 
    }

    // 3. Lock and protect shared state modifications
    rc = pthread_mutex_lock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    // 4. Remove element from the circular buffer safely
    void *entry = q->ptr[q->head];
    q->ptr[q->head] = NULL; // Clear slot to avoid stale reference bugs
    q->head = (q->head + 1) % q->size;
    q->pending--;

    // 5. Unlock state
    rc = pthread_mutex_unlock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    // 6. Signal to waiting producers that a free slot has opened up
    rc = sem_post(&q->push_semaphore);
    if (rc == -1) {
        FATAL("sem_post (push_semaphore) failed; errno: %d", errno);
    }

    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Destroy the queue and release all associated system resources.
 *
 * This function completely unrolls the queue allocation and destroys all underlying
 * POSIX thread and semaphore primitives.
 *
 * @param q Pointer to the queue structure.
 *
 * @return 0 on success, -1 on invalid argument (errno set), aborts on system corruption.
 *
 * @warning The caller MUST ensure that no other threads are actively calling push, pop,
 *          or pending operations on this queue during destruction. Destroying a queue
 *          with active waiters causes Undefined Behavior.
 *
 * @code
 * // Recommended clean teardown pattern:
 * if (queue_destroy(my_queue) == -1) {
 *     // Handle instances where an invalid pointer was provided
 * }
 * @endcode
 */
static inline int queue_destroy(queue_t *q) {
    // 1. Validate inputs immediately before tearing down resources
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* 
     * 2. Destroy synchronization primitives.
     * We destroy semaphores first to unblock the structure, followed by the mutex.
     * If these fail, the synchronization state of the application is corrupted.
     */
    if (sem_destroy(&q->pop_semaphore) != 0) {
        FATAL("sem_destroy (pop_semaphore) failed; errno: %d", errno);
    }

    if (sem_destroy(&q->push_semaphore) != 0) {
        FATAL("sem_destroy (push_semaphore) failed; errno: %d", errno);
    }

    int rc = pthread_mutex_destroy(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_destroy failed with code %d", rc);
    }

    // 3. Free internal circular buffer memory
    free(q->ptr);

    // 4. Wipe out structure states to completely prevent dangling pointer exploitation
    q->ptr = NULL;
    q->size = 0;
    q->head = 0;
    q->tail = 0;
    q->pending = 0;
    free(q);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Capture and return the count of pending elements in the queue.
 *
 * @param q Pointer to the queue structure.
 *
 * @return The number of elements currently in the queue on success, -1 on failure (errno set),
 *         aborts on system corruption or integer overflow.
 *
 * @code
 * // Recommended usage pattern for checking pending elements:
 * ssize_t count = queue_get_pending(my_queue);
 * if (count == -1) {
 *     // Handle invalid pointer errors (EINVAL)
 * } else {
 *     printf("Queue current depth: %ld\n", (long)count);
 * }
 * @endcode
 *
 * @threadsafe Yes
 */
static inline ssize_t queue_get_pending(queue_t *q) {
    // 1. Validate inputs immediately before attempting synchronization
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    // 2. Lock and protect shared state read operations
    int rc = pthread_mutex_lock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_lock failed with code %d", rc);
    }

    /*
     * 3. Validate value safety against signed boundaries.
     * This ensures the value can safely cast down to ssize_t without
     * clipping into a negative integer, which would mimic an error code.
     */
    if (q->pending > (size_t)SSIZE_MAX) {
        FATAL("queue pending count %zu exceeds SSIZE_MAX (%ld)", q->pending, (long)SSIZE_MAX);
    }
    ssize_t pending = (ssize_t)q->pending;

    // 4. Unlock state
    rc = pthread_mutex_unlock(&q->mutex);
    if (rc != 0) {
        FATAL("pthread_mutex_unlock failed with code %d", rc);
    }

    return pending;
}

#ifdef __cplusplus
}
#endif

// END LINUX

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

//START WINDOWS

#elif defined(_WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "utils.h"

#ifndef SEM_VALUE_MAX
#define SEM_VALUE_MAX INT_MAX
#endif

// Define SSIZE_MAX if not provided by MSVC
#ifndef SSIZE_MAX
#ifdef _WIN64
#define SSIZE_MAX _I64_MAX
#else
#define SSIZE_MAX INT_MAX
#endif
#endif

// Define ssize_t if compiling with MSVC
#if defined(_MSC_VER) && !defined(_SSIZE_T_DEFINED)
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Thread-safe bounded FIFO queue (Windows API Implementation).
 *
 * This queue is designed for producer-consumer scenarios with multiple threads.
 * It uses:
 *  - a CRITICAL_SECTION to protect internal state
 *  - two Win32 Semaphores:
 *      - push_semaphore: tracks available space (free slots)
 *      - pop_semaphore:  tracks available items (queued elements)
 *
 * The queue stores generic pointers (void*). Ownership of the pointed-to memory
 * is NOT managed by the queue (caller is responsible).
 */
typedef struct queue_t {
    size_t size;            /**< Maximum number of elements the queue can hold */
    void **ptr;             /**< Circular buffer storing elements (void*) */

    size_t head;            /**< Index of next element to pop */
    size_t tail;            /**< Index of next slot to push */
    size_t pending;         /**< Current number of elements in the queue */

    CRITICAL_SECTION cs;    /**< Protects access to head/tail/pending */

    HANDLE push_semaphore;  /**< Semaphore tracking available space (initially size) */
    HANDLE pop_semaphore;   /**< Semaphore tracking available items (initially 0) */

} queue_t;


//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Initialize a queue with a maximum capacity.
 *
 * @param size Maximum number of elements the queue can hold.
 *
 * @return Pointer to dynamically allocated queue_t on success, NULL on invalid arguments/allocation failure (errno set), aborts on system initialization failure.
 */
static inline queue_t *queue_init(const size_t size) {

    if (size == 0 || size > (size_t)LONG_MAX) {
        errno = EINVAL;
        return NULL;
    }

    queue_t *q = (queue_t*)malloc(sizeof(queue_t));
    if (!q) {
        errno = ENOMEM;
        return NULL;
    }

    q->size = size;

    // Allocate circular buffer storage
    q->ptr = (void **)malloc(size * sizeof(void *));
    if (q->ptr == NULL) {
        free(q);
        errno = ENOMEM;
        return NULL;
    }

    (void)memset(q->ptr, 0, size * sizeof(void *));

    q->head = 0;
    q->tail = 0;
    q->pending = 0;

    // Initialize Critical Section
    InitializeCriticalSection(&q->cs);

    // Semaphore tracking available items (initially 0)
    q->pop_semaphore = CreateSemaphore(NULL, 0, (LONG)size, NULL);
    if (q->pop_semaphore == NULL) {
        DeleteCriticalSection(&q->cs);
        free(q->ptr);
        free(q);
        FATAL("CreateSemaphore (pop_semaphore) failed with code %lu", GetLastError());
    }

    // Semaphore tracking free slots (initially full capacity)
    q->push_semaphore = CreateSemaphore(NULL, (LONG)size, (LONG)size, NULL);
    if (q->push_semaphore == NULL) {
        CloseHandle(q->pop_semaphore);
        DeleteCriticalSection(&q->cs);
        free(q->ptr);
        free(q);
        FATAL("CreateSemaphore (push_semaphore) failed with code %lu", GetLastError());
    }

    return q;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue (blocking).
 *
 * Waits until space is available if the queue is full.
 *
 * @param q   Pointer to queue structure.
 * @param ptr Pointer to the element to insert.
 *
 * @return 0 on success, -1 on failure (errno set), aborts on system corruption.
 *
 * @threadsafe Yes
 */
static inline int queue_wait_push(queue_t *q, void *ptr) {
    if (q == NULL || q->ptr == NULL || ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Wait until a free slot is available
    DWORD res = WaitForSingleObject(q->push_semaphore, INFINITE);
    if (res != WAIT_OBJECT_0) {
        errno = EINVAL;
        return -1;
    }

    // Lock and protect shared state modifications
    EnterCriticalSection(&q->cs);

    // Insert element into the circular buffer safely
    q->ptr[q->tail] = ptr;
    q->tail = (q->tail + 1) % q->size;
    q->pending++;

    // Unlock state
    LeaveCriticalSection(&q->cs);

    // Signal to waiting consumers that a new item is ready
    if (!ReleaseSemaphore(q->pop_semaphore, 1, NULL)) {
        FATAL("ReleaseSemaphore (pop_semaphore) failed with code %lu", GetLastError());
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Pop an element from the queue (blocking).
 *
 * Waits until an element is available if the queue is empty.
 *
 * @param q Pointer to queue structure.
 *
 * @return Pointer to the retrieved element on success, NULL on failure (errno set), 
 *         aborts on system corruption.
 *
 * @threadsafe Yes
 */
static inline void *queue_wait_pop(queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // Wait until an item is available
    DWORD res = WaitForSingleObject(q->pop_semaphore, INFINITE);
    if (res != WAIT_OBJECT_0) {
        errno = EINVAL;
        return NULL;
    }

    // Lock and protect shared state modifications
    EnterCriticalSection(&q->cs);

    // Remove element from the circular buffer safely
    void *entry = q->ptr[q->head];
    q->ptr[q->head] = NULL; // Clear slot to avoid stale reference bugs
    q->head = (q->head + 1) % q->size;
    q->pending--;

    // Unlock state
    LeaveCriticalSection(&q->cs);

    // Signal to waiting producers that a free slot has opened up
    if (!ReleaseSemaphore(q->push_semaphore, 1, NULL)) {
        FATAL("ReleaseSemaphore (push_semaphore) failed with code %lu", GetLastError());
    }

    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Push an element into the queue (non-blocking).
 *
 * Fails immediately if the queue is full.
 *
 * @param q   Pointer to queue structure.
 * @param ptr Pointer to the element to insert.
 *
 * @return 0 on success, -1 if the queue is full or on failure (errno set),
 *         aborts on system corruption.
 *
 * @threadsafe Yes
 */
static inline int queue_try_push(queue_t *q, void *ptr) {
    if (q == NULL || q->ptr == NULL || ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Try to reserve a free slot immediately without blocking
    DWORD res = WaitForSingleObject(q->push_semaphore, 0);
    if (res == WAIT_TIMEOUT) {
        errno = EAGAIN;
        return -1;
    } else if (res != WAIT_OBJECT_0) {
        errno = EINVAL;
        return -1;
    }

    // Lock and protect shared state modifications
    EnterCriticalSection(&q->cs);

    // Insert element into the circular buffer safely
    q->ptr[q->tail] = ptr;
    q->tail = (q->tail + 1) % q->size;
    q->pending++;

    // Unlock state
    LeaveCriticalSection(&q->cs);

    // Signal to waiting consumers that a new item is ready
    if (!ReleaseSemaphore(q->pop_semaphore, 1, NULL)) {
        FATAL("ReleaseSemaphore (pop_semaphore) failed with code %lu", GetLastError());
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Pop an element from the queue (non-blocking).
 *
 * Fails immediately if the queue is empty.
 *
 * @param q Pointer to queue structure.
 *
 * @return Pointer to the retrieved element on success, NULL if the queue is empty 
 *         or on failure (errno set), aborts on system corruption.
 *
 * @threadsafe Yes
 */
static inline void *queue_try_pop(queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // Try to reserve an available item immediately without blocking
    DWORD res = WaitForSingleObject(q->pop_semaphore, 0);
    if (res == WAIT_TIMEOUT) {
        errno = EAGAIN;
        return NULL;
    } else if (res != WAIT_OBJECT_0) {
        errno = EINVAL;
        return NULL;
    }

    // Lock and protect shared state modifications
    EnterCriticalSection(&q->cs);

    // Remove element from the circular buffer safely
    void *entry = q->ptr[q->head];
    q->ptr[q->head] = NULL; // Clear slot to avoid stale reference bugs
    q->head = (q->head + 1) % q->size;
    q->pending--;

    // Unlock state
    LeaveCriticalSection(&q->cs);

    // Signal to waiting producers that a free slot has opened up
    if (!ReleaseSemaphore(q->push_semaphore, 1, NULL)) {
        FATAL("ReleaseSemaphore (push_semaphore) failed with code %lu", GetLastError());
    }

    return entry;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Destroy the queue and release all associated system resources.
 *
 * @param q Pointer to the queue structure.
 *
 * @return 0 on success, -1 on invalid argument (errno set), aborts on system corruption.
 */
static inline int queue_destroy(queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Close Windows handles
    if (!CloseHandle(q->pop_semaphore)) {
        FATAL("CloseHandle (pop_semaphore) failed with code %lu", GetLastError());
    }

    if (!CloseHandle(q->push_semaphore)) {
        FATAL("CloseHandle (push_semaphore) failed with code %lu", GetLastError());
    }

    DeleteCriticalSection(&q->cs);

    // Free internal circular buffer memory
    free(q->ptr);

    // Reset structure states
    q->ptr = NULL;
    q->size = 0;
    q->head = 0;
    q->tail = 0;
    q->pending = 0;
    free(q);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
/**
 * @brief Capture and return the count of pending elements in the queue.
 *
 * @param q Pointer to the queue structure.
 *
 * @return The number of elements currently in the queue on success, -1 on failure (errno set),
 *         aborts on system corruption or integer overflow.
 *
 * @threadsafe Yes
 */
static inline ssize_t queue_get_pending(queue_t *q) {
    if (q == NULL || q->ptr == NULL) {
        errno = EINVAL;
        return -1;
    }

    EnterCriticalSection(&q->cs);

    if (q->pending > (size_t)SSIZE_MAX) {
        LeaveCriticalSection(&q->cs);
        FATAL("queue pending count %zu exceeds SSIZE_MAX", q->pending);
    }
    ssize_t pending = (ssize_t)q->pending;

    LeaveCriticalSection(&q->cs);

    return pending;
}

#ifdef __cplusplus
}
#endif

#else // END WINDOWS

    // Other OS

#endif //END

#endif // QUEUE_H

