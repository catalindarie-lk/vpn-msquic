// cond_sync.h

#ifndef COND_SYNC_H
#define COND_SYNC_H

#include <pthread.h>
#include <stdbool.h>

typedef struct {

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    bool signaled;

} cond_sync_t;

//==========================================================
// INIT / DESTROY
//==========================================================

static inline int
cond_sync_init(cond_sync_t* cs)
{
    if (pthread_mutex_init(&cs->mutex, NULL) != 0) {
        return -1;
    }

    if (pthread_cond_init(&cs->cond, NULL) != 0) {
        pthread_mutex_destroy(&cs->mutex);
        return -1;
    }

    cs->signaled = false;

    return 0;
}

static inline void
cond_sync_destroy(cond_sync_t* cs)
{
    pthread_cond_destroy(&cs->cond);
    pthread_mutex_destroy(&cs->mutex);
}

//==========================================================
// WAIT
//==========================================================

static inline void
cond_sync_wait(cond_sync_t* cs)
{
    pthread_mutex_lock(&cs->mutex);

    while (!cs->signaled) {
        pthread_cond_wait(&cs->cond, &cs->mutex);
    }

    cs->signaled = false;

    pthread_mutex_unlock(&cs->mutex);
}

//==========================================================
// SIGNAL
//==========================================================

static inline void
cond_sync_signal(cond_sync_t* cs)
{
    pthread_mutex_lock(&cs->mutex);

    cs->signaled = true;

    pthread_cond_signal(&cs->cond);

    pthread_mutex_unlock(&cs->mutex);
}

//==========================================================
// BROADCAST
//==========================================================

static inline void
cond_sync_broadcast(cond_sync_t* cs)
{
    pthread_mutex_lock(&cs->mutex);

    cs->signaled = true;

    pthread_cond_broadcast(&cs->cond);

    pthread_mutex_unlock(&cs->mutex);
}

#endif