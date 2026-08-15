
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <errno.h>

#include "log.h"


static pthread_t h_engine_thread_routine;
static void *vpn_engine_ctx = NULL;

extern void *vpn_engine_start(void);
extern void vpn_engine_cleanup(void *vpn_engine_ctx);

static pthread_mutex_t vpn_engine_start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  vpn_engine_start_cond = PTHREAD_COND_INITIALIZER;
static bool vpn_engine_start_done = false;
static bool vpn_engine_start_success = false;
static atomic_bool vpn_engine_running = false;


void *engine_thread_routine(void *arg) {
    vpn_engine_ctx = vpn_engine_start();
    
    pthread_mutex_lock(&vpn_engine_start_lock);
    vpn_engine_start_done = true;
    vpn_engine_start_success = (vpn_engine_ctx != NULL);
    pthread_cond_signal(&vpn_engine_start_cond);
    pthread_mutex_unlock(&vpn_engine_start_lock);
    
    if (!vpn_engine_ctx) {
        return NULL;
    }

    atomic_store_explicit(&vpn_engine_running, true, memory_order_relaxed);
    
    while (atomic_load_explicit(&vpn_engine_running, memory_order_relaxed)) {
        sleep(1);
    }

    return NULL;
}


int main(int argc, char *argv[]) {

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // Spawn VPN backend thread
    if (pthread_create(&h_engine_thread_routine, NULL, engine_thread_routine, NULL) != 0) {
        LOG_ERROR("Failed to create thread: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Wait until worker thread signals that startup completed or failed
    pthread_mutex_lock(&vpn_engine_start_lock);
    while (!vpn_engine_start_done) {
        pthread_cond_wait(&vpn_engine_start_cond, &vpn_engine_start_lock);
    }
    bool success = vpn_engine_start_success;
    pthread_mutex_unlock(&vpn_engine_start_lock);

    // If startup failed, join worker immediately and terminate program
    if (!success) {
        LOG_ERROR("[VPN] Engine startup failed!\n");
        // atomic_store_explicit(&vpn_engine_running, false, memory_order_relaxed);
        pthread_join(h_engine_thread_routine, NULL);
        return EXIT_FAILURE;
    }

    // Wait for shutdown signal
    int sig;
    sigwait(&set, &sig);

    atomic_store_explicit(&vpn_engine_running, false, memory_order_relaxed);
    pthread_join(h_engine_thread_routine, NULL);
    vpn_engine_cleanup(vpn_engine_ctx);

    LOG_ERROR("[VPN] Shutdown complete.\n");
    return EXIT_SUCCESS;
}