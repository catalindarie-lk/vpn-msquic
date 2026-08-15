#ifndef VPN_APP_H
#define VPN_APP_H

#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
// #include "session.h"

// Configuration parameters bound from CLI inputs or UI text fields
typedef struct {
    int port;
    char app_name[64];
    char alpn[32];
    char cert_path[256];
    char key_path[256];
    char password[128];
} vpn_config_t;

// Central Application Context
typedef struct {
    vpn_config_t config;
    atomic_bool is_running;
    pthread_t engine_thread;
    void *main_window;

    void *vpn_engine_ctx;
} vpn_app_t;

// Lifecycle Management
vpn_app_t *vpn_app_create(int argc, char **argv);
void vpn_app_run(vpn_app_t *app);
void vpn_app_start_engine(vpn_app_t *app);
void vpn_app_stop_engine(vpn_app_t *app);
void vpn_app_destroy(vpn_app_t *app);

#endif // VPN_APP_H