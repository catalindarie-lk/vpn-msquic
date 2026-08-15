#ifndef VPN_APP_H
#define VPN_APP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include "app_config.h"

#include "state_sync.h"
// #include "view_controls.h"

typedef struct session_t session_t;

typedef enum {
    APP_STOPPED = 1,
    APP_STARTING,
    APP_RUNNING,
    APP_STOPPING
} app_state_t;

typedef struct view_controls_t view_controls_t;

// Central Application Context
typedef struct vpn_app_t {
    vpn_config_t config;
    state_sync_t state;

    pthread_t engine_thread;
    void *main_window;
    view_controls_t *controls;

    session_t *session;

} vpn_app_t;

// Lifecycle Management
vpn_app_t *vpn_app_create(int argc, char **argv);
void vpn_app_run(vpn_app_t *app);
void vpn_app_start_engine(vpn_app_t *app);
void vpn_app_stop_engine(vpn_app_t *app);
void vpn_app_destroy(vpn_app_t *app);

#endif // VPN_APP_H