#include <stdlib.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <assert.h>

#include "app_config.h"
#include "view_controls.h"
#include "log.h"
#include "session.h"

extern void *vpn_engine_start(vpn_config_t* config);
extern void vpn_engine_cleanup(session_t *session);

static void *engine_thread_routine(void *arg) {
    vpn_app_t *app = (vpn_app_t *)arg;
    assert(app);
    
    app->session = vpn_engine_start(&app->config);

    if (!app->session) {
        state_sync_set(&app->state, APP_STOPPED);
        return NULL;
    }

    state_sync_set(&app->state, APP_RUNNING);
    GtkButton *start_stop_btn = (GtkButton*)app->controls->start_stop_btn;
    gtk_button_set_label(start_stop_btn, "Stop VPN Engine");

    while (state_sync_check(&app->state, APP_RUNNING) /*&& 
            state_sync_check(&app->session->con_state, SESSION_CONNECTED)*/) {
        sleep(1);
    }

    if (app->session) {
        vpn_engine_cleanup(app->session);
        app->session = NULL;
    }

    state_sync_set(&app->state, APP_STOPPED);
    gtk_button_set_label(start_stop_btn, "Start VPN Engine");
    return NULL;
}

vpn_app_t *vpn_app_create(int argc, char **argv) {
    (void)argc; (void)argv;
    vpn_app_t *app = calloc(1, sizeof(vpn_app_t));

    state_sync_init(&app->state, APP_STOPPED);
    return app;
}

void vpn_app_start_engine(vpn_app_t *app) {
    if (!app) return;

    if (!state_sync_check(&app->state, APP_STOPPED)) {
        return;
    }

    state_sync_set(&app->state, APP_STARTING);
    pthread_create(&app->engine_thread, NULL, engine_thread_routine, app);
}

void vpn_app_stop_engine(vpn_app_t *app) {
    if (!app) return;

    // Check if aleady stopped
    if (state_sync_check(&app->state, APP_STOPPED)) {
        return;
    }

    // Check if starting
    if (state_sync_check(&app->state, APP_STARTING)) {
        state_sync_wait(&app->state, APP_RUNNING);
    }

    // Stop engine thread
    state_sync_set(&app->state, APP_STOPPING);

    // Join the engine thread
    pthread_join(app->engine_thread, NULL);

    LOG_DEBUG("VPN Engine shutdown complete");
    return;
}

void vpn_app_destroy(vpn_app_t *app) {
    if (app) {
        vpn_app_stop_engine(app);
        free(app);
    }
}