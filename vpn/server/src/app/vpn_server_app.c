
#include "vpn_app.h"
#include "window_main.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern void *vpn_engine_start(void);
extern void vpn_engine_cleanup(void *vpn_engine_ctx);

static void *engine_thread_routine(void *arg) {
    vpn_app_t *app = (vpn_app_t *)arg;
    app->vpn_engine_ctx = vpn_engine_start();

    if (!app->vpn_engine_ctx) {
        return NULL;
    }

    while (atomic_load(&app->is_running)) {
        fflush(stdout);
        sleep(1);
    }
    return NULL;
}

vpn_app_t *vpn_app_create(int argc, char **argv) {
    (void)argc; (void)argv;
    vpn_app_t *app = calloc(1, sizeof(vpn_app_t));
    atomic_init(&app->is_running, false);
    return app;
}

void vpn_app_start_engine(vpn_app_t *app) {
    if (!atomic_load(&app->is_running)) {
        atomic_store(&app->is_running, true);
        pthread_create(&app->engine_thread, NULL, engine_thread_routine, app);
    }
}

void vpn_app_stop_engine(vpn_app_t *app) {
    if (atomic_exchange(&app->is_running, false)) {
        printf("[VPN App] Shutting down network engine...\n");
        if (app->vpn_engine_ctx) {
            vpn_engine_cleanup(app->vpn_engine_ctx);
            app->vpn_engine_ctx = NULL;
        }
        pthread_join(app->engine_thread, NULL);
    }
}

void vpn_app_run(vpn_app_t *app) {
    gtk_init(NULL, NULL);
    app->main_window = window_main_create(app);
    vpn_app_start_engine(app);
    gtk_main();
}

void vpn_app_destroy(vpn_app_t *app) {
    if (app) free(app);
}