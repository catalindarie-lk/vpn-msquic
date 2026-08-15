#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// #include <gtk/gtk.h>
// #include <gio/gio.h>

#include "vpn_app.h"
#include "gtk_app.h"



int main(int argc, char *argv[]) {
    // Force line buffering for clean stdout logging
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    // Initialize application context
    vpn_app_t *app = vpn_app_create(argc, argv);
    if (!app) {
        fprintf(stderr, "[VPN] Failed to create application context.\n");
        return EXIT_FAILURE;
    }

    // Launch GTK application loop
    gtk_app_create(app, argc, argv);

    // Cleanup resources after main loop exits
    vpn_app_destroy(app);

    return EXIT_SUCCESS;
}