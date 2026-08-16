#include <unistd.h>
#include <gtk/gtk.h>
#include <gio/gio.h>

#include "gtk_app.h"
#include "vpn_app.h"
#include "window_main.h"

// Triggered when the main GTK window is destroyed (e.g., clicking the 'X' button)
static void on_main_window_destroy(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    GApplication *g_app = G_APPLICATION(user_data);

    if (g_app) {
        g_application_quit(g_app);
    }
}

// Called when app starts or when a user launches a 2nd instance
static void on_activate(GtkApplication *gtk_app, gpointer user_data) {
    vpn_app_t *app = (vpn_app_t *)user_data;
    if (!app) return;

    // Focus existing window if primary instance is already running
    if (app->main_window) {
        gtk_window_present(GTK_WINDOW(app->main_window));
        return;
    }

    // Create main window on primary instance startup
    app->main_window = window_main_create(app);

    // Bind main window to GtkApplication tracking
    gtk_application_add_window(gtk_app, GTK_WINDOW(app->main_window));

    // Connect window destruction directly to GApplication termination
    g_signal_connect(app->main_window, "destroy", G_CALLBACK(on_main_window_destroy), gtk_app);

    // Start background engine thread
    // vpn_app_start_engine(app);

    gtk_widget_show_all(app->main_window);
}

// Clean shutdown handler (triggered via g_application_quit, SIGINT, or SIGTERM)
static void on_shutdown(GApplication *g_app, gpointer user_data) {
    (void)g_app;
    vpn_app_t *app = (vpn_app_t *)user_data;

    if (app) {
        // Stop engine thread and join resources
        vpn_app_stop_engine(app);
        app->main_window = NULL;
    }
    // No exit(0) needed: g_application_run unblocks and main thread exits cleanly
}


// Spawns GtkApplication, runs the main event loop, and blocks until application exit
void gtk_app_create(vpn_app_t *app, int argc, char *argv[]) {
    
    if (daemon(0, 0) != 0) {
        g_printerr("Failed to daemonize process\n");
        return;
    }
    
    
    GtkApplication *gtk_app = gtk_application_new(
        "com.yourcompany.vpnapp",
        G_APPLICATION_DEFAULT_FLAGS
    );

    g_signal_connect(gtk_app, "activate", G_CALLBACK(on_activate), app);
    g_signal_connect(gtk_app, "shutdown", G_CALLBACK(on_shutdown), app);

    // Blocks until g_application_quit() is called or OS signals hit
    g_application_run(G_APPLICATION(gtk_app), argc, argv);

    // Clean up GTK application object
    g_object_unref(gtk_app);
}

