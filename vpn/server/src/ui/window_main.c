// src/ui/window_main.c
#include "window_main.h"
#include "view_logger.h"
#include "view_controls.h"

static void on_window_destroy(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    vpn_app_t *app = (vpn_app_t *)user_data;
    vpn_app_stop_engine(app);
    gtk_main_quit();
}

GtkWidget *window_main_create(vpn_app_t *app) {
    GtkSettings *settings = gtk_settings_get_default();
    g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "VPN Server Control Console");
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);

    g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), app);

    // Main Vertical Layout Container
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // 1. Top Controls Bar
    // view_controls_t *controls = view_controls_create(app);
    // gtk_box_pack_start(GTK_BOX(vbox), view_controls_get_widget(controls), FALSE, FALSE, 0);

    // 2. Bottom Log View
    view_logger_t *logger = view_logger_create();
    gtk_box_pack_start(GTK_BOX(vbox), view_logger_get_widget(logger), TRUE, TRUE, 0);
    

    gtk_widget_show_all(window);
    return window;
}