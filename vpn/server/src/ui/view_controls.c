// src/ui/view_controls.c
#include "view_controls.h"

static void on_start_stop_clicked(GtkButton *btn, gpointer user_data) {
    vpn_app_t *app = (vpn_app_t *)user_data;

    if (atomic_load(&app->is_running)) {
        vpn_app_stop_engine(app);
        gtk_button_set_label(btn, "Start VPN Engine");
    } else {
        vpn_app_start_engine(app);
        gtk_button_set_label(btn, "Stop VPN Engine");
    }
}

view_controls_t *view_controls_create(vpn_app_t *app) {
    view_controls_t *controls = calloc(1, sizeof(view_controls_t));
    controls->app_ctx = app;

    // Horizontal box container for parameters
    controls->container = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(controls->container), 10);

    // Port input
    GtkWidget *port_label = gtk_label_new("Port:");
    controls->port_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(controls->port_entry), "443");

    // Start/Stop Action Button
    controls->start_stop_btn = gtk_button_new_with_label("Stop VPN Engine");
    g_signal_connect(controls->start_stop_btn, "clicked", G_CALLBACK(on_start_stop_clicked), app);

    // Layout assembly
    gtk_box_pack_start(GTK_BOX(controls->container), port_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(controls->container), controls->port_entry, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(controls->container), controls->start_stop_btn, FALSE, FALSE, 0);

    return controls;
}

GtkWidget *view_controls_get_widget(view_controls_t *controls) {
    return controls->container;
}