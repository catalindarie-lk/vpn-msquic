// src/ui/view_controls.c
#include <assert.h>
#include "view_controls.h"
#include "vpn_app.h"
#include "app_config.h"

// Helper: Safely reads entry inputs into a vpn_config_t instance
static bool view_controls_read_config(view_controls_t *controls, vpn_config_t *out_config) {
    if (!controls || !out_config) return false;

    memset(out_config, 0, sizeof(vpn_config_t));

    // Copy text inputs into fixed-length char arrays
    const char *text;

    text = gtk_entry_get_text(GTK_ENTRY(controls->server_port_entry));
    if (text) {
        out_config->server_port = (uint16_t)strtoul(text, NULL, 10);
    }   

    text = gtk_entry_get_text(GTK_ENTRY(controls->server_addr_entry));
    if (text) {
        g_strlcpy(out_config->server_hostname, text, sizeof(out_config->server_hostname));
    }

    return true;
}


static void on_start_stop_clicked(GtkButton *start_stop_btn, gpointer user_data) {

    vpn_app_t *app = (vpn_app_t*)user_data;
    view_controls_t *controls = app->controls;

    if (state_sync_check(&app->state, APP_RUNNING)) {
        vpn_app_stop_engine(app);
    } else if (state_sync_check(&app->state, APP_STOPPED)) {
        view_controls_read_config(controls, &app->config);
        vpn_app_start_engine(app);
    } else {
        //
    }
    return;
}

view_controls_t *view_controls_create(vpn_app_t *app) {
    assert(app);

    view_controls_t *controls = calloc(1, sizeof(view_controls_t));
    // controls->app_ctx = app;
    app->controls = controls;

    // Main outer container is VERTICAL
    controls->container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(controls->container), 10);

    // --- ROW 1: Server Addr ---
    GtkWidget *row_addr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(row_addr, GTK_ALIGN_START); // Keep row from stretching across window

    GtkWidget *server_addr_label = gtk_label_new("Server\nHostname:");
    gtk_widget_set_size_request(server_addr_label, 90, -1);
    gtk_label_set_xalign(GTK_LABEL(server_addr_label), 0.0);

    controls->server_addr_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(controls->server_addr_entry), "10.10.10.11");
    gtk_entry_set_width_chars(GTK_ENTRY(controls->server_addr_entry), 20); // Limit width to ~20 characters

    gtk_box_pack_start(GTK_BOX(row_addr), server_addr_label, FALSE, FALSE, 0);
    // Note: Passed FALSE, FALSE to expand and fill
    gtk_box_pack_start(GTK_BOX(row_addr), controls->server_addr_entry, FALSE, FALSE, 0); 
    gtk_box_pack_start(GTK_BOX(controls->container), row_addr, FALSE, FALSE, 0);

    // --- ROW 2: Server Port ---
    GtkWidget *row_port = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(row_port, GTK_ALIGN_START);

    GtkWidget *server_port_label = gtk_label_new("Server\nPort:");
    gtk_widget_set_size_request(server_port_label, 90, -1);
    gtk_label_set_xalign(GTK_LABEL(server_port_label), 0.0);

    controls->server_port_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(controls->server_port_entry), "443");
    gtk_entry_set_width_chars(GTK_ENTRY(controls->server_port_entry), 20);

    gtk_box_pack_start(GTK_BOX(row_port), server_port_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row_port), controls->server_port_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(controls->container), row_port, FALSE, FALSE, 0);

    // --- ROW 4: Start/Stop Button ---
    controls->start_stop_btn = gtk_button_new_with_label("Start VPN Engine");
    gtk_widget_set_halign(controls->start_stop_btn, GTK_ALIGN_START); // Don't stretch button either

    g_signal_connect(controls->start_stop_btn, "clicked", G_CALLBACK(on_start_stop_clicked), app);

    gtk_box_pack_start(GTK_BOX(controls->container), controls->start_stop_btn, FALSE, FALSE, 10);

    return controls;
}

GtkWidget *view_controls_get_widget(view_controls_t *controls) {
    return controls->container;
}