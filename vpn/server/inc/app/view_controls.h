// src/ui/view_controls.h
#ifndef VIEW_CONTROLS_H
#define VIEW_CONTROLS_H

#include <gtk/gtk.h>
#include "vpn_app.h"

typedef struct {
    GtkWidget *container;
    GtkWidget *port_entry;
    GtkWidget *alpn_entry;
    GtkWidget *start_stop_btn;
    vpn_app_t *app_ctx;
} view_controls_t;

view_controls_t *view_controls_create(vpn_app_t *app);
GtkWidget *view_controls_get_widget(view_controls_t *controls);

#endif // VIEW_CONTROLS_H