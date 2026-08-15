// src/ui/window_main.h
#ifndef WINDOW_MAIN_H
#define WINDOW_MAIN_H

#include <gtk/gtk.h>
#include "vpn_app.h"

GtkWidget *window_main_create(vpn_app_t *app);

#endif // WINDOW_MAIN_H