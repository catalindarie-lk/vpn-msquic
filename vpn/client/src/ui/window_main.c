// src/ui/window_main.c
#include "window_main.h"
// #include "view_logger.h"
#include "gtk/gtk.h"
#include "view_controls.h"

static void on_window_destroy(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    vpn_app_t *app = (vpn_app_t *)user_data;
    if (app) {
        vpn_app_stop_engine(app);
        app->main_window = NULL;
    }
}

void move_relative_to_center(GtkWindow *window, int offset_x, int offset_y) {
    // 1. Get default display and active monitor
    GdkDisplay *display = gdk_display_get_default();
    GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
    
    if (!monitor) {
        monitor = gdk_display_get_monitor(display, 0);
    }

    // 2. Get monitor usable area (excludes panels/taskbars)
    GdkRectangle workarea;
    gdk_monitor_get_workarea(monitor, &workarea);

    // 3. Get window dimensions
    int window_width, window_height;
    gtk_window_get_size(window, &window_width, &window_height);

    // 4. Calculate exact center position
    int center_x = workarea.x + (workarea.width - window_width) / 2;
    int center_y = workarea.y + (workarea.height - window_height) / 2;

    // 5. Apply offset relative to center
    int target_x = center_x + offset_x;
    int target_y = center_y + offset_y;

    // 6. Move window
    gtk_window_move(window, target_x, target_y);
}

GtkWidget *window_main_create(vpn_app_t *app) {
    GtkSettings *settings = gtk_settings_get_default();
    g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Quic VPN Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 150);

    // Center the window on screen upon creation
    // gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_NONE);
    gtk_widget_show_all(window);
    gtk_window_move(GTK_WINDOW(window), 100, 300);


    // Move 250px left of center (-350), keep Y aligned with center (0)
    // move_relative_to_center(GTK_WINDOW(window), -350, 0);

    g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), app);

    // Main Vertical Layout Container
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // 1. Top Controls Bar
    view_controls_t *controls = view_controls_create(app);
    gtk_box_pack_start(GTK_BOX(vbox), view_controls_get_widget(controls), FALSE, FALSE, 0);

    // 2. Bottom Log View
    // view_logger_t *logger = view_logger_create();
    // gtk_box_pack_start(GTK_BOX(vbox), view_logger_get_widget(logger), TRUE, TRUE, 0);

    return window;
}