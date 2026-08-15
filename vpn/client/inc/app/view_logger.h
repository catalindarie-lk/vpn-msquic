// src/ui/view_logger.h
#ifndef VIEW_LOGGER_H
#define VIEW_LOGGER_H

#include <gtk/gtk.h>

typedef struct {
    GtkWidget *scrolled_window;
    GtkWidget *text_view;
    GtkTextBuffer *buffer;
    int pipe_fd[2];
} view_logger_t;

view_logger_t *view_logger_create(void);
GtkWidget *view_logger_get_widget(view_logger_t *logger);
void view_logger_destroy(view_logger_t *logger);

#endif // VIEW_LOGGER_H