#include "view_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static gboolean on_log_received(GIOChannel *source, GIOCondition condition, gpointer data) {
    (void)condition;
    view_logger_t *logger = (view_logger_t *)data;
    char buf[1024];
    gsize bytes_read = 0;

    if (g_io_channel_read_chars(source, buf, sizeof(buf) - 1, &bytes_read, NULL) == G_IO_STATUS_NORMAL && bytes_read > 0) {
        buf[bytes_read] = '\0';

        // 1. Sanitize input to guarantee valid UTF-8
        gchar *valid_utf8 = NULL;
        if (!g_utf8_validate(buf, bytes_read, NULL)) {
            valid_utf8 = g_utf8_make_valid(buf, bytes_read);
        }

        const char *text_to_insert = valid_utf8 ? valid_utf8 : buf;

        // 2. Append text to buffer
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(logger->buffer, &end);
        gtk_text_buffer_insert(logger->buffer, &end, text_to_insert, -1);

        if (valid_utf8) {
            g_free(valid_utf8);
        }

        // 3. Process pending GTK layout events so heights recalculate before scrolling
        while (gtk_events_pending()) {
            gtk_main_iteration();
        }

        // 4. Reliable auto-scroll to bottom iter after wrapping
        gtk_text_buffer_get_end_iter(logger->buffer, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(logger->text_view), &end, 0.0, FALSE, 0.0, 0.0);
    }

    return TRUE;
}

view_logger_t *view_logger_create(void) {
    view_logger_t *logger = calloc(1, sizeof(view_logger_t));
    if (!logger) return NULL;

    // 1. Redirect stdout and stderr into pipe
    if (pipe(logger->pipe_fd) == 0) {
        dup2(logger->pipe_fd[1], STDOUT_FILENO);
        dup2(logger->pipe_fd[1], STDERR_FILENO);
        close(logger->pipe_fd[1]);

        GIOChannel *channel = g_io_channel_unix_new(logger->pipe_fd[0]);
        g_io_channel_set_encoding(channel, NULL, NULL);
        g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);
        g_io_add_watch(channel, G_IO_IN | G_IO_HUP, on_log_received, logger);
    }

    // 2. Create ScrolledWindow container
    logger->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(logger->scrolled_window),
                                   GTK_POLICY_NEVER,     // No horizontal scrollbar
                                   GTK_POLICY_AUTOMATIC); // Vertical scrollbar as needed

    gtk_widget_set_hexpand(logger->scrolled_window, TRUE);
    gtk_widget_set_vexpand(logger->scrolled_window, TRUE);

    // 3. Create TextView
    logger->text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(logger->text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(logger->text_view), FALSE);

    // Enable horizontal line wrapping (wraps long packet lines/hex dumps cleanly)
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(logger->text_view), GTK_WRAP_WORD_CHAR);

    // Modern CSS Monospace styling
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *css = "textview {\n"
                      "    font-family: monospace;\n"
                      "}\n"
                      "textview text {\n"
                      "    font-family: monospace;\n"
                      "}\n";

    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    gtk_style_context_add_provider(gtk_widget_get_style_context(logger->text_view),
                                   GTK_STYLE_PROVIDER(provider),
                                   GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);

    logger->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(logger->text_view));
    gtk_container_add(GTK_CONTAINER(logger->scrolled_window), logger->text_view);

    return logger;
}

GtkWidget *view_logger_get_widget(view_logger_t *logger) {
    return logger->scrolled_window;
}

void view_logger_destroy(view_logger_t *logger) {
    if (logger) free(logger);
}