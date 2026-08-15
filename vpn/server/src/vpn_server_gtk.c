#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gtk/gtk.h>
#include "vpn_app.h"

static vpn_app_t *g_app = NULL;
bool headless;

static void handle_signal(int sig) {
    (void)sig;
    if (g_app) {
        vpn_app_stop_engine(g_app);
    }
    // Only call gtk_main_quit if GTK was initialized
    if (!headless) {
        gtk_main_quit();
    }
}

// Helper to detach process into background when running with GUI
static void detach_to_background(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    // Parent exits immediately, returning prompt to terminal/Makefile
    if (pid > 0) {
        printf("[VPN] GUI display detected. Detaching process to background (PID: %d)...\n", pid);
        exit(EXIT_SUCCESS);
    }

    // --- Child process continues ---
    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    // Redirect standard descriptors so closing the terminal won't break pipes
    int dev_null = open("/dev/null", O_RDWR);
    if (dev_null != -1) {
        dup2(dev_null, STDIN_FILENO);
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
        if (dev_null > 2) {
            close(dev_null);
        }
    }
}


int main(int argc, char *argv[]) {

    // Check if running on a headless system or if --headless flag is passed
    headless = (getenv("DISPLAY") == NULL && getenv("WAYLAND_DISPLAY") == NULL);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--headless") == 0) {
            headless = true;
            break;
        }
    }

    if (!headless) {
        detach_to_background();
    }

    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    g_app = vpn_app_create(argc, argv);

    if (headless) {
        printf("[VPN] Headless environment detected. Running core engine in CLI mode...\n");
        vpn_app_start_engine(g_app);

        // Keep main thread alive in headless mode until SIGINT/SIGTERM
        while (atomic_load(&g_app->is_running)) {
            sleep(1);
        }
    } else {
        // Run full GTK application
        vpn_app_run(g_app);
    }

    vpn_app_destroy(g_app);
    return 0;
}