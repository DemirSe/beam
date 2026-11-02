/*
 * beam-tray: minimal Linux tray for the beam client.
 *
 * The tray is deliberately small: it reports whether sbtun0 is present and
 * calls the fixed-command root helper to bring the tunnel up or down.
 * DNS switching lives in beam-helper, not in the GUI.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define HELPER "/usr/local/libexec/beam-helper"
#define TUN_IFACE "sbtun0"
#define CATEGORY_SYSTEM_SERVICES 2
#define INDICATOR_STATUS_ACTIVE 1

typedef void GtkWidget;
typedef void GtkMenu;
typedef void GtkMenuItem;
typedef void AppIndicator;
typedef void GtkWindow;
typedef int gboolean;
typedef int gint;
typedef unsigned int guint;
typedef void *gpointer;
typedef char gchar;
typedef void (*GCallback)(void);
typedef gboolean (*GSourceFunc)(gpointer data);
typedef void (*GChildWatchFunc)(pid_t pid, gint status, gpointer data);

extern void gtk_init(int *argc, char ***argv);
extern GtkWidget *gtk_menu_new(void);
extern GtkWidget *gtk_menu_item_new_with_label(const gchar *label);
extern GtkWidget *gtk_separator_menu_item_new(void);
extern void gtk_menu_shell_append(GtkWidget *menu, GtkWidget *item);
extern void gtk_widget_show_all(GtkWidget *widget);
extern void gtk_widget_set_sensitive(GtkWidget *widget, gboolean sensitive);
extern void gtk_menu_item_set_label(GtkWidget *item, const gchar *label);
extern void gtk_main(void);
extern void gtk_main_quit(void);
extern unsigned long g_signal_connect_data(gpointer instance, const gchar *signal,
                                           GCallback handler, gpointer data,
                                           gpointer destroy, int flags);
extern guint g_timeout_add_seconds(guint interval, GSourceFunc function,
                                   gpointer data);
extern guint g_child_watch_add(pid_t pid, GChildWatchFunc function,
                               gpointer data);
extern gboolean g_spawn_async(const gchar *working_directory, gchar **argv,
                              gchar **envp, int flags,
                              void (*child_setup)(gpointer), gpointer user_data,
                              pid_t *child_pid, void *error);
extern AppIndicator *app_indicator_new(const gchar *id, const gchar *icon,
                                       int category);
extern void app_indicator_set_status(AppIndicator *indicator, int status);
extern void app_indicator_set_icon_full(AppIndicator *indicator,
                                        const gchar *icon,
                                        const gchar *description);
extern void app_indicator_set_title(AppIndicator *indicator,
                                    const gchar *title);
extern void app_indicator_set_menu(AppIndicator *indicator, GtkWidget *menu);

static AppIndicator *g_indicator;
static GtkWidget *g_status_item;
static GtkWidget *g_action_item;
static int g_busy;
static int g_helper_failed;

static int tunnel_present(void)
{
    return if_nametoindex(TUN_IFACE) != 0;
}

static void update_ui(void)
{
    int connected = tunnel_present();

    if (g_busy) {
        gtk_menu_item_set_label(g_status_item, "Beam: working...");
        gtk_widget_set_sensitive(g_action_item, 0);
        return;
    }

    if (g_helper_failed)
        gtk_menu_item_set_label(g_status_item, "Beam: error");
    else
        gtk_menu_item_set_label(g_status_item,
                                connected ? "Beam: connected" : "Beam: disconnected");
    gtk_menu_item_set_label(g_action_item,
                            connected ? "Disconnect" : "Connect");
    gtk_widget_set_sensitive(g_action_item, 1);
    app_indicator_set_icon_full(g_indicator,
        connected ? "network-vpn-symbolic" : "network-vpn-disconnected-symbolic",
        connected ? "Connected" : "Disconnected");
}

static gboolean poll_state(gpointer data)
{
    (void)data;
    update_ui();
    return 1;
}

static void helper_done(pid_t pid, gint status, gpointer data)
{
    (void)pid;
    (void)data;
    g_busy = 0;
    g_helper_failed = !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    update_ui();
}

static void on_toggle(GtkWidget *item, gpointer data)
{
    pid_t pid = 0;
    const char *command;
    char *argv[3];
    char *envp[] = {
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL=C",
        "HOME=/",
        NULL
    };
    const int flags = 2 | 8 | 16; /* DO_NOT_REAP_CHILD | stdout/stderr null */

    (void)item;
    (void)data;

    if (g_busy)
        return;

    command = tunnel_present() ? "down" : "up";
    g_helper_failed = 0;
    g_busy = 1;
    update_ui();

    argv[0] = (char *)HELPER;
    argv[1] = (char *)command;
    argv[2] = NULL;
    if (!g_spawn_async(NULL, argv, envp, flags, NULL, NULL, &pid, NULL)) {
        g_busy = 0;
        g_helper_failed = 1;
        update_ui();
        return;
    }
    g_child_watch_add(pid, helper_done, NULL);
}

static void on_quit(GtkWidget *item, gpointer data)
{
    (void)item;
    (void)data;
    gtk_main_quit();
}

int main(int argc, char **argv)
{
    GtkWidget *menu;
    GtkWidget *quit_item;
    char lock_path[128];
    int lock_fd;

    snprintf(lock_path, sizeof(lock_path), "/run/user/%u/beam-tray.lock",
             (unsigned)getuid());
    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        return 1;
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        close(lock_fd);
        return 0;
    }

    gtk_init(&argc, &argv);

    menu = gtk_menu_new();
    g_status_item = gtk_menu_item_new_with_label("Beam: checking...");
    gtk_widget_set_sensitive(g_status_item, 0);
    gtk_menu_shell_append(menu, g_status_item);

    g_action_item = gtk_menu_item_new_with_label("Connect");
    g_signal_connect_data(g_action_item, "activate", (GCallback)on_toggle,
                          NULL, NULL, 0);
    gtk_menu_shell_append(menu, g_action_item);

    gtk_menu_shell_append(menu, gtk_separator_menu_item_new());

    quit_item = gtk_menu_item_new_with_label("Quit");
    g_signal_connect_data(quit_item, "activate", (GCallback)on_quit,
                          NULL, NULL, 0);
    gtk_menu_shell_append(menu, quit_item);
    gtk_widget_show_all(menu);

    g_indicator = app_indicator_new("beam-tray", "network-vpn-disconnected-symbolic",
                                    CATEGORY_SYSTEM_SERVICES);
    if (!g_indicator)
        return 1;
    app_indicator_set_status(g_indicator, INDICATOR_STATUS_ACTIVE);
    app_indicator_set_title(g_indicator, "Beam");
    app_indicator_set_menu(g_indicator, menu);

    update_ui();
    g_timeout_add_seconds(1, poll_state, NULL);
    gtk_main();
    close(lock_fd);

    return 0;
}
