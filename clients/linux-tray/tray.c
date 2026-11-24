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
#include <time.h>
#include <unistd.h>

#define HELPER "/usr/local/libexec/beam-helper"
#define TUN_IFACE_NATIVE "beamtun0"
#define TUN_IFACE_LEGACY "sbtun0"
#define STATUS_FILE "/run/beam-client/status"
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
static time_t g_cooldown_until;

/*
 * Last values pushed to GTK/AppIndicator. The poll runs every second, so
 * repeating an unchanged label or icon would wake the toolkit and the
 * compositor for no visible change. Every comparison uses the same truncated
 * copy that is cached, so two long strings that differ only past the truncation
 * point are treated as equal instead of redrawing the menu every second.
 */
static char g_last_status_label[96];
static char g_last_action_label[24];
static int g_last_action_sensitive = -1;
static char g_last_icon[64];
static char g_last_desc[64];

static void set_status_label(const char *label)
{
    char buf[sizeof(g_last_status_label)];

    snprintf(buf, sizeof(buf), "%s", label);
    if (strcmp(g_last_status_label, buf) == 0)
        return;
    memcpy(g_last_status_label, buf, sizeof(buf));
    gtk_menu_item_set_label(g_status_item, buf);
}

static void set_action_label(const char *label)
{
    char buf[sizeof(g_last_action_label)];

    snprintf(buf, sizeof(buf), "%s", label);
    if (strcmp(g_last_action_label, buf) == 0)
        return;
    memcpy(g_last_action_label, buf, sizeof(buf));
    gtk_menu_item_set_label(g_action_item, buf);
}

static void set_action_sensitive(int sensitive)
{
    if (sensitive == g_last_action_sensitive)
        return;
    g_last_action_sensitive = sensitive;
    gtk_widget_set_sensitive(g_action_item, sensitive);
}

static void set_indicator_icon(const char *icon, const char *desc)
{
    char icon_buf[sizeof(g_last_icon)];
    char desc_buf[sizeof(g_last_desc)];

    snprintf(icon_buf, sizeof(icon_buf), "%s", icon);
    snprintf(desc_buf, sizeof(desc_buf), "%s", desc);
    if (strcmp(g_last_icon, icon_buf) == 0 && strcmp(g_last_desc, desc_buf) == 0)
        return;
    memcpy(g_last_icon, icon_buf, sizeof(icon_buf));
    memcpy(g_last_desc, desc_buf, sizeof(desc_buf));
    app_indicator_set_icon_full(g_indicator, icon_buf, desc_buf);
}

static int native_tunnel_present(void)
{
    return if_nametoindex(TUN_IFACE_NATIVE) != 0;
}

static int tunnel_present(void)
{
    return native_tunnel_present() || if_nametoindex(TUN_IFACE_LEGACY) != 0;
}

static int read_client_status(char *state_out, size_t state_cap, long *rtt_out)
{
    FILE *fp;
    /* Wide enough for the longest status line (`drops=...`) without splitting it
     * into two unparsable halves. */
    char line[512];
    int found_state = 0;
    long long ts = -1;
    pid_t pid = 0;

    state_out[0] = '\0';
    *rtt_out = -1;

    fp = fopen(STATUS_FILE, "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (strncmp(line, "state=", 6) == 0) {
            size_t copy_len = strlen(line + 6);
            if (copy_len >= state_cap)
                copy_len = state_cap - 1;
            memcpy(state_out, line + 6, copy_len);
            state_out[copy_len] = '\0';
            found_state = 1;
        } else if (strncmp(line, "rtt_ms=", 7) == 0) {
            char *end = NULL;
            errno = 0;
            long val = strtol(line + 7, &end, 10);
            if (errno == 0 && end != line + 7 && *end == '\0' && val >= 0 && val <= 60000)
                *rtt_out = val;
        } else if (strncmp(line, "ts=", 3) == 0) {
            char *end = NULL;
            errno = 0;
            long long val = strtoll(line + 3, &end, 10);
            if (errno == 0 && end != line + 3 && *end == '\0' && val > 0)
                ts = val;
        } else if (strncmp(line, "pid=", 4) == 0) {
            char *end = NULL;
            errno = 0;
            long long val = strtoll(line + 4, &end, 10);
            if (errno == 0 && end != line + 4 && *end == '\0' && val > 0 &&
                (long long)(pid_t)val == val)
                pid = (pid_t)val;
        }
    }
    fclose(fp);
    if (!found_state)
        return 0;
    /* Reject stale status files from a crashed/SIGKILL'd daemon immediately. */
    if (pid > 0 && !(kill(pid, 0) == 0 || errno == EPERM))
        return 0;
    /* Ignore stale status files left behind by a crashed/hung daemon (> 90s). */
    if (ts > 0 && (long long)time(NULL) - ts > 90)
        return 0;
    return 1;
}

static void update_ui(void)
{
    int native_up = native_tunnel_present();
    int connected = native_up || if_nametoindex(TUN_IFACE_LEGACY) != 0;
    int cooling = time(NULL) < g_cooldown_until;
    char state[32];
    char label[96];
    long rtt_ms = -1;
    const char *icon = connected ? "network-vpn-symbolic" : "network-vpn-disconnected-symbolic";
    const char *desc = connected ? "Interface up" : "Disconnected";

    if (g_busy) {
        set_status_label("Beam: working...");
        set_action_sensitive(0);
        return;
    }

    if (g_helper_failed) {
        set_status_label("Beam: error");
    } else if (native_up && read_client_status(state, sizeof(state), &rtt_ms)) {
        if (strcmp(state, "connected") == 0) {
            if (rtt_ms >= 0)
                snprintf(label, sizeof(label), "Beam: connected (%ld ms)", rtt_ms);
            else
                snprintf(label, sizeof(label), "Beam: connected");
            icon = "network-vpn-symbolic";
            desc = "Connected";
        } else if (strcmp(state, "waiting_network") == 0) {
            snprintf(label, sizeof(label), "Beam: waiting for network...");
            icon = "network-vpn-acquiring-symbolic";
            desc = "Waiting for network";
        } else {
            snprintf(label, sizeof(label), "Beam: reconnecting...");
            icon = "network-vpn-acquiring-symbolic";
            desc = "Reconnecting";
        }
        set_status_label(label);
    } else {
        set_status_label(connected ? "Beam: interface up" : "Beam: interface down");
    }
    set_action_label(connected ? "Disconnect" : "Connect");
    set_action_sensitive(!cooling);
    set_indicator_icon(icon, desc);
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
    g_cooldown_until = time(NULL) + 3;
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

    if (g_busy || time(NULL) < g_cooldown_until)
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
