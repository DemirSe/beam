/*
 * beam-helper: tiny fixed-command root helper.
 *
 * User commands: up, down.
 * systemd-only commands: dns-on, dns-off, restore-dns.
 *
 * No shell, no user paths, no arbitrary arguments. The process clears its
 * environment, redirects stdio, closes inherited descriptors, and resets
 * dumpability before executing absolute systemctl paths.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SERVICE "beam-client"
#define TUN_IFACE "sbtun0"
#define DNS_DIR "/etc/systemd/resolved.conf.d"
#define CTRL_DROPIN DNS_DIR "/10-controld.conf"
#define CTRL_SAVED DNS_DIR "/10-controld.conf.beam-off"
#define BEAM_DROPIN DNS_DIR "/99-beam.conf"
#define ALLOWED_USER "/etc/beam/allowed-user"
#define LOCK_PATH "/run/beam-helper.lock"
#define SYSTEMCTL "/usr/bin/systemctl"

static int run(char *const argv[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int allowed_user(void)
{
    FILE *f;
    char allowed[256];
    struct passwd *pw;
    size_t len;

    if (getuid() == 0)
        return 1;

    pw = getpwuid(getuid());
    if (!pw)
        return 0;

    f = fopen(ALLOWED_USER, "r");
    if (!f)
        return 0;
    if (!fgets(allowed, sizeof(allowed), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    len = strlen(allowed);
    while (len && (allowed[len - 1] == '\n' || allowed[len - 1] == '\r'))
        allowed[--len] = '\0';
    return strcmp(allowed, pw->pw_name) == 0;
}

static void close_extra_fds(void)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0)
        return;
#endif
    for (int fd = 3; fd < 1024; fd++)
        close(fd);
}

static void sanitize(void)
{
    int nullfd;

    clearenv();
    (void)setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    (void)setenv("HOME", "/", 1);
    (void)setenv("LC_ALL", "C", 1);
    if (chdir("/") != 0)
        _exit(127);
    umask(022);

    nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd >= 0) {
        (void)dup2(nullfd, STDIN_FILENO);
        (void)dup2(nullfd, STDOUT_FILENO);
        (void)dup2(nullfd, STDERR_FILENO);
        if (nullfd > STDERR_FILENO)
            close(nullfd);
    }

    close_extra_fds();
    (void)signal(SIGCHLD, SIG_DFL);
    (void)signal(SIGPIPE, SIG_DFL);
    (void)prctl(PR_SET_DUMPABLE, 0);
}

static int state_lock(void)
{
    int fd = open(LOCK_PATH, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int write_text(const char *path, const char *text, mode_t mode)
{
    char tmp[256];
    int fd;
    ssize_t n;
    size_t left = strlen(text);

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return -1;

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    while (left) {
        n = write(fd, text, left);
        if (n <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        text += n;
        left -= (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int restore_ctrld_dropin(void)
{
    if (access(CTRL_SAVED, F_OK) == 0) {
        if (rename(CTRL_SAVED, CTRL_DROPIN) != 0)
            return -1;
    }
    (void)unlink(BEAM_DROPIN);
    return access(CTRL_DROPIN, F_OK) == 0 ? 0 : -1;
}

static int switch_dns_on(void)
{
    if (access(CTRL_SAVED, F_OK) != 0 && access(CTRL_DROPIN, F_OK) == 0) {
        if (rename(CTRL_DROPIN, CTRL_SAVED) != 0)
            return -1;
    }
    if (access(CTRL_SAVED, F_OK) != 0)
        return -1;
    if (write_text(BEAM_DROPIN,
                   "[Resolve]\nDNS=1.1.1.1\nDomains=~.\n", 0644) != 0) {
        (void)restore_ctrld_dropin();
        return -1;
    }
    return 0;
}

static int restart_resolved(void)
{
    char *const argv[] = {
        SYSTEMCTL, "--no-pager", "--no-ask-password", "--quiet",
        "restart", "systemd-resolved", NULL
    };
    return run(argv);
}

static int wait_tun(int seconds)
{
    int i;
    for (i = 0; i < seconds * 10; i++) {
        if (if_nametoindex(TUN_IFACE) != 0)
            return 0;
        usleep(100000);
    }
    return -1;
}

static int dns_on(void)
{
    int lock = state_lock();
    int rc = -1;

    if (lock < 0)
        return 1;
    if (wait_tun(10) == 0 && switch_dns_on() == 0 &&
        restart_resolved() == 0 &&
        access(CTRL_DROPIN, F_OK) != 0 &&
        access(BEAM_DROPIN, F_OK) == 0) {
        rc = 0;
    } else {
        (void)restore_ctrld_dropin();
        (void)restart_resolved();
    }
    close(lock);
    return rc == 0 ? 0 : 1;
}

static int dns_off(void)
{
    int lock = state_lock();
    int rc;

    if (lock < 0)
        return 1;
    rc = restore_ctrld_dropin();
    if (restart_resolved() != 0)
        rc = -1;
    if (access(CTRL_DROPIN, F_OK) != 0 || access(BEAM_DROPIN, F_OK) == 0)
        rc = -1;
    close(lock);
    return rc == 0 ? 0 : 1;
}

static int do_up(void)
{
    char *const argv[] = {
        SYSTEMCTL, "--no-pager", "--no-ask-password", "--quiet",
        "start", SERVICE, NULL
    };
    return run(argv) == 0 ? 0 : 1;
}

static int do_down(void)
{
    char *const argv[] = {
        SYSTEMCTL, "--no-pager", "--no-ask-password", "--quiet",
        "stop", SERVICE, NULL
    };
    return run(argv) == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *command;

    if (geteuid() != 0)
        return 1;
    if (!allowed_user())
        return 1;
    if (argc != 2)
        return 1;

    command = argv[1];
    if (strcmp(command, "dns-on") == 0 ||
        strcmp(command, "dns-off") == 0 ||
        strcmp(command, "restore-dns") == 0) {
        if (getuid() != 0)
            return 1;
    } else if (strcmp(command, "up") != 0 && strcmp(command, "down") != 0) {
        return 1;
    }

    sanitize();

    if (strcmp(command, "up") == 0)
        return do_up();
    if (strcmp(command, "down") == 0)
        return do_down();
    if (strcmp(command, "dns-on") == 0)
        return dns_on();
    if (strcmp(command, "dns-off") == 0)
        return dns_off();
    if (strcmp(command, "restore-dns") == 0)
        return dns_off();
    return 1;
}
