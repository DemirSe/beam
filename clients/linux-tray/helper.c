/*
 * beam-helper: tiny fixed-command root helper.
 *
 * User commands: up, down.
 * systemd-only commands: dns-on, dns-off, restore-dns.
 *
 * No shell, no user paths, no arbitrary arguments. The process clears its
 * environment, redirects stdio, closes inherited descriptors, and resets
 * dumpability before executing absolute systemctl paths.
 *
 * DNS switching edits only systemd-resolved drop-ins. It moves the ctrld
 * drop-in aside and saves a host-owned 99-beam.conf, with or without ctrld,
 * which dns-off restores. The path macros below are compile-time defaults;
 * the isolated state test overrides them.
 *
 * Ownership of the live 99-beam.conf comes only from the marker file, never
 * from its content: a host file can legitimately contain the same bytes. The
 * marker stores the exact bytes this helper wrote, so a crash can be told
 * apart from an edit. restore-dns restores every component it can, removes
 * only a live file whose bytes still equal the marker, and keeps the marker
 * when that removal fails, so a later attempt retries it. The marker goes
 * before a saved host file returns to the live path, so a failed marker
 * delete can never claim a byte-identical host file. A restored ctrld drop-in
 * cannot be checked against a live resolver; the helper reports that limit
 * and keeps the file. It is safe to run by hand while the tunnel is up.
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
#include <syslog.h>
#include <unistd.h>

#define SERVICE "beam-client"
#ifndef TUN_IFACE
#define TUN_IFACE "sbtun0"
#endif
#define TUN_IFACE_NATIVE "beamtun0"
#ifndef DNS_DIR
#define DNS_DIR "/etc/systemd/resolved.conf.d"
#endif
#define CTRL_DROPIN DNS_DIR "/10-controld.conf"
#define CTRL_SAVED DNS_DIR "/10-controld.conf.beam-off"
#define BEAM_DROPIN DNS_DIR "/99-beam.conf"
#define BEAM_SAVED DNS_DIR "/99-beam.conf.beam-prev"
/* Exact bytes of the live file written by this helper; the only ownership
 * proof. The suffix is not .conf, so systemd-resolved ignores it. */
#define BEAM_OWNED DNS_DIR "/99-beam.conf.beam-own"
/* A dns-off reload failure leaves this boot-reset trigger after the saved
 * files are gone. Its suffix is not .conf, so resolved ignores it. */
#define BEAM_RELOAD_PENDING DNS_DIR "/99-beam.conf.beam-reload"
#define BEAM_DNS_CTRLD "[Resolve]\nDNS=1.1.1.1\nDomains=~.\n"
/* Without ctrld, an empty DNS= clears the inherited list; repeats append. */
#define BEAM_DNS_CLEAR "[Resolve]\nDNS=\nDNS=1.1.1.1\nDomains=~.\n"
#ifndef ALLOWED_USER
#define ALLOWED_USER "/etc/beam/allowed-user"
#endif
#ifndef LOCK_PATH
#define LOCK_PATH "/run/beam-helper.lock"
#endif
#ifndef SYSTEMCTL
#define SYSTEMCTL "/usr/bin/systemctl"
#endif
/* The isolated state test replaces this to inject an unlink failure. */
#ifndef UNLINK
#define UNLINK unlink
#endif
/* The isolated state test replaces this to inject a rename failure. */
#ifndef RENAME
#define RENAME rename
#endif

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

/* Reject paths run before sanitize(), so syslog is safe here. Show only a
 * bounded, printable form of the command: never file content or a secret. */
static void log_reject(const char *reason, const char *command)
{
    struct passwd *pw = getpwuid(getuid());
    char shown[32];
    size_t i, n = 0;

    for (i = 0; command && command[i] && n + 1 < sizeof(shown); i++) {
        unsigned char c = (unsigned char)command[i];
        shown[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    shown[n] = '\0';
    syslog(LOG_WARNING, "rejected %s: uid=%u user=%s command=%s", reason,
           (unsigned)getuid(), (pw && pw->pw_name) ? pw->pw_name : "unknown",
           shown);
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

static void log_errno(const char *what, const char *path)
{
    syslog(LOG_ERR, "%s %s: %s", what, path, strerror(errno));
}

static int state_lock(void)
{
    int fd = open(LOCK_PATH, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_errno("could not open", LOCK_PATH);
        return -1;
    }
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

/* Read at most size bytes. A larger file fails with EFBIG so that a content
 * comparison never matches a truncated prefix. */
static int read_small(const char *path, char *buf, size_t size, size_t *len)
{
    int fd;
    ssize_t n;
    size_t total = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    while (total < size) {
        n = read(fd, buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    if (total == size) {
        char extra;
        do {
            n = read(fd, &extra, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 0) {
            close(fd);
            if (n > 0)
                errno = EFBIG;
            return -1;
        }
    }
    close(fd);
    *len = total;
    return 0;
}

static int file_text_is(const char *path, const char *text)
{
    char buf[sizeof BEAM_DNS_CLEAR];
    size_t n;
    size_t len = strlen(text);

    if (read_small(path, buf, sizeof buf, &n) != 0)
        return 0;
    return n == len && memcmp(buf, text, len) == 0;
}

/* Content that this helper writes. Used only for a warning; never as proof of
 * ownership and never as the reason to delete a file. */
static int helper_output(const char *path)
{
    return file_text_is(path, BEAM_DNS_CTRLD) ||
           file_text_is(path, BEAM_DNS_CLEAR);
}

static int beam_state_present(void)
{
    return access(BEAM_OWNED, F_OK) == 0;
}

/* The marker and the live file hold the same bytes, so the live file is
 * unchanged since this helper wrote it. */
static int beam_file_unchanged(void)
{
    char own[sizeof BEAM_DNS_CLEAR];
    char live[sizeof BEAM_DNS_CLEAR];
    size_t own_len, live_len;

    if (read_small(BEAM_OWNED, own, sizeof own, &own_len) != 0)
        return 0;
    if (read_small(BEAM_DROPIN, live, sizeof live, &live_len) != 0)
        return 0;
    return own_len == live_len && memcmp(own, live, own_len) == 0;
}

/* Restore the saved ctrld drop-in and the saved host 99-beam.conf, then remove
 * a live 99-beam.conf only when its bytes still equal the ownership marker.
 *
 * Every part runs even when another part conflicts, so a re-created ctrld file
 * cannot stop the helper from removing its own live DNS override after the
 * tunnel is gone. A file whose bytes differ from the marker is never deleted,
 * even when its content matches some other helper output. */
static int restore_dns(void)
{
    int failed = 0;
    int keep_marker = 0;

    if (beam_state_present()) {
        if (access(BEAM_SAVED, F_OK) == 0 &&
            access(BEAM_DROPIN, F_OK) == 0 && !beam_file_unchanged()) {
            syslog(LOG_WARNING,
                   "kept %s and %s: the live drop-in was edited while the tunnel was up",
                   BEAM_SAVED, BEAM_DROPIN);
            failed = 1;
        } else if (access(BEAM_SAVED, F_OK) == 0) {
            char own[sizeof BEAM_DNS_CLEAR];
            size_t own_len = 0;
            int have_own = read_small(BEAM_OWNED, own, sizeof own - 1, &own_len) == 0;

            /* The marker goes first. Once the host bytes are live, a marker
             * that still matched them would prove ownership of host data, and
             * the next restore would delete it. A failed marker delete keeps
             * both files, so a later attempt retries this rename. */
            if (UNLINK(BEAM_OWNED) != 0 && errno != ENOENT) {
                log_errno("could not remove", BEAM_OWNED);
                keep_marker = 1;
                failed = 1;
            } else if (RENAME(BEAM_SAVED, BEAM_DROPIN) != 0) {
                log_errno("could not restore", BEAM_DROPIN);
                failed = 1;
                keep_marker = 1;
                /* The live file is still the marked one. Put the marker back,
                 * but only while it still describes those bytes, so a later
                 * attempt retries this rename instead of reporting a conflict
                 * on every run. */
                if (have_own) {
                    own[own_len] = '\0';
                    if (file_text_is(BEAM_DROPIN, own) &&
                        write_text(BEAM_OWNED, own, 0600) != 0)
                        log_errno("could not restore", BEAM_OWNED);
                }
            }
        } else if (access(BEAM_DROPIN, F_OK) == 0) {
            if (beam_file_unchanged()) {
                if (UNLINK(BEAM_DROPIN) != 0) {
                    log_errno("could not remove", BEAM_DROPIN);
                    /* The live file still holds the marked bytes, so the
                     * marker stays valid. Keep it and fail, so a later
                     * attempt retries instead of treating the file as host
                     * data and blocking every future restore. */
                    keep_marker = 1;
                    failed = 1;
                }
            } else {
                syslog(LOG_WARNING,
                       "left %s in place: its bytes differ from %s",
                       BEAM_DROPIN, BEAM_OWNED);
            }
        }
        if (!keep_marker && access(BEAM_OWNED, F_OK) == 0 &&
            UNLINK(BEAM_OWNED) != 0 && errno != ENOENT) {
            log_errno("could not remove", BEAM_OWNED);
            failed = 1;
        }
    } else if (access(BEAM_SAVED, F_OK) == 0 &&
               access(BEAM_DROPIN, F_OK) == 0) {
        /* Without the marker the live file is host data. Both files hold data
         * that this helper did not prove it wrote; keep both and report. */
        syslog(LOG_WARNING, "kept %s and %s: %s has no ownership marker",
               BEAM_SAVED, BEAM_DROPIN, BEAM_DROPIN);
        failed = 1;
    } else if (access(BEAM_SAVED, F_OK) == 0) {
        if (rename(BEAM_SAVED, BEAM_DROPIN) != 0) {
            log_errno("could not restore", BEAM_DROPIN);
            failed = 1;
        }
    } else if (helper_output(BEAM_DROPIN)) {
        syslog(LOG_WARNING, "left %s in place: helper-like DNS has no ownership marker; inspect it manually", BEAM_DROPIN);
    }

    if (access(CTRL_SAVED, F_OK) == 0) {
        if (access(CTRL_DROPIN, F_OK) == 0) {
            syslog(LOG_WARNING, "kept %s; %s exists again",
                   CTRL_SAVED, CTRL_DROPIN);
            failed = 1;
        } else if (rename(CTRL_SAVED, CTRL_DROPIN) != 0) {
            log_errno("could not restore", CTRL_DROPIN);
            failed = 1;
        } else {
            /* ctrld can be removed while the tunnel is up, and then no file
             * proves it: dns-on already moved its drop-in aside. The helper
             * cannot verify a resolver behind the restored file, so it keeps
             * the host's only copy and reports the unverified state. */
            syslog(LOG_WARNING,
                   "restored %s without verifying a resolver behind it; if ctrld was removed while connected, DNS stays pointed at a dead address until an operator moves the file out",
                   CTRL_DROPIN);
        }
    }

    if (access(CTRL_SAVED, F_OK) == 0 || access(BEAM_SAVED, F_OK) == 0 ||
        access(BEAM_OWNED, F_OK) == 0)
        failed = 1;
    return failed ? -1 : 0;
}

/* Save the host's own 99-beam.conf before writing ours. Only the ownership
 * marker proves that an existing file is a helper leftover; content alone is
 * never enough to delete or overwrite a host file. */
static int save_beam_dropin(void)
{
    if (access(BEAM_SAVED, F_OK) == 0) {
        if (access(BEAM_DROPIN, F_OK) == 0 && !beam_file_unchanged()) {
            syslog(LOG_WARNING,
                   "kept %s; %s was replaced or edited while the tunnel was up",
                   BEAM_SAVED, BEAM_DROPIN);
            return -1;
        }
        return 0;
    }
    if (access(BEAM_DROPIN, F_OK) != 0)
        return 0;
    if (beam_state_present()) {
        if (!beam_file_unchanged()) {
            syslog(LOG_WARNING,
                   "kept %s; it was edited after the helper wrote it",
                   BEAM_DROPIN);
            return -1;
        }
        return 0;               /* our own leftover from an unclean stop */
    }
    if (helper_output(BEAM_DROPIN))
        syslog(LOG_WARNING,
               "saving %s as %s although its content matches a helper output; no ownership marker",
               BEAM_DROPIN, BEAM_SAVED);
    if (rename(BEAM_DROPIN, BEAM_SAVED) != 0) {
        log_errno("could not save", BEAM_DROPIN);
        return -1;
    }
    return 0;
}

static int switch_dns_on(void)
{
    int ctrld = access(CTRL_SAVED, F_OK) == 0 ||
                access(CTRL_DROPIN, F_OK) == 0;
    const char *text = ctrld ? BEAM_DNS_CTRLD : BEAM_DNS_CLEAR;

    if (save_beam_dropin() != 0)
        return -1;
    if (ctrld && access(CTRL_SAVED, F_OK) != 0 &&
        rename(CTRL_DROPIN, CTRL_SAVED) != 0) {
        log_errno("could not move", CTRL_DROPIN);
        return -1;
    }
    /* Marker first: after a crash it is the only proof that the live file is
     * ours. A crash between the two writes leaves a marker with no live file,
     * which restore_dns clears. */
    if (write_text(BEAM_OWNED, text, 0600) != 0) {
        log_errno("could not write", BEAM_OWNED);
        (void)restore_dns();
        return -1;
    }
    if (write_text(BEAM_DROPIN, text, 0644) != 0) {
        log_errno("could not write", BEAM_DROPIN);
        (void)restore_dns();
        return -1;
    }
    return 0;
}

static int reload_resolved(void)
{
    /* Use --no-block so ExecStopPost never deadlocks waiting on a systemd
     * transaction while beam-client.service itself is stopping. */
    char *const argv[] = {
        SYSTEMCTL, "--no-pager", "--no-ask-password", "--quiet",
        "--no-block", "reload", "systemd-resolved", NULL
    };
    return run(argv);
}

/* The boot reset or a later restore-dns retries a failed resolver reload. */
static void record_reload_result(int failed)
{
    if (!failed) {
        (void)unlink(BEAM_RELOAD_PENDING);
    } else if (write_text(BEAM_RELOAD_PENDING, "reload failed\n", 0600) != 0) {
        log_errno("could not write", BEAM_RELOAD_PENDING);
    }
}

static int wait_tun(int seconds)
{
    int i;
    for (i = 0; i < seconds * 10; i++) {
        if (if_nametoindex(TUN_IFACE) != 0 ||
            if_nametoindex(TUN_IFACE_NATIVE) != 0)
            return 0;
        usleep(100000);
    }
    return -1;
}

static int dns_on(void)
{
    int lock = state_lock();
    int reload_failed = 0;
    int rollback_reload_failed = 0;
    int rc = -1;

    if (lock < 0)
        return 1;
    if (wait_tun(10) == 0 && switch_dns_on() == 0) {
        if (reload_resolved() != 0) {
            reload_failed = 1;
        } else if (access(CTRL_DROPIN, F_OK) != 0 &&
                   access(BEAM_DROPIN, F_OK) == 0 &&
                   beam_file_unchanged()) {
            rc = 0;
        }
    }
    if (rc != 0) {
        syslog(LOG_ERR, "dns-on did not complete; restoring the previous DNS state");
        (void)restore_dns();
        if (reload_resolved() != 0)
            rollback_reload_failed = 1;
    }
    if (reload_failed || rollback_reload_failed)
        record_reload_result(1);
    else if (rc == 0)
        record_reload_result(0);
    close(lock);
    return rc == 0 ? 0 : 1;
}

/* Idempotent: every state left by a crash, a manual restore-dns, or an edit
 * conflict either restores cleanly or keeps both files and reports. A clean
 * state always exits 0, so a manual restore-dns followed by ExecStopPost does
 * not report a false failure. */
static int dns_off(void)
{
    int lock = state_lock();
    int rc;

    if (lock < 0)
        return 1;
    rc = restore_dns();
    if (reload_resolved() != 0) {
        syslog(LOG_ERR, "could not reload systemd-resolved");
        rc = -1;
        record_reload_result(1);
    } else {
        record_reload_result(0);
    }
    if (access(CTRL_SAVED, F_OK) == 0 || access(BEAM_SAVED, F_OK) == 0 ||
        access(BEAM_OWNED, F_OK) == 0)
        rc = -1;
    close(lock);
    return rc == 0 ? 0 : 1;
}

/* Native beam-client configures per-link DNS on beamtun0 via resolvectl, so
 * it only needs ctrld's global drop-in moved aside (without writing a
 * competing global 99-beam.conf ~. scope). */
static int ctrld_off(void)
{
    int lock = state_lock();
    int reload_failed = 0;
    int reload_ok = 0;
    int rc = 0;

    if (lock < 0)
        return 1;
    if (access(CTRL_DROPIN, F_OK) == 0 && access(CTRL_SAVED, F_OK) != 0) {
        if (rename(CTRL_DROPIN, CTRL_SAVED) != 0) {
            log_errno("could not move", CTRL_DROPIN);
            rc = -1;
        } else if (reload_resolved() != 0) {
            reload_failed = 1;
            syslog(LOG_ERR, "could not reload systemd-resolved after moving ctrld drop-in");
            (void)restore_dns();
            (void)reload_resolved();
            rc = -1;
        } else {
            reload_ok = 1;
        }
    }
    if (reload_failed)
        record_reload_result(1);
    else if (reload_ok)
        record_reload_result(0);
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

    /* Set a fixed tag before any reject log; argv[0] is caller-controlled. */
    openlog("beam-helper", LOG_PID, LOG_AUTHPRIV);
    if (geteuid() != 0) {
        log_reject("effective uid is not root", argc > 1 ? argv[1] : "");
        return 1;
    }
    if (!allowed_user()) {
        log_reject("user is not allowed", argc > 1 ? argv[1] : "");
        return 1;
    }
    if (argc != 2) {
        log_reject("bad argument count", argc > 1 ? argv[1] : "");
        return 1;
    }

    command = argv[1];
    if (strcmp(command, "dns-on") == 0 ||
        strcmp(command, "dns-off") == 0 ||
        strcmp(command, "restore-dns") == 0 ||
        strcmp(command, "ctrld-off") == 0) {
        if (getuid() != 0) {
            log_reject("dns command from non-root", command);
            return 1;
        }
    } else if (strcmp(command, "up") != 0 && strcmp(command, "down") != 0) {
        log_reject("unknown command", command);
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
    if (strcmp(command, "ctrld-off") == 0)
        return ctrld_off();
    return 1;
}
