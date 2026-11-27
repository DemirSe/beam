/*
 * Isolated state test for the beam-helper DNS switch.
 *
 * This file includes helper.c so it can call the static state functions. The
 * path, lock, TUN, and systemctl macros are replaced by test_dns_state.sh;
 * production builds keep the defaults in helper.c. The test needs no root,
 * does not write /etc, and opens no network or TUN device.
 *
 * Ownership comes only from BEAM_OWNED, which stores the exact bytes the
 * helper wrote. The cases below cover the normal cycle, host files whose
 * content equals a helper output, every crash point in the marker protocol,
 * edit conflicts, a manual restore-dns while the tunnel is up, a failed
 * delete that must keep the marker and fail again, and a failed marker delete
 * or restore rename next to a byte-identical host file.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* Injected by -DUNLINK=beam_test_unlink and -DRENAME=beam_test_rename in
 * test_dns_state.sh. */
int beam_test_unlink(const char *path);
int beam_test_rename(const char *from, const char *to);

/* Test doubles for the early reject paths. No syslog daemon or root is
 * needed: the calls are counted and the formatted text is inspected. */
void beam_test_syslog(int priority, const char *fmt, ...);
void beam_test_openlog(const char *ident, int option, int facility);
uid_t beam_test_geteuid(void);

static int syslog_calls;
static char syslog_last[512];
static int openlog_calls;
static char openlog_ident[64];
static int openlog_option;
static int openlog_facility;
static int syslog_before_openlog;
static int fake_euid;

void beam_test_syslog(int priority, const char *fmt, ...)
{
    va_list ap;

    (void)priority;
    if (openlog_calls == 0)
        syslog_before_openlog++;
    syslog_calls++;
    va_start(ap, fmt);
    vsnprintf(syslog_last, sizeof(syslog_last), fmt, ap);
    va_end(ap);
}

void beam_test_openlog(const char *ident, int option, int facility)
{
    openlog_calls++;
    snprintf(openlog_ident, sizeof(openlog_ident), "%s", ident ? ident : "");
    openlog_option = option;
    openlog_facility = facility;
}

uid_t beam_test_geteuid(void)
{
    return fake_euid ? (uid_t)1 : (uid_t)0;
}

#define main beam_helper_main
#include "../../clients/linux-tray/helper.c"
#undef main

static int unlink_fail;
static int marker_unlink_fail;
static int restore_rename_fail;

int beam_test_unlink(const char *path)
{
    if ((unlink_fail && strcmp(path, BEAM_DROPIN) == 0) ||
        (marker_unlink_fail && strcmp(path, BEAM_OWNED) == 0)) {
        errno = EACCES;
        return -1;
    }
    return unlink(path);
}

int beam_test_rename(const char *from, const char *to)
{
    if (restore_rename_fail && strcmp(from, BEAM_SAVED) == 0 &&
        strcmp(to, BEAM_DROPIN) == 0) {
        errno = EACCES;
        return -1;
    }
    return rename(from, to);
}

#define OTHER_DROPIN DNS_DIR "/50-other.conf"
#define RELOAD_FAIL DNS_DIR "/reload.fail"

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static const char BEAM_CLEAR[] = BEAM_DNS_CLEAR;
static const char BEAM_CTRLD[] = BEAM_DNS_CTRLD;
static const char USER_DNS[] = "[Resolve]\nDNS=192.0.2.53\n";
static const char OTHER_DNS[] = "[Resolve]\nDNS=192.0.2.99\n";
static const char CTRLD_DNS[] = "[Resolve]\nDNS=127.0.0.1:5300\n";

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");

    if (!f || fputs(text, f) == EOF || fclose(f) != 0) {
        perror(path);
        exit(2);
    }
}

static int file_is(const char *path, const char *text)
{
    char buf[1024];
    size_t n;
    FILE *f = fopen(path, "r");

    if (!f)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    if (ferror(f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    buf[n] = '\0';
    return strcmp(buf, text) == 0;
}

static int exists(const char *path)
{
    return access(path, F_OK) == 0;
}

/* Identity of a file object, so a test can tell a restored host file from a
 * helper file with the same bytes. */
static ino_t inode_of(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 ? st.st_ino : 0;
}

static void reset_state(void)
{
    unlink(CTRL_DROPIN);
    unlink(CTRL_SAVED);
    unlink(BEAM_DROPIN);
    unlink(BEAM_SAVED);
    unlink(BEAM_OWNED);
    unlink(BEAM_RELOAD_PENDING);
    unlink(OTHER_DROPIN);
    unlink(RELOAD_FAIL);
}

static void check_rejects(void)
{
    char *spoof[] = { "spoofed-tag", "up", NULL };
    char *up[] = { "beam-helper", "up", NULL };
    char *bad[] = { "beam-helper", "bad\nsecret", NULL };
    char *dns[] = { "beam-helper", "dns-off", NULL };
    struct passwd *pw = getpwuid(getuid());
    FILE *f;

    unlink(ALLOWED_USER);
    fake_euid = 1;
    syslog_calls = 0;
    openlog_calls = 0;
    syslog_before_openlog = 0;
    CHECK(beam_helper_main(2, spoof) == 1);
    CHECK(openlog_calls == 1);
    CHECK(strcmp(openlog_ident, "beam-helper") == 0);
    CHECK(openlog_option == LOG_PID);
    CHECK(openlog_facility == LOG_AUTHPRIV);
    CHECK(syslog_before_openlog == 0);
    CHECK(syslog_calls == 1);
    CHECK(strstr(syslog_last, "effective uid is not root") != NULL);
    CHECK(strstr(syslog_last, "uid=") != NULL);

    fake_euid = 0;
    syslog_calls = 0;
    CHECK(beam_helper_main(2, up) == 1);
    CHECK(syslog_calls == 1);
    CHECK(strstr(syslog_last, "user is not allowed") != NULL);
    CHECK(strstr(syslog_last, "uid=") != NULL);

    f = fopen(ALLOWED_USER, "w");
    CHECK(f != NULL);
    if (f) {
        if (pw)
            fprintf(f, "%s\n", pw->pw_name);
        fclose(f);
    }

    syslog_calls = 0;
    CHECK(beam_helper_main(1, up) == 1);
    CHECK(syslog_calls == 1);
    CHECK(strstr(syslog_last, "bad argument count") != NULL);

    syslog_calls = 0;
    CHECK(beam_helper_main(2, bad) == 1);
    CHECK(syslog_calls == 1);
    CHECK(strstr(syslog_last, "unknown command") != NULL);
    CHECK(strstr(syslog_last, "bad?secret") != NULL);
    CHECK(strchr(syslog_last, '\n') == NULL);

    syslog_calls = 0;
    CHECK(beam_helper_main(2, dns) == 1);
    CHECK(syslog_calls == 1);
    CHECK(strstr(syslog_last, "dns command from non-root") != NULL);
    unlink(ALLOWED_USER);
}

int main(void)
{
    ino_t host_ino;

    /* No ctrld: a host-owned 99-beam.conf survives a full on/off cycle. The
     * marker records the exact bytes the helper wrote. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(BEAM_OWNED, BEAM_CLEAR));
    CHECK(file_is(BEAM_SAVED, USER_DNS));
    CHECK(!exists(CTRL_DROPIN));
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* No ctrld and no prior beam file: other drop-ins stay untouched. */
    reset_state();
    write_file(OTHER_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(OTHER_DROPIN, USER_DNS));
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    CHECK(file_is(OTHER_DROPIN, USER_DNS));

    /* A host file whose content equals a helper output is still host data:
     * content alone never proves ownership. It is saved, not deleted, and
     * restored byte for byte. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CTRLD);
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_SAVED, BEAM_CTRLD));
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CTRLD));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* The same-content case for the no-ctrld helper output on the ctrld
     * path: the saved copy keeps the host bytes, not the helper's choice. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    write_file(BEAM_DROPIN, BEAM_CLEAR);
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_SAVED, BEAM_CLEAR));
    CHECK(file_is(BEAM_DROPIN, BEAM_CTRLD));
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(BEAM_OWNED));

    /* A marker-less file from a helper version before the marker is host
     * data. The boot reset leaves it in place and succeeds; it never guesses
     * ownership from the content. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CTRLD);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CTRLD));
    CHECK(!exists(BEAM_OWNED));

    /* Crash after writing the live file on a host with no host file: the
     * marker proves ownership, so the reset removes it. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CLEAR);
    write_file(BEAM_OWNED, BEAM_CLEAR);
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));

    /* Crash after the marker write and before the live write. Nothing live
     * was written, and the stale marker is cleared. */
    reset_state();
    write_file(BEAM_OWNED, BEAM_CLEAR);
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_OWNED));
    CHECK(!exists(BEAM_DROPIN));

    /* Crash after saving the host file and after the live write: the saved
     * host file comes back and the marker goes away. */
    reset_state();
    write_file(BEAM_SAVED, USER_DNS);
    write_file(BEAM_DROPIN, BEAM_CLEAR);
    write_file(BEAM_OWNED, BEAM_CLEAR);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* Bytes that differ from the marker are preserved, even when they equal
     * another helper output. A ctrld change and a failed rewrite can leave
     * such a file, and a host edit looks the same. Ownership is not guessed. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CTRLD);
    write_file(BEAM_OWNED, BEAM_CLEAR);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CTRLD));
    CHECK(!exists(BEAM_OWNED));

    /* A failed delete keeps the marker and fails again on the next attempt.
     * Removing the marker here would turn the live file into host data and
     * block every later restore. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CLEAR);
    write_file(BEAM_OWNED, BEAM_CLEAR);
    unlink_fail = 1;
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(BEAM_OWNED, BEAM_CLEAR));
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(BEAM_OWNED, BEAM_CLEAR));
    unlink_fail = 0;
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));

    /* A marker delete that fails while a byte-identical host file is saved:
     * the host file must not return to the live path until the marker is
     * gone. Otherwise the next restore matches the host bytes against the
     * stale marker and deletes host data. */
    reset_state();
    write_file(BEAM_DROPIN, BEAM_CLEAR);
    host_ino = inode_of(BEAM_DROPIN);
    CHECK(dns_on() == 0);
    CHECK(inode_of(BEAM_SAVED) == host_ino);
    marker_unlink_fail = 1;
    CHECK(dns_off() == 1);
    CHECK(inode_of(BEAM_SAVED) == host_ino);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(BEAM_OWNED, BEAM_CLEAR));
    marker_unlink_fail = 0;
    CHECK(dns_off() == 0);
    CHECK(exists(BEAM_DROPIN));
    CHECK(inode_of(BEAM_DROPIN) == host_ino);
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* A restore rename that fails keeps the host bytes in the saved file and
     * puts the marker back, so the next attempt finishes instead of leaving
     * two files that every later attempt reports as a conflict. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    host_ino = inode_of(BEAM_DROPIN);
    CHECK(dns_on() == 0);
    restore_rename_fail = 1;
    CHECK(dns_off() == 1);
    CHECK(inode_of(BEAM_SAVED) == host_ino);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(file_is(BEAM_OWNED, BEAM_CLEAR));
    restore_rename_fail = 0;
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(inode_of(BEAM_DROPIN) == host_ino);
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* ctrld path: unchanged save and restore contract. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    CHECK(!exists(CTRL_DROPIN));
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));
    CHECK(file_is(BEAM_DROPIN, BEAM_CTRLD));
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(CTRL_SAVED));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));

    /* ctrld removed while connected. dns-on already moved the drop-in aside,
     * so the package leaves no trace and this state is identical to a host
     * where ctrld is still installed. The helper cannot tell them apart: it
     * restores the saved file, never deletes the host's only copy, and the
     * journal line names the unverified resolver. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(CTRL_SAVED));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));

    /* The removal procedure moves the stale saved file out while the tunnel
     * is up. dns-off then restores only the host file, and the next dns-on
     * takes the no-ctrld path instead of resurrecting the ctrld drop-in. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    CHECK(rename(CTRL_SAVED, CTRL_SAVED ".moved") == 0);
    CHECK(dns_off() == 0);
    CHECK(!exists(CTRL_DROPIN));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_DROPIN, BEAM_CLEAR));
    CHECK(!exists(CTRL_DROPIN));
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_DROPIN));
    CHECK(unlink(CTRL_SAVED ".moved") == 0);

    /* A ctrld drop-in re-created while connected is kept with the saved copy,
     * and the helper still removes its own live DNS override: a ctrld
     * conflict must not leave DNS pointed at the dead tunnel. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    write_file(CTRL_DROPIN, USER_DNS);
    CHECK(dns_off() == 1);
    CHECK(file_is(CTRL_DROPIN, USER_DNS));
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 1);
    CHECK(file_is(CTRL_DROPIN, USER_DNS));
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));

    /* A live file edited while connected is never replaced by the saved
     * file: dns-off reports the conflict and keeps both files. The marker
     * described the bytes the helper wrote, so it is cleared; the saved and
     * live pair keeps protecting the edit. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    write_file(BEAM_DROPIN, OTHER_DNS);
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, OTHER_DNS));
    CHECK(file_is(BEAM_SAVED, USER_DNS));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, OTHER_DNS));
    CHECK(file_is(BEAM_SAVED, USER_DNS));

    /* A later dns-on in that state is refused too, instead of overwriting the
     * edited file. */
    CHECK(dns_on() == 1);
    CHECK(file_is(BEAM_DROPIN, OTHER_DNS));
    CHECK(file_is(BEAM_SAVED, USER_DNS));

    /* An edited live file with no saved host file is refused here as well;
     * dns-on must never overwrite an edit. */
    reset_state();
    CHECK(dns_on() == 0);
    write_file(BEAM_DROPIN, OTHER_DNS);
    CHECK(dns_on() == 1);
    CHECK(file_is(BEAM_DROPIN, OTHER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    /* An edited beam file with no saved host file is host data now; dns-off
     * leaves it and clears the marker. */
    reset_state();
    CHECK(dns_on() == 0);
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_OWNED));

    /* Reload failure rolls the host file back and clears the marker. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    write_file(RELOAD_FAIL, "");
    CHECK(dns_on() == 1);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));
    unlink(RELOAD_FAIL);

    /* Reload failure on the ctrld path restores ctrld. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    write_file(RELOAD_FAIL, "");
    CHECK(dns_on() == 1);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(CTRL_SAVED));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    unlink(RELOAD_FAIL);

    /* Reload failure with no prior file leaves no beam drop-in behind. */
    reset_state();
    write_file(RELOAD_FAIL, "");
    CHECK(dns_on() == 1);
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));
    unlink(RELOAD_FAIL);

    /* A dns-off reload failure leaves a reset trigger after restore, so a
     * later boot reset or manual restore-dns retries the failed reload. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    write_file(RELOAD_FAIL, "");
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));
    CHECK(file_is(BEAM_RELOAD_PENDING, "reload failed\n"));
    unlink(RELOAD_FAIL);
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_RELOAD_PENDING));
    CHECK(file_is(BEAM_DROPIN, USER_DNS));

    /* The trigger is also written when dns-off had nothing to restore. */
    reset_state();
    write_file(RELOAD_FAIL, "");
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_RELOAD_PENDING, "reload failed\n"));
    unlink(RELOAD_FAIL);
    CHECK(dns_off() == 0);
    CHECK(!exists(BEAM_RELOAD_PENDING));

    /* A ctrld conflict does not block the host-file restore. The live host
     * file comes back, the saved beam copy is consumed, and the ctrld
     * conflict is still reported. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    write_file(CTRL_DROPIN, OTHER_DNS);
    CHECK(dns_off() == 1);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));
    CHECK(file_is(CTRL_DROPIN, OTHER_DNS));

    /* A repeated dns-on keeps the first saved host file. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    CHECK(dns_on() == 0);
    CHECK(file_is(BEAM_SAVED, USER_DNS));
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));

    /* A manual restore-dns while connected restores the host file and leaves
     * no state behind, so the later ExecStopPost dns-off is a clean no-op. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_on() == 0);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));

    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));

    /* A manual restore-dns in the ctrld-conflict state still reports the
     * unresolved ctrld conflict, and every later dns-off reports it again
     * without losing either ctrld file. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(dns_on() == 0);
    write_file(CTRL_DROPIN, OTHER_DNS);
    CHECK(dns_off() == 1);
    CHECK(dns_off() == 1);
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));
    CHECK(file_is(CTRL_DROPIN, OTHER_DNS));

    /* Native beam-client ctrld-off path: moves ctrld aside without writing a
     * competing global 99-beam.conf, and dns-off cleanly restores ctrld. */
    reset_state();
    write_file(CTRL_DROPIN, CTRLD_DNS);
    CHECK(ctrld_off() == 0);
    CHECK(!exists(CTRL_DROPIN));
    CHECK(file_is(CTRL_SAVED, CTRLD_DNS));
    CHECK(!exists(BEAM_DROPIN));
    CHECK(!exists(BEAM_OWNED));
    CHECK(dns_off() == 0);
    CHECK(file_is(CTRL_DROPIN, CTRLD_DNS));
    CHECK(!exists(CTRL_SAVED));
    CHECK(!exists(BEAM_DROPIN));

    /* A clean host has nothing to restore and must exit 0. */
    reset_state();
    CHECK(dns_off() == 0);

    /* The host's own 99-beam.conf with no saved file: the boot reset leaves
     * it alone and succeeds. */
    reset_state();
    write_file(BEAM_DROPIN, USER_DNS);
    CHECK(dns_off() == 0);
    CHECK(file_is(BEAM_DROPIN, USER_DNS));
    CHECK(!exists(BEAM_SAVED));
    CHECK(!exists(BEAM_OWNED));

    check_rejects();

    reset_state();
    if (failures) {
        fprintf(stderr, "%d DNS state check(s) failed\n", failures);
        return 1;
    }
    printf("dns state: all checks passed\n");
    return 0;
}
