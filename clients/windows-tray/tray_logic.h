/*
 * Platform-independent beam-tray (Windows) IPC logic: the parser for the
 * beam-client named-pipe wire format, the tray state mapping, and the
 * `vless://` import request builder.
 *
 * Kept free of Win32 headers so the same code compiles into beam-tray.exe and
 * is unit-tested on Linux by tests/windows-tray/test_tray_logic.c.
 *
 * Wire contract (see crates/beam-client/src/win_ipc.rs):
 *
 *   requests:  STATUS | CONNECT | DISCONNECT | RESTART | IMPORT_LINK <vless://...>
 *   replies :  OK state=<s> ifname=<n|none> server=<host:port|none>
 *                 rtt_ms=<ms|none> reason=<tok> bypass_ok=<0|1>
 *                 dial_failures=<n> generation=<n> drops=<drops|none>
 *              OK <key>=<value> ...        (command replies: state= or server=)
 *              ERR code=<tok> msg=<single line text>
 *
 * Both sides are one bounded UTF-8 line; values never contain spaces, except
 * the trailing `ERR` message text.
 */

#ifndef BEAM_WINDOWS_TRAY_LOGIC_H
#define BEAM_WINDOWS_TRAY_LOGIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Matches win_ipc::MAX_REQUEST_BYTES; excludes the trailing '\n'. */
#define BEAM_IPC_MAX_REQUEST_BYTES 4095
/* Longest `vless://` link the importer accepts. */
#define BEAM_IPC_MAX_LINK_BYTES 2048

typedef enum {
    TRAY_STATE_DISCONNECTED     = 0,
    TRAY_STATE_CONNECTING       = 1,
    TRAY_STATE_CONNECTED        = 2,
    TRAY_STATE_DEGRADED         = 3,
    TRAY_STATE_RECONNECTING     = 4,
    TRAY_STATE_WAITING_NETWORK  = 5,
    TRAY_STATE_STOPPING         = 6,
    TRAY_STATE_ERROR            = 7,
    TRAY_STATE_UNAVAILABLE      = 8
} TrayState;

/* One parsed `STATUS` (or `ERR`) reply line. */
typedef struct {
    char state[32];
    char ifname[128];
    char server[128];
    bool has_rtt;
    unsigned long long rtt_ms;
    char reason[64];
    bool bypass_ok;
    unsigned long long dial_failures;
    unsigned long long generation;
    char drops[256];
    bool is_err;
    char err_code[64];
    char err_msg[256];
} BeamIpcStatus;

/* --- bounded string and number helpers --- */

static inline void beam_ipc_copy(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (!dst || cap == 0 || !src)
        return;
    n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static inline void beam_ipc_store(char *dst, size_t cap, const char *src, size_t len)
{
    size_t n;

    if (!dst || cap == 0)
        return;
    n = len < cap - 1 ? len : cap - 1;
    if (n > 0)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Strict decimal parse; returns false for an empty, non-digit, or overflowing value. */
static inline bool beam_ipc_parse_u64(const char *s, size_t len, unsigned long long *out)
{
    unsigned long long value = 0;
    size_t i;

    if (!s || !out || len == 0)
        return false;
    for (i = 0; i < len; ++i) {
        unsigned digit;
        if (s[i] < '0' || s[i] > '9')
            return false;
        digit = (unsigned)(s[i] - '0');
        if (value > (~0ULL - digit) / 10ULL)
            return false;
        value = value * 10ULL + digit;
    }
    *out = value;
    return true;
}

static inline bool beam_ipc_is_none(const char *value, size_t len)
{
    return len == 4 && memcmp(value, "none", 4) == 0;
}

/* --- reply parser --- */

/*
 * Stores one `key=value` field in `st`. Unknown keys are ignored so a newer
 * service can add fields without breaking an older tray.
 */
static inline void beam_ipc_set_field(BeamIpcStatus *st, const char *key, size_t klen,
                                      const char *value, size_t vlen)
{
    unsigned long long num = 0;
    bool none = beam_ipc_is_none(value, vlen);

    if (klen == 5 && memcmp(key, "state", 5) == 0) {
        if (!none)
            beam_ipc_store(st->state, sizeof(st->state), value, vlen);
    } else if (klen == 6 && memcmp(key, "ifname", 6) == 0) {
        if (!none)
            beam_ipc_store(st->ifname, sizeof(st->ifname), value, vlen);
    } else if (klen == 6 && memcmp(key, "server", 6) == 0) {
        if (!none)
            beam_ipc_store(st->server, sizeof(st->server), value, vlen);
    } else if (klen == 6 && memcmp(key, "rtt_ms", 6) == 0) {
        if (!none && beam_ipc_parse_u64(value, vlen, &num)) {
            st->has_rtt = true;
            st->rtt_ms = num;
        }
    } else if (klen == 6 && memcmp(key, "reason", 6) == 0) {
        if (!none)
            beam_ipc_store(st->reason, sizeof(st->reason), value, vlen);
    } else if (klen == 9 && memcmp(key, "bypass_ok", 9) == 0) {
        if (vlen == 1 && value[0] == '1')
            st->bypass_ok = true;
        else if (vlen == 1 && value[0] == '0')
            st->bypass_ok = false;
    } else if (klen == 13 && memcmp(key, "dial_failures", 13) == 0) {
        if (beam_ipc_parse_u64(value, vlen, &num))
            st->dial_failures = num;
    } else if (klen == 10 && memcmp(key, "generation", 10) == 0) {
        if (beam_ipc_parse_u64(value, vlen, &num))
            st->generation = num;
    } else if (klen == 5 && memcmp(key, "drops", 5) == 0) {
        if (!none)
            beam_ipc_store(st->drops, sizeof(st->drops), value, vlen);
    } else if (klen == 4 && memcmp(key, "code", 4) == 0) {
        beam_ipc_store(st->err_code, sizeof(st->err_code), value, vlen);
    } else if (klen == 3 && memcmp(key, "msg", 3) == 0) {
        beam_ipc_store(st->err_msg, sizeof(st->err_msg), value, vlen);
    }
}

/*
 * Parses the space-separated `key=value` tokens of one reply body. A bare token
 * without `=` is malformed. The `msg` text runs to the end of the line because
 * it is the only value that may contain spaces.
 */
static inline bool beam_ipc_scan_fields(const char *body, size_t len, BeamIpcStatus *st)
{
    size_t pos = 0;

    while (pos < len) {
        size_t start;
        size_t end;
        size_t eq;
        size_t vstart;
        size_t vlen;

        while (pos < len && body[pos] == ' ')
            pos++;
        if (pos >= len)
            break;

        start = pos;
        while (pos < len && body[pos] != ' ')
            pos++;
        end = pos;

        eq = start;
        while (eq < end && body[eq] != '=')
            eq++;
        if (eq == end)
            return false;

        vstart = eq + 1;
        vlen = end - vstart;
        if (eq - start == 3 && memcmp(body + start, "msg", 3) == 0) {
            vlen = len - vstart;
            pos = len;
        }
        beam_ipc_set_field(st, body + start, eq - start, body + vstart, vlen);
    }
    return true;
}

/* Rejects embedded line breaks and reports the length without trailing CR/LF. */
static inline bool beam_ipc_strip_line(const char *line, size_t len, size_t *out_len)
{
    size_t n = len;
    size_t i;

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        n--;
    for (i = 0; i < n; ++i) {
        if (line[i] == '\n' || line[i] == '\r')
            return false;
    }
    *out_len = n;
    return true;
}

/*
 * Parses one reply line into `st`. `OK` lines need a state or server field,
 * `ERR` lines need a code. String fields are always NUL-terminated, truncated
 * to their struct size, and never read past `len`.
 */
static inline bool beam_ipc_parse_line(const char *line, size_t len, BeamIpcStatus *out)
{
    size_t n = 0;
    const char *body;
    size_t blen;

    if (!line || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->bypass_ok = true; /* an absent key means "no known bypass problem" */

    if (!beam_ipc_strip_line(line, len, &n) || n < 2)
        return false;
    if (memcmp(line, "OK", 2) == 0 && (n == 2 || line[2] == ' ')) {
        body = line + 2;
        blen = n - 2;
    } else if (n >= 3 && memcmp(line, "ERR", 3) == 0 && (n == 3 || line[3] == ' ')) {
        out->is_err = true;
        body = line + 3;
        blen = n - 3;
    } else {
        return false;
    }
    if (!beam_ipc_scan_fields(body, blen, out))
        return false;
    if (out->is_err)
        return out->err_code[0] != '\0';
    return out->state[0] != '\0' || out->server[0] != '\0';
}

/*
 * Parses one `STATUS` reply: `OK state=... ...` or `ERR code=... msg=...`.
 * `"none"` clears the optional server, ifname, rtt, and drops fields.
 */
static inline bool beam_ipc_parse_status(const char *line, size_t len, BeamIpcStatus *out)
{
    if (!beam_ipc_parse_line(line, len, out))
        return false;
    return out->is_err || out->state[0] != '\0';
}

/*
 * Parses one command reply. On success, `*is_ok` reports which kind it was:
 * `true` writes the `state=` or `server=` value to `out_value`, `false` writes
 * the `msg=` text (or the code when the text is empty) to `out_err`. Both
 * outputs are emptied on failure.
 */
static inline bool beam_ipc_parse_command_reply(const char *line, size_t len, bool *is_ok,
                                               char *out_value, size_t value_cap,
                                               char *out_err, size_t err_cap)
{
    BeamIpcStatus st;

    if (out_value && value_cap > 0)
        out_value[0] = '\0';
    if (out_err && err_cap > 0)
        out_err[0] = '\0';
    if (!line || !is_ok)
        return false;
    *is_ok = false;
    if (!beam_ipc_parse_line(line, len, &st))
        return false;

    *is_ok = !st.is_err;
    if (st.is_err) {
        beam_ipc_copy(out_err, err_cap, st.err_msg[0] != '\0' ? st.err_msg : st.err_code);
        return true;
    }
    beam_ipc_copy(out_value, value_cap,
                  st.state[0] != '\0' ? st.state : st.server);
    return true;
}

/* --- state mapping --- */

/*
 * Maps a parsed status to the tray state. Mirrors the Linux beam-tray rules:
 * `reason` (not the lifetime `dial_failures` counter) decides the degraded
 * dial case, and a connected link without every bypass route is degraded.
 */
static inline TrayState beam_ipc_derive_tray_state(const BeamIpcStatus *st)
{
    if (!st)
        return TRAY_STATE_UNAVAILABLE;
    if (st->is_err)
        return TRAY_STATE_ERROR;
    if (strcmp(st->state, "connected") == 0)
        return st->bypass_ok ? TRAY_STATE_CONNECTED : TRAY_STATE_DEGRADED;
    if (strcmp(st->state, "reconnecting") == 0)
        return strcmp(st->reason, "dial_failures") == 0 ? TRAY_STATE_DEGRADED
                                                        : TRAY_STATE_RECONNECTING;
    if (strcmp(st->state, "waiting_network") == 0)
        return TRAY_STATE_WAITING_NETWORK;
    if (strcmp(st->state, "connecting") == 0)
        return TRAY_STATE_CONNECTING;
    if (strcmp(st->state, "stopping") == 0)
        return TRAY_STATE_STOPPING;
    if (strcmp(st->state, "disconnected") == 0)
        return TRAY_STATE_DISCONNECTED;
    /* "error" and any unknown token. */
    return TRAY_STATE_ERROR;
}

static inline bool beam_tray_can_connect(TrayState state)
{
    return state == TRAY_STATE_DISCONNECTED || state == TRAY_STATE_ERROR;
}

static inline bool beam_tray_can_disconnect(TrayState state)
{
    return state == TRAY_STATE_CONNECTING || state == TRAY_STATE_CONNECTED ||
           state == TRAY_STATE_DEGRADED || state == TRAY_STATE_RECONNECTING ||
           state == TRAY_STATE_WAITING_NETWORK;
}

/*
 * Writes the tooltip / menu-header text for `state`. `out_cap` 128 matches the
 * Win32 NOTIFYICONDATA `szTip` bound; the longest string is 45 characters.
 */
static inline void beam_ipc_format_status_text(const BeamIpcStatus *st, TrayState state,
                                               char *out, size_t out_cap)
{
    char line[64];

    if (!out || out_cap == 0)
        return;
    out[0] = '\0';

    switch (state) {
    case TRAY_STATE_CONNECTED:
        if (st && st->has_rtt) {
            /* At most 20 digits, so this never truncates the 64-byte buffer. */
            snprintf(line, sizeof(line), "beam: Connected (%llu ms)", st->rtt_ms);
            beam_ipc_copy(out, out_cap, line);
        } else {
            beam_ipc_copy(out, out_cap, "beam: Connected");
        }
        break;
    case TRAY_STATE_DEGRADED: {
        bool dial = st && strcmp(st->reason, "dial_failures") == 0;
        bool bypass = st && !st->bypass_ok;

        if (dial && bypass)
            beam_ipc_copy(out, out_cap, "beam: Degraded (dial failures, bypass missing)");
        else if (dial)
            beam_ipc_copy(out, out_cap, "beam: Degraded (dial failures)");
        else if (bypass)
            beam_ipc_copy(out, out_cap, "beam: Degraded (bypass missing)");
        else
            beam_ipc_copy(out, out_cap, "beam: Degraded");
        break;
    }
    case TRAY_STATE_CONNECTING:
        beam_ipc_copy(out, out_cap, "beam: Connecting...");
        break;
    case TRAY_STATE_RECONNECTING:
        beam_ipc_copy(out, out_cap, "beam: Reconnecting...");
        break;
    case TRAY_STATE_WAITING_NETWORK:
        beam_ipc_copy(out, out_cap, "beam: Waiting for network...");
        break;
    case TRAY_STATE_STOPPING:
        beam_ipc_copy(out, out_cap, "beam: Stopping...");
        break;
    case TRAY_STATE_DISCONNECTED:
        beam_ipc_copy(out, out_cap, "beam: Disconnected");
        break;
    case TRAY_STATE_UNAVAILABLE:
        beam_ipc_copy(out, out_cap, "beam: Service unavailable");
        break;
    case TRAY_STATE_ERROR:
    default:
        beam_ipc_copy(out, out_cap, "beam: Error");
        break;
    }
}

/* --- vless:// import request --- */

static inline bool beam_ipc_is_blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
 * Builds the one-line `IMPORT_LINK <link>\n` request from user input.
 *
 * Surrounding whitespace is trimmed, the link must be `vless://` followed by
 * 1..2040 bytes without whitespace or control characters, and the result
 * (prefix plus link) stays far below the 4095-byte request bound.
 */
static inline bool beam_ipc_prepare_import_link(const char *raw, char *out_cmd,
                                                size_t out_cap)
{
    size_t len;
    size_t start = 0;
    size_t end;
    size_t i;
    size_t link_len;

    if (out_cmd && out_cap > 0)
        out_cmd[0] = '\0';
    if (!raw || !out_cmd || out_cap == 0)
        return false;

    len = strlen(raw);
    while (start < len && beam_ipc_is_blank(raw[start]))
        start++;
    end = len;
    while (end > start && beam_ipc_is_blank(raw[end - 1]))
        end--;
    link_len = end - start;

    if (link_len < 9 || link_len > BEAM_IPC_MAX_LINK_BYTES)
        return false;
    if (memcmp(raw + start, "vless://", 8) != 0)
        return false;
    for (i = start; i < end; ++i) {
        unsigned char c = (unsigned char)raw[i];
        if (c < 0x21 || c == 0x7F)
            return false;
    }

    /* "IMPORT_LINK " (12) + link + '\n' + '\0'; 12 + 2048 < 4095 always holds. */
    if (link_len + 14 > out_cap)
        return false;
    memcpy(out_cmd, "IMPORT_LINK ", 12);
    memcpy(out_cmd + 12, raw + start, link_len);
    out_cmd[12 + link_len] = '\n';
    out_cmd[12 + link_len + 1] = '\0';
    return true;
}

#endif /* BEAM_WINDOWS_TRAY_LOGIC_H */
