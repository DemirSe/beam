/*
 * Platform-independent state machine and bounded config.json parser for
 * beam-tray (Windows). Kept free of Win32 headers so it can be unit-tested
 * on Linux with a host C compiler as well as compiled into beam-tray.exe.
 */

#ifndef BEAM_WINDOWS_TRAY_LOGIC_H
#define BEAM_WINDOWS_TRAY_LOGIC_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef enum {
    TRAY_STATE_DISCONNECTED = 0,
    TRAY_STATE_CONNECTING   = 1,
    TRAY_STATE_CONNECTED    = 2,
    TRAY_STATE_STOPPING     = 3,
    TRAY_STATE_ERROR        = 4
} TrayState;

static inline bool tray_state_is_active(TrayState state)
{
    return state == TRAY_STATE_CONNECTING || state == TRAY_STATE_CONNECTED;
}

static inline bool tray_state_can_start(TrayState state, bool process_alive)
{
    return !process_alive &&
           (state == TRAY_STATE_DISCONNECTED || state == TRAY_STATE_ERROR);
}

static inline bool tray_state_can_stop(TrayState state, bool process_alive)
{
    return process_alive && state != TRAY_STATE_STOPPING;
}

/*
 * Compute the next state after an interface change or connectivity check while
 * the core process is alive. A late TUN coming up after a startup timeout
 * recovers from ERROR back to CONNECTED.
 */
static inline TrayState tray_state_on_tun_status(TrayState current, bool tun_up,
                                                 bool process_alive)
{
    if (!process_alive || current == TRAY_STATE_STOPPING)
        return current;
    if ((current == TRAY_STATE_CONNECTING || current == TRAY_STATE_ERROR) && tun_up)
        return TRAY_STATE_CONNECTED;
    if (current == TRAY_STATE_CONNECTED && !tun_up)
        return TRAY_STATE_CONNECTING;
    return current;
}

/*
 * Compute the next state when the sing-box process exits.
 * Intentional stops always transition to DISCONNECTED; unexpected exits
 * transition to ERROR regardless of exit code.
 */
static inline TrayState tray_state_on_process_exit(TrayState current,
                                                   bool intentional_stop)
{
    if (intentional_stop || current == TRAY_STATE_STOPPING)
        return TRAY_STATE_DISCONNECTED;
    return TRAY_STATE_ERROR;
}

/* --- Minimal, bounded JSON scanner for inbounds[].interface_name --- */

typedef struct {
    const char *buf;
    size_t len;
    size_t pos;
    int depth;
} BeamJsonCursor;

#define BEAM_JSON_MAX_DEPTH 32

static inline void beam_json_skip_ws(BeamJsonCursor *c)
{
    while (c->pos < c->len) {
        char ch = c->buf[c->pos];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
            c->pos++;
        else
            break;
    }
}

/*
 * Parse a JSON string starting at '"'. If out != NULL and out_cap > 0, copies
 * the unescaped ASCII/UTF-8 bytes (truncated safely with NUL termination) and
 * sets *truncated if it did not fit. Returns false on malformed/unterminated
 * strings.
 */
static inline bool beam_json_parse_string(BeamJsonCursor *c, char *out,
                                          size_t out_cap, bool *truncated)
{
    size_t out_len = 0;

    if (truncated)
        *truncated = false;
    if (out && out_cap > 0)
        out[0] = '\0';

    beam_json_skip_ws(c);
    if (c->pos >= c->len || c->buf[c->pos] != '"')
        return false;
    c->pos++;

    while (c->pos < c->len) {
        char ch = c->buf[c->pos++];
        if (ch == '"') {
            if (out && out_cap > 0)
                out[out_len] = '\0';
            return true;
        }
        if (ch == '\\') {
            if (c->pos >= c->len)
                return false;
            char esc = c->buf[c->pos++];
            switch (esc) {
            case '"':  ch = '"'; break;
            case '\\': ch = '\\'; break;
            case '/':  ch = '/'; break;
            case 'b':  ch = '\b'; break;
            case 'f':  ch = '\f'; break;
            case 'n':  ch = '\n'; break;
            case 'r':  ch = '\r'; break;
            case 't':  ch = '\t'; break;
            case 'u':
                /* Skip 4 hex digits; interface names are plain text. */
                if (c->len - c->pos < 4)
                    return false;
                c->pos += 4;
                ch = '?';
                break;
            default:
                return false;
            }
        } else if ((unsigned char)ch < 0x20) {
            return false;
        }

        if (out && out_cap > 0) {
            if (out_len + 1 < out_cap)
                out[out_len++] = ch;
            else if (truncated)
                *truncated = true;
        }
    }

    return false;
}

static inline bool beam_json_skip_value(BeamJsonCursor *c);

static inline bool beam_json_skip_array(BeamJsonCursor *c)
{
    if (c->depth >= BEAM_JSON_MAX_DEPTH)
        return false;
    c->depth++;
    c->pos++; /* '[' */
    beam_json_skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == ']') {
        c->pos++;
        c->depth--;
        return true;
    }
    while (c->pos < c->len) {
        if (!beam_json_skip_value(c))
            return false;
        beam_json_skip_ws(c);
        if (c->pos >= c->len)
            return false;
        if (c->buf[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (c->buf[c->pos] == ']') {
            c->pos++;
            c->depth--;
            return true;
        }
        return false;
    }
    return false;
}

static inline bool beam_json_skip_object(BeamJsonCursor *c)
{
    if (c->depth >= BEAM_JSON_MAX_DEPTH)
        return false;
    c->depth++;
    c->pos++; /* '{' */
    beam_json_skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == '}') {
        c->pos++;
        c->depth--;
        return true;
    }
    while (c->pos < c->len) {
        if (!beam_json_parse_string(c, NULL, 0, NULL))
            return false;
        beam_json_skip_ws(c);
        if (c->pos >= c->len || c->buf[c->pos] != ':')
            return false;
        c->pos++;
        if (!beam_json_skip_value(c))
            return false;
        beam_json_skip_ws(c);
        if (c->pos >= c->len)
            return false;
        if (c->buf[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (c->buf[c->pos] == '}') {
            c->pos++;
            c->depth--;
            return true;
        }
        return false;
    }
    return false;
}

static inline bool beam_json_skip_value(BeamJsonCursor *c)
{
    beam_json_skip_ws(c);
    if (c->pos >= c->len)
        return false;

    char ch = c->buf[c->pos];
    if (ch == '"')
        return beam_json_parse_string(c, NULL, 0, NULL);
    if (ch == '{')
        return beam_json_skip_object(c);
    if (ch == '[')
        return beam_json_skip_array(c);
    if (ch == 't' && c->len - c->pos >= 4 && memcmp(c->buf + c->pos, "true", 4) == 0) {
        c->pos += 4;
        return true;
    }
    if (ch == 'f' && c->len - c->pos >= 5 && memcmp(c->buf + c->pos, "false", 5) == 0) {
        c->pos += 5;
        return true;
    }
    if (ch == 'n' && c->len - c->pos >= 4 && memcmp(c->buf + c->pos, "null", 4) == 0) {
        c->pos += 4;
        return true;
    }
    if (ch == '-' || (ch >= '0' && ch <= '9')) {
        c->pos++;
        while (c->pos < c->len) {
            char n = c->buf[c->pos];
            if ((n >= '0' && n <= '9') || n == '.' || n == 'e' || n == 'E' ||
                n == '+' || n == '-') {
                c->pos++;
            } else {
                break;
            }
        }
        return true;
    }
    return false;
}

static inline bool beam_json_scan_inbound_obj(BeamJsonCursor *c, char *out,
                                              size_t out_cap)
{
    bool is_tun = false;
    bool has_name = false;
    char candidate[128];

    candidate[0] = '\0';
    beam_json_skip_ws(c);
    if (c->pos >= c->len || c->buf[c->pos] != '{')
        return false;
    if (c->depth >= BEAM_JSON_MAX_DEPTH)
        return false;
    c->depth++;
    c->pos++;

    beam_json_skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == '}') {
        c->pos++;
        c->depth--;
        return false;
    }

    while (c->pos < c->len) {
        char key[64];
        bool key_trunc = false;
        if (!beam_json_parse_string(c, key, sizeof(key), &key_trunc))
            return false;
        beam_json_skip_ws(c);
        if (c->pos >= c->len || c->buf[c->pos] != ':')
            return false;
        c->pos++;
        beam_json_skip_ws(c);

        if (!key_trunc && strcmp(key, "type") == 0 &&
            c->pos < c->len && c->buf[c->pos] == '"') {
            char val[32];
            bool val_trunc = false;
            if (!beam_json_parse_string(c, val, sizeof(val), &val_trunc))
                return false;
            if (!val_trunc && strcmp(val, "tun") == 0)
                is_tun = true;
        } else if (!key_trunc && strcmp(key, "interface_name") == 0 &&
                   c->pos < c->len && c->buf[c->pos] == '"') {
            bool name_trunc = false;
            if (!beam_json_parse_string(c, candidate, sizeof(candidate), &name_trunc))
                return false;
            if (!name_trunc && candidate[0] != '\0')
                has_name = true;
        } else {
            if (!beam_json_skip_value(c))
                return false;
        }

        beam_json_skip_ws(c);
        if (c->pos >= c->len)
            return false;
        if (c->buf[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (c->buf[c->pos] == '}') {
            c->pos++;
            c->depth--;
            if (is_tun && has_name) {
                size_t n = strlen(candidate);
                if (n + 1 <= out_cap) {
                    memcpy(out, candidate, n + 1);
                    return true;
                }
            }
            return false;
        }
        return false;
    }
    return false;
}

/*
 * Extract the first TUN inbound's "interface_name" from a sing-box JSON config.
 * Returns true and writes a NUL-terminated string into `out` on success;
 * returns false if absent, malformed, or too long for `out_cap`.
 */
static inline bool extract_tun_interface_name(const char *json, size_t len,
                                              char *out, size_t out_cap)
{
    BeamJsonCursor c;

    if (!json || !out || out_cap == 0)
        return false;
    out[0] = '\0';

    c.buf = json;
    c.len = len;
    c.pos = 0;
    c.depth = 0;

    /* Skip optional UTF-8 BOM. */
    if (len >= 3 && (unsigned char)json[0] == 0xEF &&
        (unsigned char)json[1] == 0xBB && (unsigned char)json[2] == 0xBF) {
        c.pos = 3;
    }

    beam_json_skip_ws(&c);
    if (c.pos >= c.len || c.buf[c.pos] != '{')
        return false;
    c.pos++;
    c.depth = 1;

    beam_json_skip_ws(&c);
    if (c.pos < c.len && c.buf[c.pos] == '}')
        return false;

    while (c.pos < c.len) {
        char key[64];
        bool key_trunc = false;
        if (!beam_json_parse_string(&c, key, sizeof(key), &key_trunc))
            return false;
        beam_json_skip_ws(&c);
        if (c.pos >= c.len || c.buf[c.pos] != ':')
            return false;
        c.pos++;
        beam_json_skip_ws(&c);

        if (!key_trunc && strcmp(key, "inbounds") == 0 &&
            c.pos < c.len && c.buf[c.pos] == '[') {
            c.pos++; /* '[' */
            c.depth++;
            beam_json_skip_ws(&c);
            if (c.pos < c.len && c.buf[c.pos] == ']') {
                c.pos++;
                c.depth--;
            } else {
                while (c.pos < c.len) {
                    beam_json_skip_ws(&c);
                    if (c.pos < c.len && c.buf[c.pos] == '{') {
                        if (beam_json_scan_inbound_obj(&c, out, out_cap))
                            return true;
                    } else if (!beam_json_skip_value(&c)) {
                        return false;
                    }
                    beam_json_skip_ws(&c);
                    if (c.pos >= c.len)
                        return false;
                    if (c.buf[c.pos] == ',') {
                        c.pos++;
                        continue;
                    }
                    if (c.buf[c.pos] == ']') {
                        c.pos++;
                        c.depth--;
                        break;
                    }
                    return false;
                }
            }
        } else {
            if (!beam_json_skip_value(&c))
                return false;
        }

        beam_json_skip_ws(&c);
        if (c.pos >= c.len)
            return false;
        if (c.buf[c.pos] == ',') {
            c.pos++;
            continue;
        }
        if (c.buf[c.pos] == '}')
            return false;
        return false;
    }

    return false;
}

#endif /* BEAM_WINDOWS_TRAY_LOGIC_H */
