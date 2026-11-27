/*
 * Host unit tests for clients/windows-tray/tray_logic.h: the beam-client
 * named-pipe reply parser, the tray state mapping, and the vless:// import
 * request builder.
 *
 * Runs on Linux with gcc/clang -std=c11 -Wall -Wextra -Werror.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../clients/windows-tray/tray_logic.h"

/* Exact wire lines produced by crates/beam-client/src/win_ipc.rs. */
static const char STATUS_CONNECTED[] =
    "OK state=connected ifname=Beam server=203.0.113.10:443 rtt_ms=42 "
    "reason=dial_activity bypass_ok=1 dial_failures=3 generation=7 "
    "drops=route:1,ip_parse:2";
static const char STATUS_IDLE[] =
    "OK state=idle ifname=Beam server=203.0.113.10:443 rtt_ms=42 "
    "reason=probe_ok bypass_ok=1 dial_failures=3 generation=7 "
    "drops=route:1,ip_parse:2";
static const char STATUS_DISCONNECTED[] =
    "OK state=disconnected ifname=none server=none rtt_ms=none "
    "reason=not_connected bypass_ok=1 dial_failures=0 generation=0 drops=none";

static BeamIpcStatus parse_or_die(const char *line)
{
    BeamIpcStatus st;

    if (!beam_ipc_parse_status(line, strlen(line), &st)) {
        fprintf(stderr, "parse failed for: %s\n", line);
        abort();
    }
    return st;
}

static void test_parse_status_fields(void)
{
    BeamIpcStatus st = parse_or_die(STATUS_CONNECTED);

    assert(!st.is_err);
    assert(strcmp(st.state, "connected") == 0);
    assert(strcmp(st.ifname, "Beam") == 0);
    assert(strcmp(st.server, "203.0.113.10:443") == 0);
    assert(st.has_rtt && st.rtt_ms == 42ULL);
    assert(strcmp(st.reason, "dial_activity") == 0);
    assert(st.bypass_ok);
    assert(st.dial_failures == 3ULL);
    assert(st.generation == 7ULL);
    assert(strcmp(st.drops, "route:1,ip_parse:2") == 0);
    assert(st.err_code[0] == '\0' && st.err_msg[0] == '\0');

    /* "none" clears the optional fields. */
    st = parse_or_die(STATUS_DISCONNECTED);
    assert(strcmp(st.state, "disconnected") == 0);
    assert(st.ifname[0] == '\0');
    assert(st.server[0] == '\0');
    assert(!st.has_rtt);
    assert(strcmp(st.reason, "not_connected") == 0);
    assert(st.bypass_ok);
    assert(st.drops[0] == '\0');

    /* A bare TCP probe keeps its neutral state and reason token. */
    st = parse_or_die(STATUS_IDLE);
    assert(strcmp(st.state, "idle") == 0);
    assert(strcmp(st.reason, "probe_ok") == 0);
    assert(st.has_rtt && st.rtt_ms == 42ULL);
}

static void test_parse_status_tolerates_line_endings(void)
{
    static const char *const variants[] = {
        "OK state=connected ifname=none server=none rtt_ms=7 reason=x\n",
        "OK state=connected ifname=none server=none rtt_ms=7 reason=x\r\n",
        "OK state=connected ifname=none server=none rtt_ms=7 reason=x\r",
        "OK state=connected ifname=none server=none rtt_ms=7 reason=x\n\r\n",
    };
    size_t i;

    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        BeamIpcStatus st = parse_or_die(variants[i]);
        assert(st.has_rtt && st.rtt_ms == 7ULL);
        assert(strcmp(st.reason, "x") == 0);
    }
}

static void test_parse_status_forward_compatibility(void)
{
    /* Unknown keys are ignored, before, between, and after the known ones. */
    BeamIpcStatus st = parse_or_die(
        "OK future_key=1 state=connected new=abc ifname=none server=none "
        "rtt_ms=none reason=x bypass_ok=1 tail=zzz");
    assert(strcmp(st.state, "connected") == 0);
    assert(strcmp(st.reason, "x") == 0);
    assert(st.bypass_ok);

    /* An absent bypass_ok means "no known bypass problem". */
    st = parse_or_die("OK state=connected");
    assert(st.bypass_ok);
    assert(!st.has_rtt);
}

static void test_parse_status_numbers(void)
{
    BeamIpcStatus st = parse_or_die("OK state=connected rtt_ms=0");
    assert(st.has_rtt && st.rtt_ms == 0ULL);

    st = parse_or_die("OK state=connected rtt_ms=007");
    assert(st.has_rtt && st.rtt_ms == 7ULL);

    st = parse_or_die("OK state=connected rtt_ms=18446744073709551615 "
                      "dial_failures=18446744073709551615 generation=9");
    assert(st.has_rtt && st.rtt_ms == ~0ULL);
    assert(st.dial_failures == ~0ULL);
    assert(st.generation == 9ULL);

    /* Overflow, sign, letters, and empty values leave the field absent. */
    static const char *const bad[] = {
        "OK state=connected rtt_ms=18446744073709551616",
        "OK state=connected rtt_ms=-1",
        "OK state=connected rtt_ms=42x",
        "OK state=connected rtt_ms=",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        st = parse_or_die(bad[i]);
        assert(!st.has_rtt);
        assert(st.rtt_ms == 0ULL);
    }

    /* bypass_ok only accepts the two wire values. */
    assert(!parse_or_die("OK state=connected bypass_ok=0").bypass_ok);
    assert(parse_or_die("OK state=connected bypass_ok=1").bypass_ok);
    assert(parse_or_die("OK state=connected bypass_ok=2").bypass_ok);
    assert(parse_or_die("OK state=connected bypass_ok=").bypass_ok);
}

static void test_parse_status_err(void)
{
    BeamIpcStatus st = parse_or_die("ERR code=import_failed msg=invalid vless link\n");

    assert(st.is_err);
    assert(strcmp(st.err_code, "import_failed") == 0);
    assert(strcmp(st.err_msg, "invalid vless link") == 0);
    assert(st.state[0] == '\0');

    /* The message keeps every space up to the end of the line. */
    st = parse_or_die("ERR code=bad_request msg=IMPORT_LINK requires one space and a vless:// link");
    assert(strcmp(st.err_msg, "IMPORT_LINK requires one space and a vless:// link") == 0);

    /* Empty message stays empty; the code is still required. */
    st = parse_or_die("ERR code=error msg=");
    assert(st.is_err && st.err_msg[0] == '\0' && strcmp(st.err_code, "error") == 0);

    st = parse_or_die("ERR code=too_long");
    assert(st.is_err && strcmp(st.err_code, "too_long") == 0 && st.err_msg[0] == '\0');
}

static void test_parse_status_rejects_malformed_input(void)
{
    static const char *const cases[] = {
        "",
        " ",
        "\n",
        "OK",
        "OK ",
        "OK    ",
        "ERR",
        "ERR ",
        "ERR msg=no code",
        "ERR code=",
        "CONNECTED",
        " OK state=connected",
        "OKstate=connected",
        "ERRcode=x",
        "OK state",
        "OK state=connected 2",
        "OK =value",
        "OK state=connected CONNECT",
        "OK state=connected\nCONNECT\n",
        "OK state=connected\rCONNECT",
        "garbage OK state=connected",
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        BeamIpcStatus st;
        assert(!beam_ipc_parse_status(cases[i], strlen(cases[i]), &st));
    }

    /* NULL arguments never crash. */
    {
        BeamIpcStatus st;
        assert(!beam_ipc_parse_status(NULL, 10, &st));
        assert(!beam_ipc_parse_status("OK state=x", 10, NULL));
    }
}

static void test_parse_status_bounds(void)
{
    static const char long_state[] =
        "OK state=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa rtt_ms=1";
    static const char long_ifname[] =
        "OK state=x ifname="
        "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
        "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
        "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii";
    static const char long_drops[] =
        "OK state=x drops="
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd";
    BeamIpcStatus st;
    size_t i;

    st = parse_or_die(long_state);
    assert(strlen(st.state) == sizeof(st.state) - 1);
    assert(st.state[sizeof(st.state) - 1] == '\0');

    st = parse_or_die(long_ifname);
    assert(strlen(st.ifname) == sizeof(st.ifname) - 1);
    assert(st.ifname[sizeof(st.ifname) - 1] == '\0');

    st = parse_or_die(long_drops);
    assert(strlen(st.drops) == sizeof(st.drops) - 1);
    assert(st.drops[sizeof(st.drops) - 1] == '\0');

    /* A parse bounded by len results in the same NUL-terminated fields. */
    memset(&st, 'Z', sizeof(st));
    assert(beam_ipc_parse_status(STATUS_CONNECTED, strlen(STATUS_CONNECTED), &st));
    assert(st.state[sizeof(st.state) - 1] == '\0');
    assert(st.ifname[sizeof(st.ifname) - 1] == '\0');
    assert(st.server[sizeof(st.server) - 1] == '\0');
    assert(st.reason[sizeof(st.reason) - 1] == '\0');
    assert(st.drops[sizeof(st.drops) - 1] == '\0');
    assert(st.err_code[sizeof(st.err_code) - 1] == '\0');
    assert(st.err_msg[sizeof(st.err_msg) - 1] == '\0');

    /* An embedded NUL byte is just an ignored byte: no over-read, no crash. */
    {
        static const char embedded[] = "OK state=conn\0ected rtt_ms=5";
        assert(beam_ipc_parse_status(embedded, sizeof(embedded) - 1, &st));
        assert(strcmp(st.state, "conn") == 0 && st.has_rtt && st.rtt_ms == 5ULL);
    }

    /* Every prefix of the full line is parsed safely (truncation fuzz). */
    for (i = 0; i <= strlen(STATUS_CONNECTED); ++i) {
        BeamIpcStatus truncated;
        if (beam_ipc_parse_status(STATUS_CONNECTED, i, &truncated))
            assert(truncated.state[0] != '\0' || truncated.is_err);
    }
}

static void test_parse_command_reply(void)
{
    static const char ok_state[] = "OK state=connecting\n";
    static const char ok_server[] = "OK server=203.0.113.10:443";
    static const char ok_extra[] = "OK generation=8 state=connected\r\n";
    static const char err_msg[] = "ERR code=bad_link msg=link must start with vless://";
    static const char err_empty[] = "ERR code=too_long msg=";
    bool is_ok = false;
    char value[128];
    char err[256];

    /* OK state=... */
    assert(beam_ipc_parse_command_reply(ok_state, strlen(ok_state), &is_ok, value,
                                        sizeof(value), err, sizeof(err)));
    assert(is_ok && strcmp(value, "connecting") == 0 && err[0] == '\0');

    /* OK server=... */
    assert(beam_ipc_parse_command_reply(ok_server, strlen(ok_server), &is_ok, value,
                                        sizeof(value), err, sizeof(err)));
    assert(is_ok && strcmp(value, "203.0.113.10:443") == 0);

    /* Unknown keys are ignored, the state value still wins. */
    assert(beam_ipc_parse_command_reply(ok_extra, strlen(ok_extra), &is_ok, value,
                                        sizeof(value), err, sizeof(err)));
    assert(is_ok && strcmp(value, "connected") == 0);

    /* ERR: the message text may contain spaces. */
    assert(beam_ipc_parse_command_reply(err_msg, strlen(err_msg), &is_ok, value,
                                        sizeof(value), err, sizeof(err)));
    assert(!is_ok && value[0] == '\0');
    assert(strcmp(err, "link must start with vless://") == 0);

    /* ERR without a message falls back to the code. */
    assert(beam_ipc_parse_command_reply(err_empty, strlen(err_empty), &is_ok, value,
                                        sizeof(value), err, sizeof(err)));
    assert(!is_ok && strcmp(err, "too_long") == 0);

    /* Malformed replies are rejected and clear both outputs. */
    static const char *const bad[] = {
        "",
        "OK",
        "OK foo=bar",
        "ERR",
        "ERR msg=no code",
        "STATUS",
        "OK state=connecting\nCONNECT",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        strcpy(value, "junk");
        strcpy(err, "junk");
        is_ok = true;
        assert(!beam_ipc_parse_command_reply(bad[i], strlen(bad[i]), &is_ok, value,
                                             sizeof(value), err, sizeof(err)));
        assert(value[0] == '\0' && err[0] == '\0');
        assert(!is_ok);
    }

    /* A small buffer truncates but stays NUL-terminated. */
    {
        char tiny[4];
        assert(beam_ipc_parse_command_reply("OK state=connected", 18, &is_ok, tiny,
                                            sizeof(tiny), err, sizeof(err)));
        assert(is_ok && strcmp(tiny, "con") == 0);
    }

    /* NULL outputs are tolerated. */
    assert(beam_ipc_parse_command_reply(ok_state, strlen(ok_state), &is_ok, NULL, 0,
                                        NULL, 0));
    assert(is_ok);
    assert(!beam_ipc_parse_command_reply(NULL, 0, &is_ok, value, sizeof(value), err,
                                         sizeof(err)));
    assert(!beam_ipc_parse_command_reply("OK state=x", 10, NULL, value,
                                         sizeof(value), err, sizeof(err)));
}

static void test_derive_tray_state(void)
{
    BeamIpcStatus st;

    memset(&st, 0, sizeof(st));
    st.bypass_ok = true;

    assert(beam_ipc_derive_tray_state(NULL) == TRAY_STATE_UNAVAILABLE);

    /* A parsed ERR line is always an error, whatever else it carries. */
    strcpy(st.state, "connected");
    st.is_err = true;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);
    st.is_err = false;

    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_CONNECTED);
    st.bypass_ok = false;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DEGRADED);

    strcpy(st.state, "idle");
    strcpy(st.reason, "probe_ok");
    st.bypass_ok = true;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_IDLE);
    st.bypass_ok = false;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DEGRADED);
    st.bypass_ok = true;

    strcpy(st.state, "reconnecting");
    strcpy(st.reason, "network_change");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_RECONNECTING);
    strcpy(st.reason, "dial_failures");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DEGRADED);
    st.bypass_ok = true;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DEGRADED);

    /* The lifetime counter does not degrade a healthy reconnect. */
    strcpy(st.reason, "network_change");
    st.dial_failures = 99;
    st.bypass_ok = true;
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_RECONNECTING);

    strcpy(st.state, "waiting_network");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_WAITING_NETWORK);
    strcpy(st.state, "connecting");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_CONNECTING);
    strcpy(st.state, "stopping");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_STOPPING);
    strcpy(st.state, "disconnected");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DISCONNECTED);
    strcpy(st.state, "error");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);
    strcpy(st.state, "Connected");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);
    strcpy(st.state, "");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);
    strcpy(st.state, "degraded");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);

    /* End-to-end: wire lines map to the expected tray state. */
    st = parse_or_die(STATUS_CONNECTED);
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_CONNECTED);
    st = parse_or_die(STATUS_IDLE);
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_IDLE);
    st = parse_or_die(STATUS_DISCONNECTED);
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_DISCONNECTED);
    st = parse_or_die("ERR code=bad_request msg=unknown command");
    assert(beam_ipc_derive_tray_state(&st) == TRAY_STATE_ERROR);
}

static void test_menu_actions(void)
{
    assert(beam_tray_can_connect(TRAY_STATE_DISCONNECTED));
    assert(beam_tray_can_connect(TRAY_STATE_ERROR));
    assert(!beam_tray_can_connect(TRAY_STATE_CONNECTING));
    assert(!beam_tray_can_connect(TRAY_STATE_CONNECTED));
    assert(!beam_tray_can_connect(TRAY_STATE_DEGRADED));
    assert(!beam_tray_can_connect(TRAY_STATE_RECONNECTING));
    assert(!beam_tray_can_connect(TRAY_STATE_WAITING_NETWORK));
    assert(!beam_tray_can_connect(TRAY_STATE_IDLE));
    assert(!beam_tray_can_connect(TRAY_STATE_STOPPING));
    assert(!beam_tray_can_connect(TRAY_STATE_UNAVAILABLE));

    assert(!beam_tray_can_disconnect(TRAY_STATE_DISCONNECTED));
    assert(!beam_tray_can_disconnect(TRAY_STATE_ERROR));
    assert(beam_tray_can_disconnect(TRAY_STATE_CONNECTING));
    assert(beam_tray_can_disconnect(TRAY_STATE_CONNECTED));
    assert(beam_tray_can_disconnect(TRAY_STATE_DEGRADED));
    assert(beam_tray_can_disconnect(TRAY_STATE_RECONNECTING));
    assert(beam_tray_can_disconnect(TRAY_STATE_WAITING_NETWORK));
    assert(beam_tray_can_disconnect(TRAY_STATE_IDLE));
    assert(!beam_tray_can_disconnect(TRAY_STATE_STOPPING));
    assert(!beam_tray_can_disconnect(TRAY_STATE_UNAVAILABLE));
}

static void test_format_status_text(void)
{
    BeamIpcStatus st;
    char text[128];

    memset(&st, 0, sizeof(st));
    st.bypass_ok = true;

    st.has_rtt = true;
    st.rtt_ms = 42;
    beam_ipc_format_status_text(&st, TRAY_STATE_CONNECTED, text, sizeof(text));
    assert(strcmp(text, "beam: Connected (42 ms)") == 0);

    st.has_rtt = false;
    beam_ipc_format_status_text(&st, TRAY_STATE_CONNECTED, text, sizeof(text));
    assert(strcmp(text, "beam: Connected") == 0);

    /* Degraded: dial failures, bypass, or both. */
    st.bypass_ok = false;
    st.reason[0] = '\0';
    beam_ipc_format_status_text(&st, TRAY_STATE_DEGRADED, text, sizeof(text));
    assert(strcmp(text, "beam: Degraded (bypass missing)") == 0);

    st.bypass_ok = true;
    strcpy(st.reason, "dial_failures");
    beam_ipc_format_status_text(&st, TRAY_STATE_DEGRADED, text, sizeof(text));
    assert(strcmp(text, "beam: Degraded (dial failures)") == 0);

    st.bypass_ok = false;
    beam_ipc_format_status_text(&st, TRAY_STATE_DEGRADED, text, sizeof(text));
    assert(strcmp(text, "beam: Degraded (dial failures, bypass missing)") == 0);

    st.reason[0] = '\0';
    st.bypass_ok = true;
    beam_ipc_format_status_text(&st, TRAY_STATE_DEGRADED, text, sizeof(text));
    assert(strcmp(text, "beam: Degraded") == 0);

    beam_ipc_format_status_text(&st, TRAY_STATE_IDLE, text, sizeof(text));
    assert(strcmp(text, "beam: Idle") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_RECONNECTING, text, sizeof(text));
    assert(strcmp(text, "beam: Reconnecting...") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_WAITING_NETWORK, text, sizeof(text));
    assert(strcmp(text, "beam: Waiting for network...") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_CONNECTING, text, sizeof(text));
    assert(strcmp(text, "beam: Connecting...") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_STOPPING, text, sizeof(text));
    assert(strcmp(text, "beam: Stopping...") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_DISCONNECTED, text, sizeof(text));
    assert(strcmp(text, "beam: Disconnected") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_ERROR, text, sizeof(text));
    assert(strcmp(text, "beam: Error") == 0);
    beam_ipc_format_status_text(&st, TRAY_STATE_UNAVAILABLE, text, sizeof(text));
    assert(strcmp(text, "beam: Service unavailable") == 0);

    /* Missing status never crashes. */
    beam_ipc_format_status_text(NULL, TRAY_STATE_CONNECTED, text, sizeof(text));
    assert(strcmp(text, "beam: Connected") == 0);
    beam_ipc_format_status_text(NULL, TRAY_STATE_UNAVAILABLE, text, sizeof(text));
    assert(strcmp(text, "beam: Service unavailable") == 0);

    /* Small buffers are truncated, NUL-terminated, and never overrun. */
    memset(text, 'Z', sizeof(text));
    beam_ipc_format_status_text(&st, TRAY_STATE_UNAVAILABLE, text, 8);
    assert(strcmp(text, "beam: S") == 0);
    text[0] = 'Z';
    beam_ipc_format_status_text(&st, TRAY_STATE_CONNECTED, text, 1);
    assert(text[0] == '\0');

    /* Every state stays inside the Win32 tooltip bound (127 characters). */
    {
        int state;
        for (state = 0; state <= (int)TRAY_STATE_IDLE; ++state) {
            beam_ipc_format_status_text(&st, (TrayState)state, text, sizeof(text));
            assert(strlen(text) > 0 && strlen(text) <= 127);
        }
    }

    /* The connected status line renders with its RTT. */
    st = parse_or_die(STATUS_CONNECTED);
    beam_ipc_format_status_text(&st, beam_ipc_derive_tray_state(&st), text,
                                sizeof(text));
    assert(strcmp(text, "beam: Connected (42 ms)") == 0);

    st = parse_or_die(STATUS_IDLE);
    beam_ipc_format_status_text(&st, beam_ipc_derive_tray_state(&st), text,
                                sizeof(text));
    assert(strcmp(text, "beam: Idle") == 0);
}

static void test_prepare_import_link(void)
{
    char cmd[4096];
    char big[2100];
    static const char link[] =
        "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443"
        "?encryption=none&security=reality&sni=whatsapp.net&fp=chrome&type=tcp";
    static const char expect[] =
        "IMPORT_LINK vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443"
        "?encryption=none&security=reality&sni=whatsapp.net&fp=chrome&type=tcp\n";

    assert(beam_ipc_prepare_import_link(link, cmd, sizeof(cmd)));
    assert(strcmp(cmd, expect) == 0);
    assert(strlen(cmd) < BEAM_IPC_MAX_REQUEST_BYTES);

    /* Leading and trailing spaces, tabs, and CRLF are trimmed. */
    assert(beam_ipc_prepare_import_link("  \t vless://a \r\n\t ", cmd, sizeof(cmd)));
    assert(strcmp(cmd, "IMPORT_LINK vless://a\n") == 0);
    assert(beam_ipc_prepare_import_link("\r\nvless://a\n", cmd, sizeof(cmd)));
    assert(strcmp(cmd, "IMPORT_LINK vless://a\n") == 0);

    /* Shortest accepted link is "vless://" plus one byte. */
    assert(beam_ipc_prepare_import_link("vless://a", cmd, sizeof(cmd)));
    assert(strcmp(cmd, "IMPORT_LINK vless://a\n") == 0);

    static const char *const bad[] = {
        "",
        "   ",
        "\r\n",
        "vless://",
        "vless:/",
        "vless:/a",
        "VLESS://a",
        "https://example.com",
        "vless://a b",
        "vless://a\tb",
        "vless://a\nb",
        "vless://a\rb",
        "vless://a\x01" "b",
        "vless://a\x7f" "b",
        "vless://a\x7f",
        " vless://a b ",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        strcpy(cmd, "junk");
        assert(!beam_ipc_prepare_import_link(bad[i], cmd, sizeof(cmd)));
        assert(cmd[0] == '\0');
    }

    /* Boundary lengths: 2048 bytes fit, 2049 bytes do not. */
    memset(big, 'a', sizeof(big));
    memcpy(big, "vless://", 8);
    big[2048] = '\0';
    assert(beam_ipc_prepare_import_link(big, cmd, sizeof(cmd)));
    assert(strlen(cmd) == 12 + 2048 + 1);
    assert(cmd[12 + 2048] == '\n' && cmd[12 + 2048 + 1] == '\0');

    big[2048] = 'a';
    big[2049] = '\0';
    assert(!beam_ipc_prepare_import_link(big, cmd, sizeof(cmd)));
    assert(cmd[0] == '\0');

    /* Exact output-capacity boundary: 12 + link + '\n' + '\0'. */
    assert(beam_ipc_prepare_import_link("vless://a", cmd, 12 + 9 + 2));
    assert(strcmp(cmd, "IMPORT_LINK vless://a\n") == 0);
    strcpy(cmd, "junk");
    assert(!beam_ipc_prepare_import_link("vless://a", cmd, 12 + 9 + 1));
    assert(cmd[0] == '\0');

    /* NULL and zero-capacity outputs never crash. */
    assert(!beam_ipc_prepare_import_link(NULL, cmd, sizeof(cmd)));
    assert(!beam_ipc_prepare_import_link(link, NULL, sizeof(cmd)));
    assert(!beam_ipc_prepare_import_link(link, cmd, 0));
}

int main(void)
{
    test_parse_status_fields();
    test_parse_status_tolerates_line_endings();
    test_parse_status_forward_compatibility();
    test_parse_status_numbers();
    test_parse_status_err();
    test_parse_status_rejects_malformed_input();
    test_parse_status_bounds();
    test_parse_command_reply();
    test_derive_tray_state();
    test_menu_actions();
    test_format_status_text();
    test_prepare_import_link();
    printf("windows-tray logic tests: OK\n");
    return 0;
}
