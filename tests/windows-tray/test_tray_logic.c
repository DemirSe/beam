/*
 * Host unit tests for clients/windows-tray/tray_logic.h.
 * Runs on Linux with gcc/clang -std=c11 -Wall -Wextra -Werror.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../clients/windows-tray/tray_logic.h"

static char *read_entire_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;
    size_t n;

    assert(f != NULL);
    assert(fseek(f, 0, SEEK_END) == 0);
    sz = ftell(f);
    assert(sz >= 0);
    assert(fseek(f, 0, SEEK_SET) == 0);

    buf = (char *)malloc((size_t)sz + 1);
    assert(buf != NULL);
    n = fread(buf, 1, (size_t)sz, f);
    assert(n == (size_t)sz);
    buf[n] = '\0';
    fclose(f);
    *out_len = n;
    return buf;
}

static void test_state_machine(void)
{
    assert(tray_state_can_start(TRAY_STATE_DISCONNECTED));
    assert(tray_state_can_start(TRAY_STATE_ERROR));
    assert(!tray_state_can_start(TRAY_STATE_CONNECTING));
    assert(!tray_state_can_start(TRAY_STATE_CONNECTED));
    assert(!tray_state_can_start(TRAY_STATE_STOPPING));

    assert(tray_state_can_stop(TRAY_STATE_CONNECTING));
    assert(tray_state_can_stop(TRAY_STATE_CONNECTED));
    assert(!tray_state_can_stop(TRAY_STATE_DISCONNECTED));
    assert(!tray_state_can_stop(TRAY_STATE_STOPPING));
    assert(!tray_state_can_stop(TRAY_STATE_ERROR));

    assert(tray_state_is_active(TRAY_STATE_CONNECTING));
    assert(tray_state_is_active(TRAY_STATE_CONNECTED));
    assert(!tray_state_is_active(TRAY_STATE_DISCONNECTED));
    assert(!tray_state_is_active(TRAY_STATE_STOPPING));
    assert(!tray_state_is_active(TRAY_STATE_ERROR));

    /* TUN up/down transitions */
    assert(tray_state_on_tun_status(TRAY_STATE_CONNECTING, true) == TRAY_STATE_CONNECTED);
    assert(tray_state_on_tun_status(TRAY_STATE_CONNECTING, false) == TRAY_STATE_CONNECTING);
    assert(tray_state_on_tun_status(TRAY_STATE_CONNECTED, true) == TRAY_STATE_CONNECTED);
    assert(tray_state_on_tun_status(TRAY_STATE_CONNECTED, false) == TRAY_STATE_CONNECTING);
    assert(tray_state_on_tun_status(TRAY_STATE_DISCONNECTED, true) == TRAY_STATE_DISCONNECTED);
    assert(tray_state_on_tun_status(TRAY_STATE_STOPPING, false) == TRAY_STATE_STOPPING);
    assert(tray_state_on_tun_status(TRAY_STATE_ERROR, true) == TRAY_STATE_ERROR);

    /* Process exit transitions */
    assert(tray_state_on_process_exit(TRAY_STATE_STOPPING, true) == TRAY_STATE_DISCONNECTED);
    assert(tray_state_on_process_exit(TRAY_STATE_STOPPING, false) == TRAY_STATE_DISCONNECTED);
    assert(tray_state_on_process_exit(TRAY_STATE_CONNECTED, true) == TRAY_STATE_DISCONNECTED);
    assert(tray_state_on_process_exit(TRAY_STATE_CONNECTED, false) == TRAY_STATE_ERROR);
    assert(tray_state_on_process_exit(TRAY_STATE_CONNECTING, false) == TRAY_STATE_ERROR);
}

static void test_json_extraction(void)
{
    char out[128];
    size_t len = 0;
    char *win_cfg;
    char *lin_cfg;

    /* Real example configs in the repo */
    win_cfg = read_entire_file("clients/windows-tray/config.example.json", &len);
    assert(extract_tun_interface_name(win_cfg, len, out, sizeof(out)));
    assert(strcmp(out, "beam-tun") == 0);
    free(win_cfg);

    lin_cfg = read_entire_file("clients/linux-tray/config.example.json", &len);
    assert(extract_tun_interface_name(lin_cfg, len, out, sizeof(out)));
    assert(strcmp(out, "sbtun0") == 0);
    free(lin_cfg);

    /* Multiple inbounds: non-tun before tun, interface_name before type */
    {
        const char *j =
            "{\"inbounds\":["
            "  {\"type\":\"mixed\",\"interface_name\":\"wrong0\"},"
            "  {\"interface_name\":\"tun-ok\",\"type\":\"tun\",\"mtu\":1500}"
            "]}";
        assert(extract_tun_interface_name(j, strlen(j), out, sizeof(out)));
        assert(strcmp(out, "tun-ok") == 0);
    }

    /* UTF-8 BOM + escaped quotes in unrelated field */
    {
        const char *j =
            "\xEF\xBB\xBF{\"log\":{\"note\":\"a\\\"b\\\\c\"},"
            "\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"wintun-1\"}]}";
        assert(extract_tun_interface_name(j, strlen(j), out, sizeof(out)));
        assert(strcmp(out, "wintun-1") == 0);
    }

    /* Missing interface_name -> returns false cleanly */
    {
        const char *j = "{\"inbounds\":[{\"type\":\"tun\",\"mtu\":1500}]}";
        assert(!extract_tun_interface_name(j, strlen(j), out, sizeof(out)));
        assert(out[0] == '\0');
    }

    /* Malformed / truncated / empty / hostile inputs -> never crash */
    {
        const char *cases[] = {
            "",
            "{",
            "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"unterminated",
            "{\"inbounds\":\"not-an-array\"}",
            "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"\"}]}",
            "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
        };
        size_t i;
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            assert(!extract_tun_interface_name(cases[i], strlen(cases[i]), out, sizeof(out)));
        }
    }

    /* Output buffer too small -> returns false cleanly */
    {
        const char *j = "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"beam-tun\"}]}";
        char tiny[4];
        assert(!extract_tun_interface_name(j, strlen(j), tiny, sizeof(tiny)));
    }
}

int main(void)
{
    test_state_machine();
    test_json_extraction();
    printf("windows-tray logic tests: OK\n");
    return 0;
}
