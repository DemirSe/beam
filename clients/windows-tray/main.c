/*
 * beam-tray: unelevated Windows tray client for the beam-client service.
 *
 * The tray owns no tunnel process and needs no administrator rights. It talks
 * to the running BeamClient service over the named pipe
 * \\.\pipe\beam-client-ipc from one background worker thread, so the Win32
 * message loop never blocks on pipe I/O.
 *
 * Request and reply lines, the status parser, and the menu text live in
 * tray_logic.h, which is host-testable and shared with the unit tests under
 * tests/windows-tray/.
 *
 * Requests:  STATUS, CONNECT, DISCONNECT, RESTART, IMPORT_LINK <link>
 * Replies:   OK state=... ... | OK ... | ERR code=... msg=...
 *
 * Build with build.sh (MinGW-w64) or the MSVC command documented there.
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <stdbool.h>
#include <string.h>

#include "tray_logic.h"

#define APP_TITLE              L"beam"
#define TRAY_CLASS             L"BeamTrayWindow"
#define TRAY_MUTEX             L"Local\\beam-native-tray"
#define IPC_PIPE_NAME          L"\\\\.\\pipe\\beam-client-ipc"

#define IDI_ICON_APP           1
#define IDI_TRAY_GRAY          101
#define IDI_TRAY_AMBER         102
#define IDI_TRAY_GREEN         103
#define IDI_TRAY_RED           104

#define IDD_IMPORT_LINK        200
#define IDC_LINK_EDIT          201

#define IDM_TRAY               1u
#define IDM_STATUS             2001u
#define IDM_SERVER             2002u
#define IDM_DROPS              2003u
#define IDM_CONNECT            2004u
#define IDM_DISCONNECT         2005u
#define IDM_RESTART            2006u
#define IDM_IMPORT             2007u
#define IDM_CONFIG             2008u
#define IDM_LOG                2009u
#define IDM_EXIT               2010u

#define WM_TRAY_MSG            (WM_APP + 1)
#define WM_IPC_STATUS          (WM_APP + 2)
#define WM_IPC_CMD_DONE        (WM_APP + 3)

/* One status poll every two seconds, and immediately after a command. */
#define IPC_POLL_MS            2000
/* Bound for WaitNamedPipeW when another client holds the single instance. */
#define IPC_PIPE_WAIT_MS       2000
/* Bound for a whole request round trip, so a stuck service cannot block us. */
#define IPC_IO_TIMEOUT_MS      4000
#define IPC_POLL_STEP_MS       10
/* Bound for joining the worker at exit. */
#define IPC_JOIN_TIMEOUT_MS    6000
#define IPC_READ_MAX           4096
/* "IMPORT_LINK " plus a link must fit the service's 4095 byte line limit. */
#define IPC_CMD_MAX            4001
#define IPC_QUEUE_LEN          4
#define IMPORT_MAX_WIDE        4096
#define IMPORT_MAX_UTF8        8192
#define BALLOON_TIMEOUT_MS     10000

typedef enum {
    CMD_NONE = 0,
    CMD_CONNECT,
    CMD_DISCONNECT,
    CMD_RESTART,
    CMD_IMPORT
} CommandKind;

static HINSTANCE g_instance;
static HWND      g_window;
static UINT      g_msg_taskbar_created;
static BOOL      g_tray_added;

static HICON     g_icon_app;
static HICON     g_icon_gray;
static HICON     g_icon_amber;
static HICON     g_icon_green;
static HICON     g_icon_red;

static wchar_t   g_config_path[MAX_PATH * 2];
static wchar_t   g_log_path[MAX_PATH * 2];

/* IPC snapshot, command queue, and the last command result share one lock. */
static CRITICAL_SECTION g_lock;
static BeamIpcStatus    g_status;
static BOOL             g_reachable;
static char             g_queue[IPC_QUEUE_LEN][IPC_CMD_MAX];
static int              g_queue_kind[IPC_QUEUE_LEN];
static int              g_queue_head;
static int              g_queue_count;
static char             g_cmd_err[256];

static volatile LONG g_worker_stop;
static HANDLE        g_worker_wake;
static HANDLE        g_worker_thread;

/* Tray state is owned by the UI thread. */
static TrayState g_tray_state = TRAY_STATE_UNAVAILABLE;

static BOOL utf8_to_wide(const char *src, wchar_t *dst, size_t dst_cap)
{
    int needed;
    int written;

    if (!dst || dst_cap == 0)
        return FALSE;
    dst[0] = L'\0';
    if (!src || src[0] == '\0')
        return TRUE;

    needed = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
    if (needed <= 0 || (size_t)needed > dst_cap)
        return FALSE;
    written = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)dst_cap);
    if (written != needed)
        return FALSE;
    dst[dst_cap - 1] = L'\0';
    return TRUE;
}

static BOOL wide_to_utf8(const wchar_t *src, char *dst, size_t dst_cap)
{
    int needed;
    int written;

    if (!dst || dst_cap == 0)
        return FALSE;
    dst[0] = '\0';
    if (!src || src[0] == L'\0')
        return TRUE;

    needed = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
    if (needed <= 0 || (size_t)needed > dst_cap)
        return FALSE;
    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dst_cap, NULL, NULL);
    if (written != needed)
        return FALSE;
    dst[dst_cap - 1] = '\0';
    return TRUE;
}

static void resolve_paths(void)
{
    wchar_t base[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"ProgramData", base, (DWORD)ARRAYSIZE(base));

    if (length == 0 || (size_t)length >= ARRAYSIZE(base))
        StringCchCopyW(base, ARRAYSIZE(base), L"C:\\ProgramData");

    if (FAILED(StringCchPrintfW(g_config_path, ARRAYSIZE(g_config_path),
                                L"%s\\beam\\client.toml", base)))
        g_config_path[0] = L'\0';
    if (FAILED(StringCchPrintfW(g_log_path, ARRAYSIZE(g_log_path),
                                L"%s\\beam\\beam-client.log", base)))
        g_log_path[0] = L'\0';
}

static HICON load_icon(HINSTANCE instance, UINT id)
{
    int cx = GetSystemMetrics(SM_CXSMICON);
    int cy = GetSystemMetrics(SM_CYSMICON);
    HICON icon;

    if (cx <= 0)
        cx = 16;
    if (cy <= 0)
        cy = 16;

    icon = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(id), IMAGE_ICON, cx, cy,
                             LR_DEFAULTCOLOR);
    if (!icon)
        icon = LoadIconW(instance, MAKEINTRESOURCEW(id));
    return icon;
}

static void load_icons(HINSTANCE instance)
{
    g_icon_app = LoadIconW(instance, MAKEINTRESOURCEW(IDI_ICON_APP));
    if (!g_icon_app)
        g_icon_app = LoadIconW(NULL, IDI_APPLICATION);

    g_icon_gray = load_icon(instance, IDI_TRAY_GRAY);
    g_icon_amber = load_icon(instance, IDI_TRAY_AMBER);
    g_icon_green = load_icon(instance, IDI_TRAY_GREEN);
    g_icon_red = load_icon(instance, IDI_TRAY_RED);
}

static HICON icon_for_state(TrayState state)
{
    HICON icon = NULL;

    switch (state) {
    case TRAY_STATE_CONNECTED:
        icon = g_icon_green;
        break;
    case TRAY_STATE_CONNECTING:
    case TRAY_STATE_RECONNECTING:
    case TRAY_STATE_WAITING_NETWORK:
    case TRAY_STATE_STOPPING:
    case TRAY_STATE_DEGRADED:
        icon = g_icon_amber;
        break;
    case TRAY_STATE_ERROR:
        icon = g_icon_red;
        break;
    case TRAY_STATE_DISCONNECTED:
    case TRAY_STATE_UNAVAILABLE:
    default:
        icon = g_icon_gray;
        break;
    }

    if (!icon)
        icon = g_icon_app;
    return icon;
}

static void tray_text(const BeamIpcStatus *st, TrayState state, wchar_t *buf,
                      size_t cap)
{
    char text[1024];
    wchar_t full[1024];

    if (!buf || cap == 0)
        return;
    buf[0] = L'\0';

    text[0] = '\0';
    (void)beam_ipc_format_status_text(st, state, text, sizeof text);
    text[ARRAYSIZE(text) - 1] = '\0';

    full[0] = L'\0';
    if (text[0] != '\0' && utf8_to_wide(text, full, ARRAYSIZE(full)) &&
        full[0] != L'\0') {
        StringCchCopyN(buf, cap, full, cap - 1);
        return;
    }

    StringCchCopyN(buf, cap, L"beam: service unavailable", cap - 1);
}

static void tray_notify(DWORD action, const BeamIpcStatus *st, TrayState state)
{
    NOTIFYICONDATAW nid;
    wchar_t tip[256];

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize = sizeof nid;
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY_MSG;
    nid.hIcon = icon_for_state(state);

    tray_text(st, state, tip, ARRAYSIZE(tip));
    StringCchCopyN(nid.szTip, ARRAYSIZE(nid.szTip), tip,
                   ARRAYSIZE(nid.szTip) - 1);

    if (Shell_NotifyIconW(action, &nid))
        g_tray_added = (action != NIM_DELETE);
}

static void tray_add(void)
{
    BeamIpcStatus status;

    ZeroMemory(&status, sizeof status);
    tray_notify(NIM_ADD, &status, g_tray_state);
}

static void tray_remove(void)
{
    NOTIFYICONDATAW nid;

    if (!g_tray_added)
        return;

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize = sizeof nid;
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_tray_added = FALSE;
}

static void tray_balloon(const BeamIpcStatus *st, TrayState state)
{
    NOTIFYICONDATAW nid;
    wchar_t text[1024];
    BOOL have_text = FALSE;

    if (!g_tray_added)
        return;
    text[0] = L'\0';

    if (state == TRAY_STATE_ERROR && st->err_msg[0] != '\0')
        have_text = utf8_to_wide(st->err_msg, text, ARRAYSIZE(text));
    if (!have_text || text[0] == L'\0')
        tray_text(st, state, text, ARRAYSIZE(text));

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize = sizeof nid;
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = (state == TRAY_STATE_ERROR) ? NIIF_ERROR : NIIF_WARNING;
    nid.uTimeout = BALLOON_TIMEOUT_MS;
    StringCchCopyW(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle), L"beam");
    StringCchCopyN(nid.szInfo, ARRAYSIZE(nid.szInfo), text,
                   ARRAYSIZE(nid.szInfo) - 1);

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void apply_state(TrayState state, const BeamIpcStatus *st)
{
    TrayState previous = g_tray_state;

    g_tray_state = state;
    if (g_tray_added)
        tray_notify(NIM_MODIFY, st, state);
    if (state != previous &&
        (state == TRAY_STATE_ERROR || state == TRAY_STATE_DEGRADED))
        tray_balloon(st, state);
}

static void snapshot_status(BeamIpcStatus *st, BOOL *reachable)
{
    EnterCriticalSection(&g_lock);
    *st = g_status;
    *reachable = g_reachable;
    LeaveCriticalSection(&g_lock);
}

/* --- Command queue ------------------------------------------------------ */

static BOOL queue_push(CommandKind kind, const char *line)
{
    size_t length;
    BOOL pushed = FALSE;

    if (!line)
        return FALSE;
    length = strlen(line);
    if (length == 0 || length >= IPC_CMD_MAX)
        return FALSE;

    EnterCriticalSection(&g_lock);
    if (g_queue_count < IPC_QUEUE_LEN) {
        int index = (g_queue_head + g_queue_count) % IPC_QUEUE_LEN;
        memcpy(g_queue[index], line, length + 1);
        g_queue_kind[index] = (int)kind;
        g_queue_count++;
        pushed = TRUE;
    }
    LeaveCriticalSection(&g_lock);

    return pushed;
}

static BOOL queue_pop(CommandKind *kind, char *out)
{
    size_t length;
    BOOL popped = FALSE;

    EnterCriticalSection(&g_lock);
    if (g_queue_count > 0) {
        length = strlen(g_queue[g_queue_head]);
        memcpy(out, g_queue[g_queue_head], length + 1);
        *kind = (CommandKind)g_queue_kind[g_queue_head];
        SecureZeroMemory(g_queue[g_queue_head], IPC_CMD_MAX);
        g_queue_head = (g_queue_head + 1) % IPC_QUEUE_LEN;
        g_queue_count--;
        popped = TRUE;
    }
    LeaveCriticalSection(&g_lock);

    return popped;
}

static void queue_clear(void)
{
    int i;

    EnterCriticalSection(&g_lock);
    for (i = 0; i < IPC_QUEUE_LEN; ++i)
        SecureZeroMemory(g_queue[i], IPC_CMD_MAX);
    g_queue_head = 0;
    g_queue_count = 0;
    LeaveCriticalSection(&g_lock);
}

/* --- Named pipe transport ----------------------------------------------- */

/*
 * Opens one pipe instance. The service serves one request per connection, so
 * every round trip opens, writes, reads, and closes. SECURITY_SQOS_PRESENT with
 * SECURITY_IDENTIFICATION lets the server identify this process but never
 * impersonate it.
 */
static HANDLE ipc_connect(void)
{
    DWORD flags = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
    HANDLE pipe;

    pipe = CreateFileW(IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, flags, NULL);
    if (pipe != INVALID_HANDLE_VALUE)
        return pipe;
    if (GetLastError() != ERROR_PIPE_BUSY)
        return INVALID_HANDLE_VALUE;
    if (!WaitNamedPipeW(IPC_PIPE_NAME, IPC_PIPE_WAIT_MS))
        return INVALID_HANDLE_VALUE;

    return CreateFileW(IPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, flags, NULL);
}

/*
 * Reads one reply line with a deadline. The pipe is blocking byte mode, so wait
 * for the first byte with a bounded PeekNamedPipe poll, then keep reading until
 * the line terminator arrives; both the wait and the buffer are bounded.
 */
static BOOL ipc_read_line(HANDLE pipe, char *buf, size_t cap, size_t *out_len)
{
    ULONGLONG deadline = GetTickCount64() + IPC_IO_TIMEOUT_MS;
    size_t used = 0;

    if (!buf || cap < 2)
        return FALSE;

    for (;;) {
        DWORD available = 0;

        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
            return FALSE;

        if (available > 0) {
            DWORD want = (DWORD)(cap - 1 - used);
            DWORD read = 0;

            if (want == 0)
                return FALSE;
            if (want > available)
                want = available;
            if (!ReadFile(pipe, buf + used, want, &read, NULL))
                return FALSE;
            if (read == 0)
                return FALSE;
            used += (size_t)read;
            if (buf[used - 1] == '\n')
                break;
            continue;
        }

        if (GetTickCount64() >= deadline)
            return FALSE;
        Sleep(IPC_POLL_STEP_MS);
    }

    buf[used] = '\0';
    *out_len = used;
    return TRUE;
}

static BOOL ipc_request(const char *line, char *reply, size_t reply_cap,
                        size_t *reply_len)
{
    char request[IPC_CMD_MAX + 2];
    size_t line_len;
    DWORD written = 0;
    HANDLE pipe;
    BOOL ok = FALSE;

    if (!line || !reply || reply_cap < 2)
        return FALSE;
    line_len = strlen(line);
    /* The importer already ends its command with '\n'; send exactly one. */
    while (line_len > 0 &&
           (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
        line_len--;
    if (line_len == 0 || line_len + 2 > ARRAYSIZE(request))
        return FALSE;

    memcpy(request, line, line_len);
    request[line_len] = '\n';

    pipe = ipc_connect();
    if (pipe == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(request, sizeof request);
        return FALSE;
    }

    if (WriteFile(pipe, request, (DWORD)(line_len + 1), &written, NULL) &&
        written == (DWORD)(line_len + 1) &&
        ipc_read_line(pipe, reply, reply_cap, reply_len))
        ok = TRUE;

    CloseHandle(pipe);
    SecureZeroMemory(request, sizeof request);

    if (ok) {
        while (*reply_len > 0 &&
               (reply[*reply_len - 1] == '\n' || reply[*reply_len - 1] == '\r')) {
            reply[*reply_len - 1] = '\0';
            (*reply_len)--;
        }
    }

    return ok;
}

/* --- IPC worker --------------------------------------------------------- */

static void drain_commands(void)
{
    CommandKind kind = CMD_NONE;
    char command[IPC_CMD_MAX];

    while (queue_pop(&kind, command)) {
        char reply[IPC_READ_MAX + 1];
        char value[256];
        char error[256];
        size_t reply_len = 0;
        BOOL ok = FALSE;
        bool is_ok = false;

        reply[0] = '\0';
        value[0] = '\0';
        error[0] = '\0';

        if (ipc_request(command, reply, sizeof reply, &reply_len)) {
            if (beam_ipc_parse_command_reply(reply, reply_len, &is_ok, value,
                                             sizeof value, error,
                                             sizeof error)) {
                ok = is_ok ? TRUE : FALSE;
            } else {
                StringCchCopyA(error, ARRAYSIZE(error),
                               "unexpected reply from the service");
            }
        } else {
            StringCchCopyA(error, ARRAYSIZE(error),
                           "cannot reach the beam service");
        }
        if (ok)
            error[0] = '\0';

        SecureZeroMemory(command, sizeof command);

        EnterCriticalSection(&g_lock);
        StringCchCopyA(g_cmd_err, ARRAYSIZE(g_cmd_err), error);
        LeaveCriticalSection(&g_lock);

        PostMessageW(g_window, WM_IPC_CMD_DONE, (WPARAM)kind,
                     (LPARAM)(ok ? 1 : 0));
    }
}

static void poll_status(void)
{
    char reply[IPC_READ_MAX + 1];
    BeamIpcStatus status;
    size_t reply_len = 0;
    BOOL reachable = FALSE;

    ZeroMemory(&status, sizeof status);
    reply[0] = '\0';

    if (ipc_request("STATUS", reply, sizeof reply, &reply_len) &&
        beam_ipc_parse_status(reply, reply_len, &status))
        reachable = TRUE;

    EnterCriticalSection(&g_lock);
    g_reachable = reachable;
    if (reachable)
        g_status = status;
    LeaveCriticalSection(&g_lock);

    PostMessageW(g_window, WM_IPC_STATUS, 0, 0);
}

static DWORD WINAPI ipc_worker(LPVOID param)
{
    BOOL first = TRUE;

    UNREFERENCED_PARAMETER(param);

    for (;;) {
        if (InterlockedCompareExchange(&g_worker_stop, 0, 0) != 0)
            break;

        if (!first)
            WaitForSingleObject(g_worker_wake, IPC_POLL_MS);
        first = FALSE;

        if (InterlockedCompareExchange(&g_worker_stop, 0, 0) != 0)
            break;

        drain_commands();
        poll_status();
    }

    return 0;
}

/* --- User actions ------------------------------------------------------- */

static void send_command(CommandKind kind, const char *line)
{
    if (!queue_push(kind, line)) {
        MessageBoxW(g_window, L"The tray is busy. Try again.", APP_TITLE,
                    MB_OK | MB_ICONWARNING);
        return;
    }
    if (g_worker_wake)
        SetEvent(g_worker_wake);
}

static void open_config_admin(void)
{
    SHELLEXECUTEINFOW info;
    wchar_t parameters[MAX_PATH * 2 + 2];

    if (g_config_path[0] == L'\0' ||
        GetFileAttributesW(g_config_path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_window,
                    L"No config file yet. Use \"Import vless:// link...\" first.",
                    APP_TITLE, MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (FAILED(StringCchPrintfW(parameters, ARRAYSIZE(parameters), L"\"%s\"",
                                g_config_path))) {
        MessageBoxW(g_window, L"Cannot build the config path.", APP_TITLE,
                    MB_OK | MB_ICONERROR);
        return;
    }

    ZeroMemory(&info, sizeof info);
    info.cbSize = sizeof info;
    info.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    info.hwnd = g_window;
    info.lpVerb = L"runas";
    info.lpFile = L"notepad.exe";
    info.lpParameters = parameters;
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info) && GetLastError() != ERROR_CANCELLED)
        MessageBoxW(g_window, L"Cannot open the config file.", APP_TITLE,
                    MB_OK | MB_ICONERROR);
}

static void open_log(void)
{
    HINSTANCE result;

    if (g_log_path[0] == L'\0' ||
        GetFileAttributesW(g_log_path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_window, L"No log file yet.", APP_TITLE,
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    result = ShellExecuteW(g_window, L"open", g_log_path, NULL, NULL,
                           SW_SHOWNORMAL);
    if ((INT_PTR)result <= 32)
        MessageBoxW(g_window, L"Cannot open the log file.", APP_TITLE,
                    MB_OK | MB_ICONERROR);
}

static void show_menu(void)
{
    BeamIpcStatus status;
    BOOL reachable = FALSE;
    HMENU menu;
    POINT point;
    wchar_t text[1024];
    wchar_t detail[256];
    TrayState state = g_tray_state;
    BOOL restart;

    if (!g_window)
        return;

    snapshot_status(&status, &reachable);

    menu = CreatePopupMenu();
    if (!menu)
        return;

    tray_text(&status, state, text, ARRAYSIZE(text));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_STATUS, text);

    if (status.server[0] != '\0' &&
        utf8_to_wide(status.server, detail, ARRAYSIZE(detail)) &&
        detail[0] != L'\0') {
        StringCchPrintfW(text, ARRAYSIZE(text), L"Server: %s", detail);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_SERVER, text);
    }

    if (status.drops[0] != '\0' &&
        utf8_to_wide(status.drops, detail, ARRAYSIZE(detail)) &&
        detail[0] != L'\0') {
        StringCchPrintfW(text, ARRAYSIZE(text), L"Drops: %s", detail);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_DROPS, text);
    }

    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu,
                MF_STRING | (beam_tray_can_connect(state) ? MF_ENABLED
                                                          : MF_GRAYED),
                IDM_CONNECT, L"Connect");
    AppendMenuW(menu,
                MF_STRING | (beam_tray_can_disconnect(state) ? MF_ENABLED
                                                             : MF_GRAYED),
                IDM_DISCONNECT, L"Disconnect");

    restart = reachable && state != TRAY_STATE_STOPPING;
    AppendMenuW(menu, MF_STRING | (restart ? MF_ENABLED : MF_GRAYED),
                IDM_RESTART, L"Restart");

    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_IMPORT, L"Import vless:// link...");
    AppendMenuW(menu, MF_STRING, IDM_CONFIG, L"Open Config (Admin)...");
    AppendMenuW(menu, MF_STRING, IDM_LOG, L"Open Log");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_EXIT, L"Exit Tray");

    GetCursorPos(&point);
    SetForegroundWindow(g_window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_TOPALIGN,
                   point.x, point.y, 0, g_window, NULL);
    PostMessageW(g_window, WM_NULL, 0, 0);

    DestroyMenu(menu);
}

/* --- Import dialog ------------------------------------------------------ */

static BOOL import_link_from_dialog(HWND dialog)
{
    wchar_t wide[IMPORT_MAX_WIDE];
    char utf8[IMPORT_MAX_UTF8];
    char command[IPC_CMD_MAX];
    BOOL queued = FALSE;

    wide[0] = L'\0';
    utf8[0] = '\0';
    command[0] = '\0';

    if (GetDlgItemTextW(dialog, IDC_LINK_EDIT, wide, ARRAYSIZE(wide)) <= 0) {
        MessageBoxW(dialog, L"Paste a vless:// link first.", APP_TITLE,
                    MB_OK | MB_ICONINFORMATION);
        return FALSE;
    }

    if (!wide_to_utf8(wide, utf8, sizeof utf8)) {
        MessageBoxW(dialog, L"That link is too long.", APP_TITLE,
                    MB_OK | MB_ICONWARNING);
    } else if (!beam_ipc_prepare_import_link(utf8, command, sizeof command)) {
        MessageBoxW(dialog, L"That is not a valid vless:// link.", APP_TITLE,
                    MB_OK | MB_ICONWARNING);
    } else if (!queue_push(CMD_IMPORT, command)) {
        MessageBoxW(dialog, L"The tray is busy. Try again.", APP_TITLE,
                    MB_OK | MB_ICONWARNING);
    } else {
        queued = TRUE;
    }

    /* The link may carry a UUID and keys; drop it from our stack at once. */
    SetDlgItemTextW(dialog, IDC_LINK_EDIT, L"");
    SecureZeroMemory(wide, sizeof wide);
    SecureZeroMemory(utf8, sizeof utf8);
    SecureZeroMemory(command, sizeof command);

    if (queued && g_worker_wake)
        SetEvent(g_worker_wake);

    return queued;
}

static INT_PTR CALLBACK import_dialog_proc(HWND dialog, UINT msg,
                                           WPARAM wparam, LPARAM lparam)
{
    UNREFERENCED_PARAMETER(lparam);

    switch (msg) {
    case WM_INITDIALOG: {
        HWND edit = GetDlgItem(dialog, IDC_LINK_EDIT);
        if (edit) {
            SendMessageW(edit, EM_SETLIMITTEXT, (WPARAM)(IMPORT_MAX_WIDE - 1), 0);
            SetFocus(edit);
        }
        return FALSE;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDOK:
            if (import_link_from_dialog(dialog))
                EndDialog(dialog, IDOK);
            return TRUE;
        case IDCANCEL:
            SetDlgItemTextW(dialog, IDC_LINK_EDIT, L"");
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        default:
            return FALSE;
        }
    default:
        return FALSE;
    }
}

static BOOL g_import_open = FALSE;

static void open_import_dialog(void)
{
    if (g_import_open)
        return;
    g_import_open = TRUE;
    DialogBoxW(g_instance, MAKEINTRESOURCEW(IDD_IMPORT_LINK), g_window,
               import_dialog_proc);
    g_import_open = FALSE;
}

/* --- UI messages -------------------------------------------------------- */

static void on_ipc_status(void)
{
    BeamIpcStatus status;
    BOOL reachable = FALSE;
    TrayState state;

    snapshot_status(&status, &reachable);
    state = reachable ? beam_ipc_derive_tray_state(&status)
                      : TRAY_STATE_UNAVAILABLE;
    apply_state(state, &status);
}

static void on_command_done(CommandKind kind, BOOL ok)
{
    char error[256];
    wchar_t detail[512];
    wchar_t text[768];

    if (ok) {
        if (kind == CMD_IMPORT)
            MessageBoxW(g_window,
                        L"vless:// link imported. Use Connect if the tunnel is stopped.",
                        APP_TITLE, MB_OK | MB_ICONINFORMATION);
        return;
    }

    EnterCriticalSection(&g_lock);
    StringCchCopyA(error, ARRAYSIZE(error), g_cmd_err);
    LeaveCriticalSection(&g_lock);
    error[ARRAYSIZE(error) - 1] = '\0';

    detail[0] = L'\0';
    if (error[0] != '\0')
        (void)utf8_to_wide(error, detail, ARRAYSIZE(detail));
    if (detail[0] == L'\0')
        StringCchCopyW(detail, ARRAYSIZE(detail), L"the service returned an error");

    if (kind == CMD_IMPORT) {
        StringCchPrintfW(text, ARRAYSIZE(text), L"Import failed.\n\n%s", detail);
    } else {
        StringCchPrintfW(text, ARRAYSIZE(text), L"Command failed.\n\n%s", detail);
    }
    MessageBoxW(g_window, text, APP_TITLE, MB_OK | MB_ICONWARNING);
}

static void handle_command(int id)
{
    switch (id) {
    case IDM_CONNECT:
        send_command(CMD_CONNECT, "CONNECT");
        break;
    case IDM_DISCONNECT:
        send_command(CMD_DISCONNECT, "DISCONNECT");
        break;
    case IDM_RESTART:
        send_command(CMD_RESTART, "RESTART");
        break;
    case IDM_IMPORT:
        open_import_dialog();
        break;
    case IDM_CONFIG:
        open_config_admin();
        break;
    case IDM_LOG:
        open_log();
        break;
    case IDM_EXIT:
        DestroyWindow(g_window);
        break;
    default:
        break;
    }
}

static void shutdown_tray(void)
{
    tray_remove();

    InterlockedExchange(&g_worker_stop, 1);
    if (g_worker_wake)
        SetEvent(g_worker_wake);
    if (g_worker_thread) {
        /* Wait until the bounded IPC worker exits so DeleteCriticalSection in
         * WinMain can never race with a live thread. */
        WaitForSingleObject(g_worker_thread, INFINITE);
        CloseHandle(g_worker_thread);
        g_worker_thread = NULL;
    }

    queue_clear();
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam,
                                    LPARAM lparam)
{
    if (g_msg_taskbar_created != 0 && msg == g_msg_taskbar_created) {
        g_tray_added = FALSE;
        tray_add();
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        tray_add();
        g_worker_thread = CreateThread(NULL, 0, ipc_worker, NULL, 0, NULL);
        if (!g_worker_thread)
            MessageBoxW(hwnd, L"Cannot start the IPC worker thread.",
                        APP_TITLE, MB_OK | MB_ICONERROR);
        return 0;

    case WM_TRAY_MSG:
        if (g_import_open)
            return 0;
        switch (LOWORD(lparam)) {
        case WM_LBUTTONUP:
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
        case WM_LBUTTONDBLCLK:
            show_menu();
            break;
        default:
            break;
        }
        return 0;

    case WM_COMMAND:
        handle_command((int)LOWORD(wparam));
        return 0;

    case WM_IPC_STATUS:
        on_ipc_status();
        return 0;

    case WM_IPC_CMD_DONE:
        on_command_done((CommandKind)wparam, lparam != 0 ? TRUE : FALSE);
        return 0;

    case WM_POWERBROADCAST:
        if (wparam == PBT_APMRESUMEAUTOMATIC ||
            wparam == PBT_APMRESUMESUSPEND ||
            wparam == PBT_APMRESUMECRITICAL) {
            if (g_worker_wake)
                SetEvent(g_worker_wake);
        }
        return TRUE;

    case WM_ENDSESSION:
        if (wparam) {
            /* Do not block logoff/shutdown waiting on the worker thread;
             * remove the tray icon and let Windows tear down the process. */
            tray_remove();
        }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        shutdown_tray();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

static BOOL has_stop_flag(void)
{
    int argc = 0;
    int i;
    LPWSTR *argv;
    BOOL found = FALSE;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return FALSE;

    for (i = 1; i < argc; ++i) {
        if (lstrcmpiW(argv[i], L"--stop") == 0) {
            found = TRUE;
            break;
        }
    }

    LocalFree(argv);
    return found;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line,
                   int show)
{
    WNDCLASSEXW window_class;
    MSG msg;
    HANDLE mutex;

    UNREFERENCED_PARAMETER(previous);
    UNREFERENCED_PARAMETER(command_line);
    UNREFERENCED_PARAMETER(show);

    if (has_stop_flag()) {
        HWND existing = FindWindowW(TRAY_CLASS, NULL);
        if (existing)
            PostMessageW(existing, WM_CLOSE, 0, 0);
        return 0;
    }

    mutex = CreateMutexW(NULL, FALSE, TRAY_MUTEX);
    if (!mutex)
        return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    InitializeCriticalSection(&g_lock);
    resolve_paths();
    g_instance = instance;
    load_icons(instance);

    g_worker_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_worker_wake)
        goto fail;

    g_msg_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");

    ZeroMemory(&window_class, sizeof window_class);
    window_class.cbSize = sizeof window_class;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hIcon = g_icon_app;
    window_class.lpszClassName = TRAY_CLASS;
    if (!RegisterClassExW(&window_class))
        goto fail;

    g_window = CreateWindowExW(0, TRAY_CLASS, APP_TITLE, WS_OVERLAPPED,
                               0, 0, 0, 0, NULL, NULL, instance, NULL);
    if (!g_window)
        goto fail;

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(g_worker_wake);
    g_worker_wake = NULL;
    DeleteCriticalSection(&g_lock);
    CloseHandle(mutex);
    return 0;

fail:
    if (g_worker_wake) {
        CloseHandle(g_worker_wake);
        g_worker_wake = NULL;
    }
    DeleteCriticalSection(&g_lock);
    CloseHandle(mutex);
    return 1;
}
