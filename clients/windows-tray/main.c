/*
 * beam-tray: lightweight, event-driven Windows tray launcher for sing-box.
 *
 * It owns one process:
 *
 *     sing-box.exe run -c config.json
 *
 * TUN, DNS (e.g. sing-box 1.15+ built-in sing-tun stack + dns_mode/strict_route),
 * and routing stay in config.json. The tray reports real tunnel status by
 * combining process liveness with Windows IP Helper TUN adapter status
 * (IfOperStatusUp), using distinct multi-resolution icons for Disconnected,
 * Connecting/Stopping, Connected, and Error states.
 *
 * Build with clients/windows-tray/build.sh. The executable carries a
 * requireAdministrator manifest because the TUN inbound needs elevation.
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "tray_logic.h"

#define APP_TITLE              L"beam"
#define CORE_EXE               L"sing-box.exe"
#define CONFIG_JSON            L"config.json"
#define LOG_FILE               L"sing-box.log"
#define LOG_FILE_PREV          L"sing-box.log.1"
#define MUTEX_NAME             L"Global\\beam-sing-box-tray"

#define IDI_ICON_APP           1
#define IDI_TRAY_DISCONNECTED  101
#define IDI_TRAY_CONNECTING    102
#define IDI_TRAY_CONNECTED     103
#define IDI_TRAY_ERROR         104

#define WM_TRAY_MSG            (WM_APP + 1)
#define WM_CORE_EXITED         (WM_APP + 2)
#define WM_IFACE_CHANGED       (WM_APP + 3)

#define TIMER_CONNECT_WATCH    1
#define TIMER_STOP_GRACE       2
#define TIMER_COOLDOWN         3

#define CONNECT_POLL_MS        1000
#define CONNECT_TIMEOUT_MS     15000
#define STOP_GRACE_MS          5000
#define SHUTDOWN_GRACE_MS      4000
#define COOLDOWN_MS            1500
#define CONFIG_CHECK_TIMEOUT   5000
#define MAX_LOG_BYTES          (2UL * 1024UL * 1024UL)
#define MAX_CONFIG_READ_BYTES  (256UL * 1024UL)

#define IDM_STATUS             1000
#define IDM_START              1001
#define IDM_STOP               1002
#define IDM_RESTART            1003
#define IDM_CONFIG             1004
#define IDM_LOG                1005
#define IDM_EXIT               1006
#define IDM_TRAY               1

static HWND      g_window;
static HICON     g_icon_app;
static HICON     g_icon_disconnected;
static HICON     g_icon_connecting;
static HICON     g_icon_connected;
static HICON     g_icon_error;
static UINT      g_taskbar_created;
static BOOL      g_tray_added;

static HANDLE    g_process;
static HANDLE    g_process_wait;
static HANDLE    g_job;
static HANDLE    g_iface_notify;

static TrayState g_state = TRAY_STATE_DISCONNECTED;
static DWORD     g_last_exit_code;
static wchar_t   g_error_detail[128];
static ULONGLONG g_connect_started_ms;
static BOOL      g_stopping;
static BOOL      g_restart_pending;
static BOOL      g_exit_pending;
static BOOL      g_cooldown;

static wchar_t   g_dir[MAX_PATH];
static wchar_t   g_core[MAX_PATH];
static wchar_t   g_config[MAX_PATH];
static wchar_t   g_log[MAX_PATH];
static wchar_t   g_log_prev[MAX_PATH];
static wchar_t   g_tun_name[128];

static void show_error(const wchar_t *what)
{
    wchar_t text[1024];
    DWORD error = GetLastError();
    wchar_t *system_text = NULL;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, 0, (LPWSTR)&system_text, 0, NULL);

    _snwprintf(text, ARRAYSIZE(text), L"%s\n\n%s (error %lu)",
               what, system_text ? system_text : L"unknown error",
               (unsigned long)error);
    text[ARRAYSIZE(text) - 1] = L'\0';

    if (system_text)
        LocalFree(system_text);

    MessageBoxW(NULL, text, APP_TITLE, MB_OK | MB_ICONERROR);
}

static BOOL file_exists(const wchar_t *path)
{
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static void resolve_paths(void)
{
    DWORD length = GetModuleFileNameW(NULL, g_dir, ARRAYSIZE(g_dir));

    if (length == 0 || length >= ARRAYSIZE(g_dir)) {
        g_dir[0] = L'\0';
    } else {
        while (length > 0 && g_dir[length - 1] != L'\\' &&
               g_dir[length - 1] != L'/') {
            --length;
        }
        g_dir[length] = L'\0';
    }

    _snwprintf(g_core, ARRAYSIZE(g_core), L"%s%s", g_dir, CORE_EXE);
    _snwprintf(g_config, ARRAYSIZE(g_config), L"%s%s", g_dir, CONFIG_JSON);
    _snwprintf(g_log, ARRAYSIZE(g_log), L"%s%s", g_dir, LOG_FILE);
    _snwprintf(g_log_prev, ARRAYSIZE(g_log_prev), L"%s%s", g_dir, LOG_FILE_PREV);

    g_core[ARRAYSIZE(g_core) - 1] = L'\0';
    g_config[ARRAYSIZE(g_config) - 1] = L'\0';
    g_log[ARRAYSIZE(g_log) - 1] = L'\0';
    g_log_prev[ARRAYSIZE(g_log_prev) - 1] = L'\0';
}

static BOOL wcs_contains_ascii_ci(const wchar_t *haystack, const wchar_t *needle)
{
    size_t nlen = wcslen(needle);
    if (nlen == 0)
        return TRUE;
    for (; *haystack != L'\0'; ++haystack) {
        if (_wcsnicmp(haystack, needle, nlen) == 0)
            return TRUE;
    }
    return FALSE;
}

static void load_tun_name_from_config(void)
{
    HANDLE file;
    LARGE_INTEGER size;
    char *buf;
    DWORD read_bytes = 0;
    char utf8_name[128];

    g_tun_name[0] = L'\0';

    file = CreateFileW(g_config, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;

    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        (ULONGLONG)size.QuadPart > MAX_CONFIG_READ_BYTES) {
        CloseHandle(file);
        return;
    }

    buf = (char *)malloc((size_t)size.QuadPart);
    if (!buf) {
        CloseHandle(file);
        return;
    }

    if (ReadFile(file, buf, (DWORD)size.QuadPart, &read_bytes, NULL) &&
        read_bytes > 0) {
        if (extract_tun_interface_name(buf, (size_t)read_bytes,
                                       utf8_name, sizeof(utf8_name))) {
            int written = MultiByteToWideChar(CP_UTF8, 0, utf8_name, -1,
                                              g_tun_name, ARRAYSIZE(g_tun_name));
            if (written <= 0)
                g_tun_name[0] = L'\0';
        }
    }

    free(buf);
    CloseHandle(file);
}

static BOOL is_tun_interface_up(void)
{
    PMIB_IF_TABLE2 table = NULL;
    BOOL found = FALSE;
    ULONG i;

    if (GetIfTable2(&table) != NO_ERROR || !table)
        return FALSE;

    for (i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2 *row = &table->Table[i];
        if (row->OperStatus != IfOperStatusUp)
            continue;

        if (g_tun_name[0] != L'\0') {
            if (_wcsicmp(row->Alias, g_tun_name) == 0) {
                found = TRUE;
                break;
            }
        } else {
            if (wcs_contains_ascii_ci(row->Description, L"Wintun") ||
                wcs_contains_ascii_ci(row->Alias, L"sing-tun") ||
                wcs_contains_ascii_ci(row->Alias, L"beam-tun")) {
                found = TRUE;
                break;
            }
        }
    }

    FreeMibTable(table);
    return found;
}

static HICON load_tray_icon_resource(HINSTANCE instance, UINT id, int cx, int cy)
{
    HICON icon = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(id), IMAGE_ICON,
                                   cx, cy, LR_DEFAULTCOLOR);
    if (!icon)
        icon = LoadIconW(instance, MAKEINTRESOURCEW(id));
    return icon;
}

static void load_icons(HINSTANCE instance)
{
    int cx = GetSystemMetrics(SM_CXSMICON);
    int cy = GetSystemMetrics(SM_CYSMICON);
    if (cx <= 0)
        cx = 16;
    if (cy <= 0)
        cy = 16;

    g_icon_app = LoadIconW(instance, MAKEINTRESOURCEW(IDI_ICON_APP));
    if (!g_icon_app)
        g_icon_app = LoadIconW(NULL, IDI_APPLICATION);

    g_icon_disconnected = load_tray_icon_resource(instance, IDI_TRAY_DISCONNECTED, cx, cy);
    g_icon_connecting   = load_tray_icon_resource(instance, IDI_TRAY_CONNECTING, cx, cy);
    g_icon_connected    = load_tray_icon_resource(instance, IDI_TRAY_CONNECTED, cx, cy);
    g_icon_error        = load_tray_icon_resource(instance, IDI_TRAY_ERROR, cx, cy);
}

static void destroy_icons(void)
{
    if (g_icon_disconnected) { DestroyIcon(g_icon_disconnected); g_icon_disconnected = NULL; }
    if (g_icon_connecting)   { DestroyIcon(g_icon_connecting);   g_icon_connecting = NULL; }
    if (g_icon_connected)    { DestroyIcon(g_icon_connected);    g_icon_connected = NULL; }
    if (g_icon_error)        { DestroyIcon(g_icon_error);        g_icon_error = NULL; }
}

static HICON icon_for_state(TrayState state)
{
    HICON icon = NULL;
    switch (state) {
    case TRAY_STATE_CONNECTED:
        icon = g_icon_connected;
        break;
    case TRAY_STATE_CONNECTING:
    case TRAY_STATE_STOPPING:
        icon = g_icon_connecting;
        break;
    case TRAY_STATE_ERROR:
        icon = g_icon_error;
        break;
    case TRAY_STATE_DISCONNECTED:
    default:
        icon = g_icon_disconnected;
        break;
    }
    return icon ? icon : g_icon_app;
}

static void tray_text(wchar_t *tip, size_t count)
{
    switch (g_state) {
    case TRAY_STATE_CONNECTED:
        if (g_tun_name[0] != L'\0')
            _snwprintf(tip, count, L"%s: Connected (%s up)", APP_TITLE, g_tun_name);
        else
            _snwprintf(tip, count, L"%s: Connected (TUN up)", APP_TITLE);
        break;
    case TRAY_STATE_CONNECTING:
        _snwprintf(tip, count, L"%s: Connecting (waiting for TUN)...", APP_TITLE);
        break;
    case TRAY_STATE_STOPPING:
        _snwprintf(tip, count, L"%s: Disconnecting...", APP_TITLE);
        break;
    case TRAY_STATE_ERROR:
        if (g_error_detail[0] != L'\0')
            _snwprintf(tip, count, L"%s: Error (%s)", APP_TITLE, g_error_detail);
        else
            _snwprintf(tip, count, L"%s: Error (exit %lu)", APP_TITLE,
                       (unsigned long)g_last_exit_code);
        break;
    case TRAY_STATE_DISCONNECTED:
    default:
        _snwprintf(tip, count, L"%s: Disconnected", APP_TITLE);
        break;
    }
    tip[count - 1] = L'\0';
}

static void tray_add(void)
{
    NOTIFYICONDATAW nid;
    wchar_t tip[128];

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY_MSG;
    nid.hIcon = icon_for_state(g_state);

    tray_text(tip, ARRAYSIZE(tip));
    lstrcpynW(nid.szTip, tip, ARRAYSIZE(nid.szTip));

    if (Shell_NotifyIconW(NIM_ADD, &nid))
        g_tray_added = TRUE;
}

static void tray_update(void)
{
    NOTIFYICONDATAW nid;
    wchar_t tip[128];

    if (!g_tray_added)
        return;

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    nid.uFlags = NIF_ICON | NIF_TIP;
    nid.hIcon = icon_for_state(g_state);

    tray_text(tip, ARRAYSIZE(tip));
    lstrcpynW(nid.szTip, tip, ARRAYSIZE(nid.szTip));

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void tray_notify_error(const wchar_t *body)
{
    NOTIFYICONDATAW nid;

    if (!g_tray_added || !body)
        return;

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_ERROR;
    lstrcpynW(nid.szInfoTitle, L"beam disconnected", ARRAYSIZE(nid.szInfoTitle));
    lstrcpynW(nid.szInfo, body, ARRAYSIZE(nid.szInfo));

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void tray_remove(void)
{
    NOTIFYICONDATAW nid;

    if (!g_tray_added)
        return;

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_window;
    nid.uID = IDM_TRAY;

    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_tray_added = FALSE;
}

static void set_state(TrayState next)
{
    if (g_state != next) {
        g_state = next;
        tray_update();
    }
}

static void start_cooldown(void)
{
    g_cooldown = TRUE;
    SetTimer(g_window, TIMER_COOLDOWN, COOLDOWN_MS, NULL);
}

static void rotate_log_if_needed(void)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONGLONG size;

    if (!GetFileAttributesExW(g_log, GetFileExInfoStandard, &fad))
        return;

    size = ((ULONGLONG)fad.nFileSizeHigh << 32) | (ULONGLONG)fad.nFileSizeLow;
    if (size >= MAX_LOG_BYTES)
        MoveFileExW(g_log, g_log_prev, MOVEFILE_REPLACE_EXISTING);
}

static BOOL check_config_valid(void)
{
    wchar_t command[2 * MAX_PATH + 64];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait_res;
    DWORD exit_code = 1;

    if (!file_exists(g_core) || !file_exists(g_config))
        return FALSE;

    _snwprintf(command, ARRAYSIZE(command), L"\"%s\" check -c \"%s\"",
               g_core, g_config);
    command[ARRAYSIZE(command) - 1] = L'\0';

    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    ZeroMemory(&process, sizeof(process));
    if (!CreateProcessW(g_core, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, g_dir, &startup, &process)) {
        return FALSE;
    }

    wait_res = WaitForSingleObject(process.hProcess, CONFIG_CHECK_TIMEOUT);
    if (wait_res == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &exit_code);
    } else {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 1000);
        exit_code = 1;
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exit_code == 0;
}

static void CALLBACK on_process_exit_cb(PVOID param, BOOLEAN timed_out)
{
    (void)param;
    (void)timed_out;
    if (g_window)
        PostMessageW(g_window, WM_CORE_EXITED, 0, 0);
}

static void NETIOAPI_API_ on_ip_interface_change_cb(
    PVOID caller_context, PMIB_IPINTERFACE_ROW row,
    MIB_NOTIFICATION_TYPE notification_type)
{
    (void)caller_context;
    (void)row;
    (void)notification_type;
    if (g_window)
        PostMessageW(g_window, WM_IFACE_CHANGED, 0, 0);
}

static void unregister_process_wait(BOOL blocking)
{
    if (g_process_wait) {
        UnregisterWaitEx(g_process_wait, blocking ? INVALID_HANDLE_VALUE : NULL);
        g_process_wait = NULL;
    }
}

static void release_process_handles(void)
{
    unregister_process_wait(FALSE);

    if (g_process) {
        CloseHandle(g_process);
        g_process = NULL;
    }

    if (g_job) {
        CloseHandle(g_job);
        g_job = NULL;
    }
}

static BOOL WINAPI ignore_ctrl_handler(DWORD ctrl_type)
{
    (void)ctrl_type;
    return TRUE;
}

static BOOL send_graceful_stop_signal(HANDLE process)
{
    DWORD pid = GetProcessId(process);
    BOOL signalled = FALSE;

    if (pid == 0)
        return FALSE;

    FreeConsole();
    if (AttachConsole(pid)) {
        SetConsoleCtrlHandler(ignore_ctrl_handler, TRUE);
        signalled = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0;
        if (!signalled)
            signalled = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) != 0;
        if (signalled)
            Sleep(50);
        FreeConsole();
        SetConsoleCtrlHandler(ignore_ctrl_handler, FALSE);
    }
    return signalled;
}

static BOOL start_core(void)
{
    wchar_t command[2 * MAX_PATH + 64];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    SECURITY_ATTRIBUTES security;
    HANDLE log_file = INVALID_HANDLE_VALUE;
    HANDLE nul_file = INVALID_HANDLE_VALUE;
    BOOL inherit_handles = FALSE;

    if (g_process) {
        tray_update();
        return TRUE;
    }

    if (!file_exists(g_core)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        lstrcpynW(g_error_detail, L"sing-box.exe missing", ARRAYSIZE(g_error_detail));
        set_state(TRAY_STATE_ERROR);
        show_error(L"sing-box.exe was not found next to beam-tray.exe.");
        return FALSE;
    }

    if (!file_exists(g_config)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        lstrcpynW(g_error_detail, L"config.json missing", ARRAYSIZE(g_error_detail));
        set_state(TRAY_STATE_ERROR);
        show_error(L"config.json was not found next to beam-tray.exe.");
        return FALSE;
    }

    load_tun_name_from_config();
    rotate_log_if_needed();

    _snwprintf(command, ARRAYSIZE(command), L"\"%s\" run -c \"%s\"",
               g_core, g_config);
    command[ARRAYSIZE(command) - 1] = L'\0';

    ZeroMemory(&security, sizeof(security));
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    log_file = CreateFileW(g_log, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    nul_file = CreateFileW(L"NUL", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                           OPEN_EXISTING, 0, NULL);

    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);

    if (log_file != INVALID_HANDLE_VALUE && nul_file != INVALID_HANDLE_VALUE) {
        SetFilePointer(log_file, 0, NULL, FILE_END);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = nul_file;
        startup.hStdOutput = log_file;
        startup.hStdError = log_file;
        inherit_handles = TRUE;
    }

    ZeroMemory(&process, sizeof(process));

    startup.dwFlags |= STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    if (!CreateProcessW(g_core, command, NULL, NULL, inherit_handles,
                        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                        NULL, g_dir, &startup, &process)) {
        DWORD error = GetLastError();

        if (log_file != INVALID_HANDLE_VALUE)
            CloseHandle(log_file);
        if (nul_file != INVALID_HANDLE_VALUE)
            CloseHandle(nul_file);

        lstrcpynW(g_error_detail, L"launch failed", ARRAYSIZE(g_error_detail));
        set_state(TRAY_STATE_ERROR);
        SetLastError(error);
        show_error(L"Could not start sing-box.exe.");
        return FALSE;
    }

    g_job = CreateJobObjectW(NULL, NULL);
    if (g_job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;

        ZeroMemory(&limits, sizeof(limits));
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        if (!SetInformationJobObject(g_job, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(g_job, process.hProcess)) {
            CloseHandle(g_job);
            g_job = NULL;
        }
    }

    if (ResumeThread(process.hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (g_job) {
            CloseHandle(g_job);
            g_job = NULL;
        }
        if (log_file != INVALID_HANDLE_VALUE)
            CloseHandle(log_file);
        if (nul_file != INVALID_HANDLE_VALUE)
            CloseHandle(nul_file);
        lstrcpynW(g_error_detail, L"resume failed", ARRAYSIZE(g_error_detail));
        set_state(TRAY_STATE_ERROR);
        SetLastError(error);
        show_error(L"Could not resume sing-box.exe.");
        return FALSE;
    }
    CloseHandle(process.hThread);

    if (log_file != INVALID_HANDLE_VALUE)
        CloseHandle(log_file);
    if (nul_file != INVALID_HANDLE_VALUE)
        CloseHandle(nul_file);

    g_process = process.hProcess;
    g_stopping = FALSE;
    g_restart_pending = FALSE;
    g_exit_pending = FALSE;
    g_last_exit_code = 0;
    g_error_detail[0] = L'\0';
    g_connect_started_ms = GetTickCount64();

    if (!RegisterWaitForSingleObject(&g_process_wait, g_process,
                                     on_process_exit_cb, NULL, INFINITE,
                                     WT_EXECUTEONLYONCE)) {
        g_process_wait = NULL;
    }

    start_cooldown();
    if (is_tun_interface_up()) {
        set_state(TRAY_STATE_CONNECTED);
    } else {
        set_state(TRAY_STATE_CONNECTING);
        SetTimer(g_window, TIMER_CONNECT_WATCH, CONNECT_POLL_MS, NULL);
    }
    return TRUE;
}

static void begin_stop_core(BOOL restart_after, BOOL exit_after)
{
    if (!g_process) {
        g_stopping = FALSE;
        g_restart_pending = FALSE;
        if (exit_after) {
            DestroyWindow(g_window);
        } else if (restart_after) {
            start_core();
        } else {
            set_state(TRAY_STATE_DISCONNECTED);
        }
        return;
    }

    KillTimer(g_window, TIMER_CONNECT_WATCH);
    g_stopping = TRUE;
    g_restart_pending = restart_after;
    g_exit_pending = exit_after;
    set_state(TRAY_STATE_STOPPING);
    start_cooldown();

    if (!send_graceful_stop_signal(g_process)) {
        TerminateProcess(g_process, 0);
    }

    SetTimer(g_window, TIMER_STOP_GRACE, STOP_GRACE_MS, NULL);
}

/*
 * Synchronous graceful stop used only on WM_ENDSESSION / WM_DESTROY so
 * sing-box has a bounded window to remove WFP filters and TUN DNS settings
 * before Windows terminates the process.
 */
static void stop_core_sync(DWORD grace_ms)
{
    KillTimer(g_window, TIMER_CONNECT_WATCH);
    KillTimer(g_window, TIMER_STOP_GRACE);

    if (g_process) {
        BOOL signalled;

        g_stopping = TRUE;
        unregister_process_wait(TRUE);

        signalled = send_graceful_stop_signal(g_process);
        if (!signalled || WaitForSingleObject(g_process, grace_ms) != WAIT_OBJECT_0) {
            TerminateProcess(g_process, 0);
            WaitForSingleObject(g_process, 2000);
        }

        CloseHandle(g_process);
        g_process = NULL;
    }

    if (g_job) {
        CloseHandle(g_job);
        g_job = NULL;
    }

    g_stopping = FALSE;
    g_restart_pending = FALSE;
    g_state = TRAY_STATE_DISCONNECTED;
}

static void refresh_tunnel_state(void)
{
    BOOL tun_up;
    TrayState next;

    if (!g_process || g_stopping)
        return;

    /* Fallback liveness check in case RegisterWaitForSingleObject failed. */
    if (WaitForSingleObject(g_process, 0) == WAIT_OBJECT_0) {
        PostMessageW(g_window, WM_CORE_EXITED, 0, 0);
        return;
    }

    tun_up = is_tun_interface_up();
    next = tray_state_on_tun_status(g_state, tun_up, g_process != NULL);

    if (next == TRAY_STATE_CONNECTED) {
        KillTimer(g_window, TIMER_CONNECT_WATCH);
        g_error_detail[0] = L'\0';
        set_state(TRAY_STATE_CONNECTED);
        return;
    }

    if (next == TRAY_STATE_CONNECTING) {
        if (g_state == TRAY_STATE_CONNECTED) {
            g_connect_started_ms = GetTickCount64();
            SetTimer(g_window, TIMER_CONNECT_WATCH, CONNECT_POLL_MS, NULL);
        }
        set_state(TRAY_STATE_CONNECTING);

        if (GetTickCount64() - g_connect_started_ms >= CONNECT_TIMEOUT_MS) {
            KillTimer(g_window, TIMER_CONNECT_WATCH);
            lstrcpynW(g_error_detail, L"TUN did not come up",
                      ARRAYSIZE(g_error_detail));
            set_state(TRAY_STATE_ERROR);
            tray_notify_error(L"TUN interface did not come up. Check sing-box.log.");
        }
    }
}

static void handle_core_exited(void)
{
    DWORD exit_code = 0;
    BOOL was_stopping = g_stopping;
    BOOL restart_after = g_restart_pending;
    BOOL exit_after = g_exit_pending;
    TrayState next;

    if (!g_process)
        return;

    /* Guard against spurious messages if the process is still running. */
    if (WaitForSingleObject(g_process, 0) != WAIT_OBJECT_0)
        return;

    GetExitCodeProcess(g_process, &exit_code);
    KillTimer(g_window, TIMER_CONNECT_WATCH);
    KillTimer(g_window, TIMER_STOP_GRACE);

    release_process_handles();

    g_stopping = FALSE;
    g_restart_pending = FALSE;
    g_exit_pending = FALSE;

    next = tray_state_on_process_exit(g_state, was_stopping);
    if (next == TRAY_STATE_ERROR) {
        wchar_t msg[128];
        g_last_exit_code = exit_code;
        _snwprintf(g_error_detail, ARRAYSIZE(g_error_detail),
                   L"sing-box exited (%lu)", (unsigned long)exit_code);
        g_error_detail[ARRAYSIZE(g_error_detail) - 1] = L'\0';
        set_state(TRAY_STATE_ERROR);

        _snwprintf(msg, ARRAYSIZE(msg),
                   L"sing-box exited unexpectedly (code %lu). Open sing-box.log for details.",
                   (unsigned long)exit_code);
        msg[ARRAYSIZE(msg) - 1] = L'\0';
        tray_notify_error(msg);
        return;
    }

    set_state(TRAY_STATE_DISCONNECTED);

    if (exit_after) {
        DestroyWindow(g_window);
    } else if (restart_after) {
        start_core();
    }
}

static void open_text_file(const wchar_t *path)
{
    wchar_t system_dir[MAX_PATH];
    wchar_t notepad[MAX_PATH];
    UINT length = GetSystemDirectoryW(system_dir, ARRAYSIZE(system_dir));
    HINSTANCE result;

    if (length == 0 || length >= ARRAYSIZE(system_dir)) {
        show_error(L"Could not locate the Windows system directory.");
        return;
    }

    _snwprintf(notepad, ARRAYSIZE(notepad), L"%s\\notepad.exe", system_dir);
    notepad[ARRAYSIZE(notepad) - 1] = L'\0';

    result = ShellExecuteW(NULL, L"open", notepad, path, NULL, SW_SHOWNORMAL);

    if ((INT_PTR)result <= 32)
        show_error(L"Could not open the file with Notepad.");
}

static void show_menu(void)
{
    HMENU menu;
    POINT point;
    int command;
    wchar_t status_label[128];
    BOOL alive     = g_process != NULL;
    BOOL can_start = !g_cooldown && tray_state_can_start(g_state, alive);
    BOOL can_stop  = !g_cooldown && tray_state_can_stop(g_state, alive);

    menu = CreatePopupMenu();
    if (!menu)
        return;

    tray_text(status_label, ARRAYSIZE(status_label));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_STATUS, status_label);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(menu, MF_STRING | (can_start ? 0 : MF_GRAYED),
                IDM_START, L"Connect");
    AppendMenuW(menu, MF_STRING | (can_stop ? 0 : MF_GRAYED),
                IDM_STOP, L"Disconnect");
    AppendMenuW(menu, MF_STRING | (can_stop ? 0 : MF_GRAYED),
                IDM_RESTART, L"Restart");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_CONFIG, L"Open config.json");
    AppendMenuW(menu, MF_STRING, IDM_LOG, L"Open sing-box.log");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, IDM_EXIT, L"Exit");

    GetCursorPos(&point);
    SetForegroundWindow(g_window);

    command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                             point.x, point.y, 0, g_window, NULL);

    DestroyMenu(menu);

    switch (command) {
    case IDM_START:
        start_core();
        break;
    case IDM_STOP:
        begin_stop_core(FALSE, FALSE);
        break;
    case IDM_RESTART:
        if (!check_config_valid()) {
            MessageBoxW(NULL,
                        L"config.json failed validation (`sing-box check`).\n\n"
                        L"Keeping the current connection running. Fix config.json and try again.",
                        APP_TITLE, MB_OK | MB_ICONWARNING);
            break;
        }
        begin_stop_core(TRUE, FALSE);
        break;
    case IDM_CONFIG:
        open_text_file(g_config);
        break;
    case IDM_LOG:
        open_text_file(g_log);
        break;
    case IDM_EXIT:
        begin_stop_core(FALSE, TRUE);
        break;
    default:
        break;
    }

    PostMessageW(g_window, WM_NULL, 0, 0);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam,
                                    LPARAM lparam)
{
    if (message == g_taskbar_created) {
        g_tray_added = FALSE;
        tray_add();
        return 0;
    }

    switch (message) {
    case WM_TRAY_MSG:
        if (lparam == WM_LBUTTONUP || lparam == WM_RBUTTONUP ||
            lparam == WM_CONTEXTMENU) {
            show_menu();
        }
        return 0;

    case WM_CORE_EXITED:
        handle_core_exited();
        return 0;

    case WM_IFACE_CHANGED:
        refresh_tunnel_state();
        return 0;

    case WM_POWERBROADCAST:
        if (wparam == PBT_APMRESUMEAUTOMATIC || wparam == PBT_APMRESUMESUSPEND)
            refresh_tunnel_state();
        return TRUE;

    case WM_TIMER:
        if (wparam == TIMER_CONNECT_WATCH) {
            refresh_tunnel_state();
        } else if (wparam == TIMER_STOP_GRACE) {
            KillTimer(window, TIMER_STOP_GRACE);
            if (g_process && g_stopping)
                TerminateProcess(g_process, 1);
        } else if (wparam == TIMER_COOLDOWN) {
            KillTimer(window, TIMER_COOLDOWN);
            g_cooldown = FALSE;
        }
        return 0;

    case WM_QUERYENDSESSION:
        return TRUE;

    case WM_ENDSESSION:
        if (wparam) {
            stop_core_sync(SHUTDOWN_GRACE_MS);
            tray_remove();
        }
        return 0;

    case WM_CLOSE:
        begin_stop_core(FALSE, TRUE);
        return 0;

    case WM_DESTROY:
        KillTimer(window, TIMER_CONNECT_WATCH);
        KillTimer(window, TIMER_STOP_GRACE);
        KillTimer(window, TIMER_COOLDOWN);
        if (g_iface_notify) {
            CancelMibChangeNotify2(g_iface_notify);
            g_iface_notify = NULL;
        }
        stop_core_sync(SHUTDOWN_GRACE_MS);
        tray_remove();
        destroy_icons();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line,
                   int show_command)
{
    WNDCLASSEXW window_class;
    MSG message;
    HANDLE mutex;
    (void)previous;
    (void)command_line;
    (void)show_command;

    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");

    if (command_line && strstr(command_line, "--stop") != NULL) {
        HWND existing = FindWindowW(L"BeamTrayWindow", NULL);
        if (existing)
            PostMessageW(existing, WM_CLOSE, 0, 0);
        return 0;
    }

    mutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    load_icons(instance);
    resolve_paths();

    ZeroMemory(&window_class, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hIcon = g_icon_app;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.lpszClassName = L"BeamTrayWindow";

    if (!RegisterClassExW(&window_class)) {
        show_error(L"Could not register the tray window class.");
        destroy_icons();
        if (mutex)
            CloseHandle(mutex);
        return 1;
    }

    g_window = CreateWindowExW(0, window_class.lpszClassName, APP_TITLE,
                               WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, instance,
                               NULL);
    if (!g_window) {
        show_error(L"Could not create the tray window.");
        destroy_icons();
        if (mutex)
            CloseHandle(mutex);
        return 1;
    }

    /* Explorer is medium-integrity; allow its callback and TaskbarCreated. */
    ChangeWindowMessageFilterEx(g_window, WM_TRAY_MSG, MSGFLT_ALLOW, NULL);
    if (g_taskbar_created)
        ChangeWindowMessageFilterEx(g_window, g_taskbar_created, MSGFLT_ALLOW, NULL);

    if (NotifyIpInterfaceChange(AF_INET, on_ip_interface_change_cb, NULL,
                                FALSE, &g_iface_notify) != NO_ERROR) {
        g_iface_notify = NULL;
    }

    tray_add();
    start_core();

    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (mutex)
        CloseHandle(mutex);

    return (int)message.wParam;
}
