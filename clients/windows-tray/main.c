/*
 * beam-tray: a deliberately tiny Windows tray launcher for sing-box.
 *
 * It owns one process:
 *
 *     sing-box.exe run -c config.json
 *
 * TUN, DNS, routing, and every other option stay in config.json. The tray
 * only provides start/stop/restart, open-config, open-log, and exit.
 *
 * Build with clients/windows-tray/build.sh. The executable carries a
 * requireAdministrator manifest because the TUN inbound needs elevation.
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

#define APP_TITLE       L"beam"
#define CORE_EXE        L"sing-box.exe"
#define CONFIG_JSON     L"config.json"
#define LOG_FILE        L"sing-box.log"
#define MUTEX_NAME      L"Local\\beam-sing-box-tray"

#define WM_TRAY_MSG     (WM_APP + 1)
#define TIMER_POLL      1

#define IDM_START       1001
#define IDM_STOP        1002
#define IDM_RESTART     1003
#define IDM_CONFIG      1004
#define IDM_LOG         1005
#define IDM_EXIT        1006
#define IDM_TRAY        1

static HWND      g_window;
static HICON     g_icon;
static UINT      g_taskbar_created;
static BOOL      g_tray_added;

static HANDLE    g_process;
static HANDLE    g_job;

static wchar_t   g_dir[MAX_PATH];
static wchar_t   g_core[MAX_PATH];
static wchar_t   g_config[MAX_PATH];
static wchar_t   g_log[MAX_PATH];

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

    g_core[ARRAYSIZE(g_core) - 1] = L'\0';
    g_config[ARRAYSIZE(g_config) - 1] = L'\0';
    g_log[ARRAYSIZE(g_log) - 1] = L'\0';
}

static void tray_text(wchar_t *tip, size_t count)
{
    const wchar_t *state = g_process ? L"running" : L"stopped";
    _snwprintf(tip, count, L"%s: sing-box %s", APP_TITLE, state);
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
    nid.hIcon = g_icon;

    tray_text(tip, ARRAYSIZE(tip));
    lstrcpynW(nid.szTip, tip, ARRAYSIZE(nid.szTip));

    if (Shell_NotifyIconW(NIM_ADD, &nid)) {
        g_tray_added = TRUE;
    }
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
    nid.uFlags = NIF_TIP;

    tray_text(tip, ARRAYSIZE(tip));
    lstrcpynW(nid.szTip, tip, ARRAYSIZE(nid.szTip));

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

static void process_stopped(void)
{
    if (g_process) {
        CloseHandle(g_process);
        g_process = NULL;
    }

    if (g_job) {
        CloseHandle(g_job);
        g_job = NULL;
    }

    tray_update();
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
        show_error(L"sing-box.exe was not found next to beam-tray.exe.");
        return FALSE;
    }

    if (!file_exists(g_config)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        show_error(L"config.json was not found next to beam-tray.exe.");
        return FALSE;
    }

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

    if (!CreateProcessW(g_core, command, NULL, NULL, inherit_handles,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, g_dir,
                        &startup, &process)) {
        DWORD error = GetLastError();

        if (log_file != INVALID_HANDLE_VALUE)
            CloseHandle(log_file);
        if (nul_file != INVALID_HANDLE_VALUE)
            CloseHandle(nul_file);

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

    ResumeThread(process.hThread);
    CloseHandle(process.hThread);

    if (log_file != INVALID_HANDLE_VALUE)
        CloseHandle(log_file);
    if (nul_file != INVALID_HANDLE_VALUE)
        CloseHandle(nul_file);

    g_process = process.hProcess;
    tray_update();
    return TRUE;
}

static void stop_core(void)
{
    if (g_process) {
        TerminateProcess(g_process, 0);
        WaitForSingleObject(g_process, 5000);
        CloseHandle(g_process);
        g_process = NULL;
    }

    if (g_job) {
        CloseHandle(g_job);
        g_job = NULL;
    }

    tray_update();
}

static void poll_core(void)
{
    DWORD exit_code;

    if (!g_process)
        return;

    if (WaitForSingleObject(g_process, 0) != WAIT_OBJECT_0)
        return;

    GetExitCodeProcess(g_process, &exit_code);
    process_stopped();
}

static void open_text_file(const wchar_t *path)
{
    HINSTANCE result = ShellExecuteW(NULL, L"open", L"notepad.exe", path,
                                     g_dir, SW_SHOWNORMAL);

    if ((INT_PTR)result <= 32)
        show_error(L"Could not open the file with Notepad.");
}

static void show_menu(void)
{
    HMENU menu;
    POINT point;
    int command;
    BOOL running = g_process != NULL;

    menu = CreatePopupMenu();
    if (!menu)
        return;

    AppendMenuW(menu, MF_STRING | (running ? MF_GRAYED : 0), IDM_START, L"Start");
    AppendMenuW(menu, MF_STRING | (running ? 0 : MF_GRAYED), IDM_STOP, L"Stop");
    AppendMenuW(menu, MF_STRING | (running ? 0 : MF_GRAYED), IDM_RESTART,
                L"Restart");
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
        stop_core();
        break;
    case IDM_RESTART:
        stop_core();
        start_core();
        break;
    case IDM_CONFIG:
        open_text_file(g_config);
        break;
    case IDM_LOG:
        open_text_file(g_log);
        break;
    case IDM_EXIT:
        DestroyWindow(g_window);
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
        if (lparam == WM_RBUTTONUP || lparam == WM_CONTEXTMENU)
            show_menu();
        else if (lparam == WM_LBUTTONDBLCLK)
            show_menu();
        return 0;

    case WM_TIMER:
        if (wparam == TIMER_POLL)
            poll_core();
        return 0;

    case WM_CLOSE:
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        KillTimer(window, TIMER_POLL);
        stop_core();
        tray_remove();
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
    g_icon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    if (!g_icon)
        g_icon = LoadIconW(NULL, IDI_APPLICATION);

    mutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    resolve_paths();

    ZeroMemory(&window_class, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hIcon = g_icon;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.lpszClassName = L"BeamTrayWindow";

    if (!RegisterClassExW(&window_class)) {
        show_error(L"Could not register the tray window class.");
        if (mutex)
            CloseHandle(mutex);
        return 1;
    }

    g_window = CreateWindowExW(0, window_class.lpszClassName, APP_TITLE,
                               WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, instance,
                               NULL);
    if (!g_window) {
        show_error(L"Could not create the tray window.");
        if (mutex)
            CloseHandle(mutex);
        return 1;
    }

    tray_add();
    SetTimer(g_window, TIMER_POLL, 1000, NULL);
    start_core();

    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (mutex)
        CloseHandle(mutex);

    return (int)message.wParam;
}
