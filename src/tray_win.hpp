#pragma once
#ifdef _WIN32

#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <shlobj.h>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <cstdio>

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_STATUS   1001
#define ID_TRAY_RESTART  1002
#define ID_TRAY_EXPORT   1003
#define ID_TRAY_BENCH    1004
#define ID_TRAY_LOGS     1005
#define ID_TRAY_QUIT     1006

namespace octane {

class TrayIcon {
    HWND hwnd_ = nullptr;
    NOTIFYICONDATAW nid_ = {};
    HICON hicon_ = nullptr;
    std::atomic<bool> server_running_{false};
    std::thread thread_;
    uint16_t port_;

public:
    TrayIcon(uint16_t port) : port_(port) {}

    void start() {
        thread_ = std::thread([this]() { run(); });
        thread_.detach();
    }

    void set_running(bool running) {
        server_running_ = running;
        if (hwnd_) {
            wcsncpy(nid_.szTip, running ? L"Octane Accelerator — Running" : L"Octane Accelerator — Stopped", 63);
            Shell_NotifyIconW(NIM_MODIFY, &nid_);
        }
    }

private:
    void run() {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = wnd_proc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = L"OctaneTrayClass";
        RegisterClassExW(&wc);

        hwnd_ = CreateWindowExW(0, L"OctaneTrayClass", L"Octane Tray", 0,
                                0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, this);

        // Load icon from exe resources
        hicon_ = LoadIconW(GetModuleHandle(nullptr), MAKEINTRESOURCEW(1));
        if (!hicon_) hicon_ = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));

        nid_.cbSize = sizeof(nid_);
        nid_.hWnd = hwnd_;
        nid_.uID = 1;
        nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid_.uCallbackMessage = WM_TRAYICON;
        nid_.hIcon = hicon_;
        wcsncpy(nid_.szTip, L"Octane Accelerator — Starting...", 63);
        Shell_NotifyIconW(NIM_ADD, &nid_);

        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        Shell_NotifyIconW(NIM_DELETE, &nid_);
    }

    void show_menu() {
        POINT pt;
        GetCursorPos(&pt);
        SetForegroundWindow(hwnd_);

        HMENU menu = CreatePopupMenu();

        // Status
        const wchar_t* status = server_running_ ? L"\x25CF Running" : L"\x25CB Stopped";
        AppendMenuW(menu, MF_STRING | MF_DISABLED, ID_TRAY_STATUS, status);
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(menu, MF_STRING, ID_TRAY_RESTART, L"Restart");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, ID_TRAY_EXPORT, L"Export Pairing File...");
        AppendMenuW(menu, MF_STRING, ID_TRAY_BENCH, L"Run Benchmark");
        AppendMenuW(menu, MF_STRING, ID_TRAY_LOGS, L"View Logs");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, ID_TRAY_QUIT, L"Quit Octane Accelerator");

        TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd_, nullptr);
        DestroyMenu(menu);
        PostMessage(hwnd_, WM_NULL, 0, 0);
    }

    void handle_command(WORD id) {
        switch (id) {
        case ID_TRAY_RESTART:
            // Server restarts itself — we just need to signal it
            // For now, the server doesn't support restart, so this is a no-op notification
            break;
        case ID_TRAY_EXPORT: {
            // Call the /pair/export endpoint and save to file
            std::thread([this]() {
                HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;
                // Use WinHTTP to hit localhost
                hSession = WinHttpOpen(L"OctaneTray", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
                if (!hSession) return;
                hConnect = WinHttpConnect(hSession, L"127.0.0.1", port_, 0);
                if (!hConnect) { WinHttpCloseHandle(hSession); return; }
                hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/pair/export", nullptr, nullptr, nullptr, 0);
                if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }
                WinHttpSendRequest(hRequest, nullptr, 0, nullptr, 0, 0, 0);
                WinHttpReceiveResponse(hRequest, nullptr);

                // Read response
                std::string body;
                DWORD size = 0;
                do {
                    WinHttpQueryDataAvailable(hRequest, &size);
                    if (size > 0) {
                        std::vector<char> buf(size);
                        DWORD read = 0;
                        WinHttpReadData(hRequest, buf.data(), size, &read);
                        body.append(buf.data(), read);
                    }
                } while (size > 0);

                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);

                if (body.empty()) return;

                // Save to user's home directory
                char home[MAX_PATH];
                SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, home);
                std::string path = std::string(home) + "\\.octane\\pairing.conf";
                FILE* f = fopen(path.c_str(), "w");
                if (f) {
                    fwrite(body.c_str(), 1, body.size(), f);
                    fclose(f);
                }

                // Open folder
                std::string dir = std::string(home) + "\\.octane";
                ShellExecuteA(nullptr, "open", dir.c_str(), nullptr, nullptr, SW_SHOW);
            }).detach();
            break;
        }
        case ID_TRAY_BENCH: {
            // Run benchmark and show result in a message box
            std::thread([this]() {
                HINTERNET hSession = WinHttpOpen(L"OctaneTray", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
                if (!hSession) return;
                HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", port_, 0);
                if (!hConnect) { WinHttpCloseHandle(hSession); return; }
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/benchmark", nullptr, nullptr, nullptr, 0);
                if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

                const char* bodyData = "{\"count\":1}";
                WinHttpSendRequest(hRequest, L"Content-Type: application/json", -1,
                                   (LPVOID)bodyData, (DWORD)strlen(bodyData), (DWORD)strlen(bodyData), 0);
                WinHttpReceiveResponse(hRequest, nullptr);

                std::string body;
                DWORD size = 0;
                do {
                    WinHttpQueryDataAvailable(hRequest, &size);
                    if (size > 0) {
                        std::vector<char> buf(size);
                        DWORD read = 0;
                        WinHttpReadData(hRequest, buf.data(), size, &read);
                        body.append(buf.data(), read);
                    }
                } while (size > 0);

                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);

                // Parse avg_ms from the last line
                std::string msg = "Benchmark complete.\n\n";
                auto pos = body.rfind("\"avg_ms\":");
                if (pos != std::string::npos) {
                    double avg = std::atof(body.c_str() + pos + 9);
                    char buf[128];
                    snprintf(buf, sizeof(buf), "Range proof: %.1f ms", avg);
                    msg += buf;
                } else {
                    msg += "Could not parse result.";
                }

                MessageBoxA(nullptr, msg.c_str(), "Octane Accelerator Benchmark", MB_OK | MB_ICONINFORMATION);
            }).detach();
            break;
        }
        case ID_TRAY_LOGS: {
            char home[MAX_PATH];
            SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, home);
            std::string logPath = std::string(home) + "\\.octane\\accelerator.log";
            ShellExecuteA(nullptr, "open", "notepad.exe", logPath.c_str(), nullptr, SW_SHOW);
            break;
        }
        case ID_TRAY_QUIT:
            Shell_NotifyIconW(NIM_DELETE, &nid_);
            PostQuitMessage(0);
            // Also kill the whole process
            ExitProcess(0);
            break;
        }
    }

    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        TrayIcon* self = nullptr;
        if (msg == WM_CREATE) {
            auto cs = reinterpret_cast<CREATESTRUCT*>(lp);
            self = static_cast<TrayIcon*>(cs->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<TrayIcon*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (self) {
            if (msg == WM_TRAYICON) {
                if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_LBUTTONUP) {
                    self->show_menu();
                }
                return 0;
            }
            if (msg == WM_COMMAND) {
                self->handle_command(LOWORD(wp));
                return 0;
            }
        }
        return DefWindowProc(hwnd, msg, wp, lp);
    }
};

} // namespace octane

#endif // _WIN32
