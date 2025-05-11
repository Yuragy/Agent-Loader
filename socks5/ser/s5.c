#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "ws2_32.lib")

typedef unsigned short uint16_t;

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

#define SERVER_USERNAME "admin"
#define SERVER_PASSWORD "password"

static void LogError(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static void LogInfo(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[INFO] ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
}

static int ReadExact(SOCKET sock, char* buffer, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, buffer + total, len - total, 0);
        if (n <= 0)
            return -1;
        total += n;
    }
    return total;
}

static int SendAll(SOCKET sock, const char* buffer, int len) {
    int total = 0;
    while (total < len) {
        int n = send(sock, buffer + total, len - total, 0);
        if (n == SOCKET_ERROR)
            return -1;
        total += n;
    }
    return total;
}

static const char* SockAddrToString(const struct sockaddr* sa, char* buf, size_t buf_len)
{
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)sa;
        inet_ntop(AF_INET, &(sin->sin_addr), buf, (socklen_t)buf_len);
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &(sin6->sin6_addr), buf, (socklen_t)buf_len);
    } else {
        strncpy(buf, "Unknown", buf_len);
    }
    return buf;
}

static BOOL SendSocksReply(SOCKET sock, UCHAR rep, const struct sockaddr* bnd_addr, int bnd_addr_len)
{
    char reply[256];
    int offset = 0;
    reply[offset++] = SOCKS5_VERSION;
    reply[offset++] = rep;
    reply[offset++] = 0x00; // RESERVED

    if (bnd_addr && bnd_addr->sa_family == AF_INET) {
        reply[offset++] = SOCKS_ADDR_IPV4;
        struct sockaddr_in* sin = (struct sockaddr_in*)bnd_addr;
        memcpy(reply + offset, &sin->sin_addr, 4);
        offset += 4;
        memcpy(reply + offset, &sin->sin_port, 2);
        offset += 2;
    } else if (bnd_addr && bnd_addr->sa_family == AF_INET6) {
        reply[offset++] = SOCKS_ADDR_IPV6;
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)bnd_addr;
        memcpy(reply + offset, &sin6->sin6_addr, 16);
        offset += 16;
        memcpy(reply + offset, &sin6->sin6_port, 2);
        offset += 2;
    } else {
        reply[offset++] = SOCKS_ADDR_IPV4;
        memset(reply + offset, 0, 4);
        offset += 4;
        memset(reply + offset, 0, 2);
        offset += 2;
    }
    if (SendAll(sock, reply, offset) != offset)
        return FALSE;
    return TRUE;
}

static BOOL ReadSocksAddress(SOCKET sock, UCHAR atyp, struct sockaddr_storage* addr, int* addr_len)
{
    memset(addr, 0, sizeof(struct sockaddr_storage));
    if (atyp == SOCKS_ADDR_IPV4) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        sin->sin_family = AF_INET;
        if (ReadExact(sock, (char*)&sin->sin_addr, 4) != 4)
            return FALSE;
        if (ReadExact(sock, (char*)&sin->sin_port, 2) != 2)
            return FALSE;
        *addr_len = sizeof(struct sockaddr_in);
        return TRUE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
        sin6->sin6_family = AF_INET6;
        if (ReadExact(sock, (char*)&sin6->sin6_addr, 16) != 16)
            return FALSE;
        if (ReadExact(sock, (char*)&sin6->sin6_port, 2) != 2)
            return FALSE;
        *addr_len = sizeof(struct sockaddr_in6);
        return TRUE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR domain_len;
        if (ReadExact(sock, (char*)&domain_len, 1) != 1)
            return FALSE;
        char domain[256];
        if (domain_len >= sizeof(domain))
            return FALSE;
        if (ReadExact(sock, domain, domain_len) != domain_len)
            return FALSE;
        domain[domain_len] = '\0';
        uint16_t port_net;
        if (ReadExact(sock, (char*)&port_net, 2) != 2)
            return FALSE;
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int err = getaddrinfo(domain, NULL, &hints, &res);
        if (err != 0 || res == NULL)
            return FALSE;
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *addr_len = (int)res->ai_addrlen;
        freeaddrinfo(res);
        if (((struct sockaddr*)addr)->sa_family == AF_INET) {
            ((struct sockaddr_in*)addr)->sin_port = port_net;
        } else if (((struct sockaddr*)addr)->sa_family == AF_INET6) {
            ((struct sockaddr_in6*)addr)->sin6_port = port_net;
        } else {
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

static void TcpRelay(SOCKET s1, SOCKET s2)
{
    char buffer[4096];
    fd_set fds;
    int maxfd = (int)((s1 > s2) ? s1 : s2);
    while (1) {
        FD_ZERO(&fds);
        FD_SET(s1, &fds);
        FD_SET(s2, &fds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int activity = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (activity == 0)
            continue;
        if (activity < 0)
            break;
        if (FD_ISSET(s1, &fds)) {
            int n = recv(s1, buffer, sizeof(buffer), 0);
            if (n <= 0)
                break;
            if (send(s2, buffer, n, 0) <= 0)
                break;
        }
        if (FD_ISSET(s2, &fds)) {
            int n = recv(s2, buffer, sizeof(buffer), 0);
            if (n <= 0)
                break;
            if (send(s1, buffer, n, 0) <= 0)
                break;
        }
    }
    closesocket(s1);
    closesocket(s2);
}

typedef struct _UDP_RELAY {
    SOCKET udp_socket;
    struct sockaddr_storage client_addr;
    int client_addr_len;
} UDP_RELAY;

static DWORD WINAPI UDPRelayThread(LPVOID param)
{
    UDP_RELAY* relay = (UDP_RELAY*)param;
    char buffer[65536];
    while (1) {
        struct sockaddr_storage src_addr;
        int src_addr_len = sizeof(src_addr);
        int n = recvfrom(relay->udp_socket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&src_addr, &src_addr_len);
        if (n <= 0)
            break;

        int is_from_client = 0;
        if (src_addr.ss_family == relay->client_addr.ss_family) {
            if (src_addr.ss_family == AF_INET) {
                if (memcmp(&((struct sockaddr_in*)&src_addr)->sin_addr,
                           &((struct sockaddr_in*)&relay->client_addr)->sin_addr,
                           sizeof(struct in_addr)) == 0 &&
                    ((struct sockaddr_in*)&src_addr)->sin_port ==
                    ((struct sockaddr_in*)&relay->client_addr)->sin_port)
                    is_from_client = 1;
            } else if (src_addr.ss_family == AF_INET6) {
                if (memcmp(&((struct sockaddr_in6*)&src_addr)->sin6_addr,
                           &((struct sockaddr_in6*)&relay->client_addr)->sin6_addr,
                           sizeof(struct in6_addr)) == 0 &&
                    ((struct sockaddr_in6*)&src_addr)->sin6_port ==
                    ((struct sockaddr_in6*)&relay->client_addr)->sin6_port)
                    is_from_client = 1;
            }
        }

        if (is_from_client) {
            if (n < 4)
                continue;
            if (buffer[0] != 0x00 || buffer[1] != 0x00)
                continue;
            UCHAR frag = buffer[2];
            if (frag != 0x00)
                continue;
            UCHAR atyp = buffer[3];
            int header_len = 0;
            struct sockaddr_storage dest_addr;
            int dest_addr_len = 0;
            memset(&dest_addr, 0, sizeof(dest_addr));
            if (atyp == SOCKS_ADDR_IPV4) {
                header_len = 4 + 4 + 2;
                if (n < header_len)
                    continue;
                struct sockaddr_in* sin = (struct sockaddr_in*)&dest_addr;
                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, buffer + 4, 4);
                memcpy(&sin->sin_port, buffer + 8, 2);
                dest_addr_len = sizeof(struct sockaddr_in);
            } else if (atyp == SOCKS_ADDR_IPV6) {
                header_len = 4 + 16 + 2;
                if (n < header_len)
                    continue;
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&dest_addr;
                sin6->sin6_family = AF_INET6;
                memcpy(&sin6->sin6_addr, buffer + 4, 16);
                memcpy(&sin6->sin6_port, buffer + 20, 2);
                dest_addr_len = sizeof(struct sockaddr_in6);
            } else if (atyp == SOCKS_ADDR_DOMAIN) {
                UCHAR dlen = buffer[4];
                header_len = 4 + 1 + dlen + 2;
                if (n < header_len)
                    continue;
                char domain[256];
                memcpy(domain, buffer + 5, dlen);
                domain[dlen] = '\0';
                uint16_t port_net;
                memcpy(&port_net, buffer + 5 + dlen, 2);
                struct addrinfo hints, *res = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                if (getaddrinfo(domain, NULL, &hints, &res) != 0 || res == NULL)
                    continue;
                memcpy(&dest_addr, res->ai_addr, res->ai_addrlen);
                dest_addr_len = (int)res->ai_addrlen;
                freeaddrinfo(res);
                if (((struct sockaddr*)&dest_addr)->sa_family == AF_INET) {
                    ((struct sockaddr_in*)&dest_addr)->sin_port = port_net;
                } else if (((struct sockaddr*)&dest_addr)->sa_family == AF_INET6) {
                    ((struct sockaddr_in6*)&dest_addr)->sin6_port = port_net;
                } else {
                    continue;
                }
            } else {
                continue;
            }
            int data_len = n - header_len;
            char* data = buffer + header_len;
            sendto(relay->udp_socket, data, data_len, 0,
                   (struct sockaddr*)&dest_addr, dest_addr_len);
        } else {
            char sendbuf[65536];
            int offset = 0;
            sendbuf[offset++] = 0x00;
            sendbuf[offset++] = 0x00;
            sendbuf[offset++] = 0x00; // frag
            if (src_addr.ss_family == AF_INET) {
                sendbuf[offset++] = SOCKS_ADDR_IPV4;
                struct sockaddr_in* sin = (struct sockaddr_in*)&src_addr;
                memcpy(sendbuf + offset, &sin->sin_addr, 4);
                offset += 4;
                memcpy(sendbuf + offset, &sin->sin_port, 2);
                offset += 2;
            } else if (src_addr.ss_family == AF_INET6) {
                sendbuf[offset++] = SOCKS_ADDR_IPV6;
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&src_addr;
                memcpy(sendbuf + offset, &sin6->sin6_addr, 16);
                offset += 16;
                memcpy(sendbuf + offset, &sin6->sin6_port, 2);
                offset += 2;
            }
            memcpy(sendbuf + offset, buffer, n);
            offset += n;
            sendto(relay->udp_socket, sendbuf, offset, 0,
                   (struct sockaddr*)&relay->client_addr, relay->client_addr_len);
        }
    }
    closesocket(relay->udp_socket);
    free(relay);
    return 0;
}

static BOOL HandleConnect(SOCKET client_sock)
{
    UCHAR reserved, atyp;
    if (ReadExact(client_sock, (char*)&reserved, 1) != 1)
        return FALSE;
    if (ReadExact(client_sock, (char*)&atyp, 1) != 1)
        return FALSE;
    struct sockaddr_storage dest_addr;
    int dest_addr_len = 0;
    if (!ReadSocksAddress(client_sock, atyp, &dest_addr, &dest_addr_len)) {
        LogError("HandleConnect: failed to read destination address");
        return FALSE;
    }
    SOCKET remote_sock = socket(((struct sockaddr*)&dest_addr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (remote_sock == INVALID_SOCKET) {
        LogError("HandleConnect: failed to create remote socket, error %d", WSAGetLastError());
        return FALSE;
    }
    if (connect(remote_sock, (struct sockaddr*)&dest_addr, dest_addr_len) == SOCKET_ERROR) {
        SendSocksReply(client_sock, 0x05, NULL, 0);
        LogError("HandleConnect: connect() failed, error %d", WSAGetLastError());
        closesocket(remote_sock);
        return FALSE;
    }
    struct sockaddr_storage local_addr;
    int local_addr_len = sizeof(local_addr);
    if (getsockname(remote_sock, (struct sockaddr*)&local_addr, &local_addr_len) != 0) {
        LogError("HandleConnect: getsockname() failed, error %d", WSAGetLastError());
        closesocket(remote_sock);
        return FALSE;
    }
    if (!SendSocksReply(client_sock, 0x00, (struct sockaddr*)&local_addr, local_addr_len)) {
        LogError("HandleConnect: SendSocksReply failed");
        closesocket(remote_sock);
        return FALSE;
    }
    TcpRelay(client_sock, remote_sock);
    return TRUE;
}

static BOOL HandleBind(SOCKET client_sock)
{
    UCHAR reserved, atyp;
    if (ReadExact(client_sock, (char*)&reserved, 1) != 1)
        return FALSE;
    if (ReadExact(client_sock, (char*)&atyp, 1) != 1)
        return FALSE;
    char dummy[256];
    if (atyp == SOCKS_ADDR_IPV4) {
        if (ReadExact(client_sock, dummy, 4) != 4)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        if (ReadExact(client_sock, dummy, 16) != 16)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen;
        if (ReadExact(client_sock, (char*)&dlen, 1) != 1)
            return FALSE;
        if (ReadExact(client_sock, dummy, dlen) != dlen)
            return FALSE;
    }
    if (ReadExact(client_sock, dummy, 2) != 2)
        return FALSE;

    SOCKET bind_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET)
        bind_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET) {
        LogError("HandleBind: failed to create bind socket, error %d", WSAGetLastError());
        return FALSE;
    }
    {
        int off = 0;
        setsockopt(bind_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&off, sizeof(off));
    }
    struct sockaddr_storage bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    int bind_addr_len = 0;
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = 0;
    memcpy(&bind_addr, &sin6, sizeof(sin6));
    bind_addr_len = sizeof(sin6);
    if (bind(bind_sock, (struct sockaddr*)&bind_addr, bind_addr_len) == SOCKET_ERROR) {
        LogError("HandleBind: bind() failed, error %d", WSAGetLastError());
        closesocket(bind_sock);
        return FALSE;
    }
    if (listen(bind_sock, 1) == SOCKET_ERROR) {
        LogError("HandleBind: listen() failed, error %d", WSAGetLastError());
        closesocket(bind_sock);
        return FALSE;
    }
    getsockname(bind_sock, (struct sockaddr*)&bind_addr, &bind_addr_len);
    if (!SendSocksReply(client_sock, 0x00, (struct sockaddr*)&bind_addr, bind_addr_len)) {
        LogError("HandleBind: first SendSocksReply failed");
        closesocket(bind_sock);
        return FALSE;
    }
    SOCKET incoming = accept(bind_sock, NULL, NULL);
    closesocket(bind_sock);
    if (incoming == INVALID_SOCKET) {
        LogError("HandleBind: accept() failed, error %d", WSAGetLastError());
        return FALSE;
    }
    struct sockaddr_storage remote_addr;
    int remote_addr_len = sizeof(remote_addr);
    if (getpeername(incoming, (struct sockaddr*)&remote_addr, &remote_addr_len) != 0) {
        LogError("HandleBind: getpeername() failed, error %d", WSAGetLastError());
        closesocket(incoming);
        return FALSE;
    }
    if (!SendSocksReply(client_sock, 0x00, (struct sockaddr*)&remote_addr, remote_addr_len)) {
        LogError("HandleBind: second SendSocksReply failed");
        closesocket(incoming);
        return FALSE;
    }
    TcpRelay(client_sock, incoming);
    return TRUE;
}

static BOOL HandleUdpAssociate(SOCKET client_sock)
{
    UCHAR reserved, atyp;
    if (ReadExact(client_sock, (char*)&reserved, 1) != 1)
        return FALSE;
    if (ReadExact(client_sock, (char*)&atyp, 1) != 1)
        return FALSE;
    char dummy[256];
    if (atyp == SOCKS_ADDR_IPV4) {
        if (ReadExact(client_sock, dummy, 4) != 4)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        if (ReadExact(client_sock, dummy, 16) != 16)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen;
        if (ReadExact(client_sock, (char*)&dlen, 1) != 1)
            return FALSE;
        if (ReadExact(client_sock, dummy, dlen) != dlen)
            return FALSE;
    }
    if (ReadExact(client_sock, dummy, 2) != 2)
        return FALSE;

    SOCKET udp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET)
        udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        LogError("HandleUdpAssociate: failed to create UDP socket, error %d", WSAGetLastError());
        return FALSE;
    }
    {
        int off = 0;
        setsockopt(udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&off, sizeof(off));
    }
    struct sockaddr_storage udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    int udp_addr_len = 0;
    struct sockaddr_in6 sin6_udp;
    memset(&sin6_udp, 0, sizeof(sin6_udp));
    sin6_udp.sin6_family = AF_INET6;
    sin6_udp.sin6_addr = in6addr_any;
    sin6_udp.sin6_port = 0;
    memcpy(&udp_addr, &sin6_udp, sizeof(sin6_udp));
    udp_addr_len = sizeof(sin6_udp);
    if (bind(udp_sock, (struct sockaddr*)&udp_addr, udp_addr_len) == SOCKET_ERROR) {
        LogError("HandleUdpAssociate: bind() failed for UDP socket, error %d", WSAGetLastError());
        closesocket(udp_sock);
        return FALSE;
    }
    getsockname(udp_sock, (struct sockaddr*)&udp_addr, &udp_addr_len);
    if (!SendSocksReply(client_sock, 0x00, (struct sockaddr*)&udp_addr, udp_addr_len)) {
        LogError("HandleUdpAssociate: SendSocksReply failed");
        closesocket(udp_sock);
        return FALSE;
    }
    UDP_RELAY* relay = (UDP_RELAY*)malloc(sizeof(UDP_RELAY));
    if (!relay) {
        LogError("HandleUdpAssociate: malloc failed");
        closesocket(udp_sock);
        return FALSE;
    }
    relay->udp_socket = udp_sock;
    relay->client_addr_len = sizeof(relay->client_addr);
    if (getpeername(client_sock, (struct sockaddr*)&relay->client_addr, &relay->client_addr_len) != 0) {
        LogError("HandleUdpAssociate: getpeername failed, error %d", WSAGetLastError());
        closesocket(udp_sock);
        free(relay);
        return FALSE;
    }
    HANDLE hThread = CreateThread(NULL, 0, UDPRelayThread, relay, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
    else
        LogError("HandleUdpAssociate: failed to create UDPRelayThread, error %d", WSAGetLastError());
    return TRUE;
}

static BOOL Authenticate(SOCKET client_sock)
{
    UCHAR ver_nmethods[2];
    if (ReadExact(client_sock, (char*)ver_nmethods, 2) != 2)
        return FALSE;
    if (ver_nmethods[0] != SOCKS5_VERSION)
        return FALSE;
    UCHAR nmethods = ver_nmethods[1];
    if (nmethods == 0)
        return FALSE;
    UCHAR methods[256];
    if (ReadExact(client_sock, (char*)methods, nmethods) != nmethods)
        return FALSE;
    BOOL support_userpass = FALSE;
    for (int i = 0; i < nmethods; i++) {
        if (methods[i] == AUTH_METHOD_USERPASS) {
            support_userpass = TRUE;
            break;
        }
    }
    UCHAR resp[2];
    resp[0] = SOCKS5_VERSION;
    resp[1] = support_userpass ? AUTH_METHOD_USERPASS : AUTH_METHOD_NO_ACCEPT;
    if (SendAll(client_sock, (char*)resp, 2) != 2)
        return FALSE;
    if (!support_userpass)
        return FALSE;
    UCHAR ver;
    if (ReadExact(client_sock, (char*)&ver, 1) != 1)
        return FALSE;
    if (ver != AUTH_VERSION_USERPASS)
        return FALSE;
    UCHAR ulen;
    if (ReadExact(client_sock, (char*)&ulen, 1) != 1)
        return FALSE;
    char username[256] = {0};
    if (ulen > 0) {
        if (ReadExact(client_sock, username, ulen) != ulen)
            return FALSE;
        username[ulen] = '\0';
    }
    UCHAR plen;
    if (ReadExact(client_sock, (char*)&plen, 1) != 1)
        return FALSE;
    char password[256] = {0};
    if (plen > 0) {
        if (ReadExact(client_sock, password, plen) != plen)
            return FALSE;
        password[plen] = '\0';
    }
    UCHAR status = 0x00;
    if (strcmp(username, SERVER_USERNAME) != 0 || strcmp(password, SERVER_PASSWORD) != 0)
        status = 0x01;
    UCHAR auth_resp[2] = { AUTH_VERSION_USERPASS, status };
    SendAll(client_sock, (char*)auth_resp, 2);
    return (status == 0x00);
}

static DWORD WINAPI ClientHandlerThread(LPVOID param)
{
    SOCKET client_sock = *(SOCKET*)param;
    free(param);
    if (!Authenticate(client_sock)) {
        LogError("ClientHandlerThread: authentication failed");
        closesocket(client_sock);
        return 0;
    }
    UCHAR header[4];
    if (ReadExact(client_sock, (char*)header, 4) != 4) {
        LogError("ClientHandlerThread: failed to read request header");
        closesocket(client_sock);
        return 0;
    }
    if (header[0] != SOCKS5_VERSION) {
        LogError("ClientHandlerThread: unsupported SOCKS version %d", header[0]);
        closesocket(client_sock);
        return 0;
    }
    UCHAR cmd = header[1];
    BOOL result = FALSE;
    switch (cmd) {
        case SOCKS_CMD_CONNECT:
            result = HandleConnect(client_sock);
            break;
        case SOCKS_CMD_BIND:
            result = HandleBind(client_sock);
            break;
        case SOCKS_CMD_UDP_ASSOCIATE:
            result = HandleUdpAssociate(client_sock);
            break;
        default:
            SendSocksReply(client_sock, 0x07, NULL, 0);
            LogError("ClientHandlerThread: unsupported command %d", cmd);
            break;
    }
    closesocket(client_sock);
    return 0;
}

int main(int argc, char* argv[])
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        LogError("WSAStartup failed");
        return 1;
    }
    int port = 1080;
    if (argc > 1)
        port = atoi(argv[1]);

    SOCKET listen_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET)
        listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        LogError("Failed to create listening socket, error %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    {
        int off = 0;
        setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&off, sizeof(off));
    }
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);
    if (bind(listen_sock, (struct sockaddr*)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
        LogError("Bind failed, error %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        LogError("Listen failed, error %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }
    LogInfo("SOCKS5 server listening on port %d", port);
    while (1) {
        struct sockaddr_storage client_addr;
        int client_addr_len = sizeof(client_addr);
        SOCKET* client_sock = (SOCKET*)malloc(sizeof(SOCKET));
        if (!client_sock)
            break;
        *client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (*client_sock == INVALID_SOCKET) {
            free(client_sock);
            LogError("Accept failed, error %d", WSAGetLastError());
            continue;
        }
        char addr_str[256];
        SockAddrToString((struct sockaddr*)&client_addr, addr_str, sizeof(addr_str));
        LogInfo("Accepted connection from %s", addr_str);
        HANDLE hThread = CreateThread(NULL, 0, ClientHandlerThread, client_sock, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
    }
    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
