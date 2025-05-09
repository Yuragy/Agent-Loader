#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Дешифрует память [addr, addr+len) ключом,
 * снимая и затем восстанавливая защиту страниц.
 *
 * @param addr  — начало шифруемого участка
 * @param len   — длина участка в байтах
 * @param key   — ключ 
 * @return
 */
bool Crypto_DecryptRegion(void *addr, size_t len, uint8_t key);

/**
 * Зашифровывает память[addr, addr+len) ключом, сразу после исполнения дешифрованного кода.
 */
bool Crypto_EncryptRegion(void *addr, size_t len, uint8_t key);

/**
 *  1) дешифрует регион
 *  2) вызывает func
 *  3) зашифровывает регион обратно
 *
 * @param func  — указатель на функцию
 * @param len   — размер в байтах
 * @param key   — ключ 
 * @return
 */
bool Crypto_Invoke(void (*func)(void), size_t len, uint8_t key);

#endif // CRYPTO_H
