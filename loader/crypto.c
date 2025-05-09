#define _CRT_SECURE_NO_WARNINGS
#include "crypto.h"

#include <windows.h>
#include <stdint.h>

// [addr, addr+len) in newProt
// *oldProt.
static bool _ChangeProtection(void *addr, size_t len, DWORD newProt, DWORD *oldProt) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t start = (uintptr_t)addr & ~(si.dwPageSize - 1);
    size_t total = len + ((uintptr_t)addr - start);
    return VirtualProtect((LPVOID)start, total, newProt, oldProt) != 0;
}

static void _XorBuffer(uint8_t *buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

bool Crypto_DecryptRegion(void *addr, size_t len, uint8_t key) {
    if (!addr || len == 0) return false;
    DWORD oldProt;
    if (!_ChangeProtection(addr, len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    _XorBuffer((uint8_t*)addr, len, key);
    DWORD tmp;
    VirtualProtect(addr, len, oldProt, &tmp);
    return true;
}

bool Crypto_EncryptRegion(void *addr, size_t len, uint8_t key) {
    if (!addr || len == 0) return false;
    DWORD oldProt;
    if (!_ChangeProtection(addr, len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    _XorBuffer((uint8_t*)addr, len, key);
    DWORD tmp;
    VirtualProtect(addr, len, oldProt, &tmp);
    return true;
}

bool Crypto_Invoke(void (*func)(void), size_t len, uint8_t key) {
    if (!func || len == 0) return false;
    if (!Crypto_DecryptRegion((void*)func, len, key))
        return false;
    func();
    if (!Crypto_EncryptRegion((void*)func, len, key))
        return false;
    return true;
}
