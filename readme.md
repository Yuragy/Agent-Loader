# Agent Loader

Modular C2 loader featuring dynamic function encryption, in-memory payload support, and a covert DoH command channel, configurable via a Python builder and a Node.js web panel.

## Technical specifications:
+ Function encryption (decrypt → exec → re-encrypt)
+ Reverse-shell module  
+ FS-mgr: search/scach/upload/delete files  
+ Token stealth: collection and impersonation of user tokens  
+ - In-memory peyloads: reflective shellcode or loadPE (.DLL/.EXE/.NET)  
+ RWX shellcode  
+ CLI-builder: build with required parameters (via a separate py builder)
+ C2 channel via DNS over HTTPS (Cloudflare/Google/Akamai DoH)  
+ - NT/ZW syscall stubs, min WinAPI  
+ - VM-based bytecode interpreter: each build with unique morphing  
+ Reverse-SOCKS5 proxy over WebSocket as a separate thread  
+ - Anti VM wrapper + DLL hijack  
+ OneDrive/Scheduler   
+ Web panel on Node.js: list of bots, FS mgr, interactive shell, start custom peyloads, IP/HWID banlist.
  
(Some of the fucncials on the list are under development, keep an eye out for updates)

# Structure
- loader client
- server C2 server+panel
- build.py - convenient build

# Build
   python builder.py
   
   Enter RSHELL_PORT, SOCKS login/password, DoH server.
   
   Enter = leave the default value as prescribed in the py code. 
   
   As a result you will get:
   - loader.exe - compiled image
   - loader.map - PE map
   - loader_packed.exe - final packed binary

## More about building with encryption
builder.py:          
Generates config.h, compiles, packs → loader.exe + loader.map + loader_packed.exe
  1. Rewrites config.h to match the given parameters in cli 
  2. cl /link /MAP:loader.map /OUT:loader.exe 
  3. Parses loader.map, finds addresses and function lengths from the FUNCS list
  4. encrypts bytecode sections and outputs ready loader_packed.exe.
How to package functions before building, for encryption: 
  1. Add the function name to the FUNCS array inside the build script: FUNCS = [ ... ]
  2. In the code, call the wrapper labeled /*LEN*/ instead of a number:
   - Includi crypto.h 
   - Wrapper: Crypto_Invoke(FuncName, /*LEN*/, 0x5A);
  3. The build will automatically detect the length of each function and replace /*LEN*/ with the actual length. 

# Loader Quick Start Guide ⇄ Server
### Start Server: 
- npm install # dependencies
- npm start # start

### Loader works: 
1. Save check
2. Persistence
3. Makes token stealth(how to where for what, yeah, think while it takes everything and uses the first one it finds)
4. Opening session and a single A signal to mark online status
5. Background C2 loop sends a DoH request to the domain every 5 seconds and receives the result.
6. Supports commands:
- start_proxy - Starts a reverse shell server on RSHELL_PORT and a reverse SOCKS5 client via WebSocket transport at the same time.
- stop_proxy - Stops the proxy and shell. 
- list_dir - Bypasses printing each file/directory.
- file_get - Reads the specified file, returning its contents in a buffer for transfer to C2.
- file_put - Decodes from Base64, writes the resulting buffer to a file.
- file_del - Deletes a file or directory at the specified path.
- run_shellcode - Decodes shellcode bytes, allocates rwx memory and runs.
- load_pe - Decodes a PE image (dll/exe) and loads it (MemoryModule + DllMain).
- load_dotnet - Decodes a .net assembly and loads it via CLR v4+ API.
- exec_reflective - Decodes either the PE or reflective shell, and executes it.
7. Reverse shell + SOCKS5 starts immediately at the entry point
8. Stop completes all modules and exits

### Edits:
- Debug the build through py builder
- It is possible to finalize the panel to be more comfortable
- Under dllmain
- Check pailoads
- DLL hijack intergr
- Rewrite base on NT/ZW syscall get off WinApi
- VM bytecode interpreter?

⚠️ This is a training material demonstrating capabilities, the responsibility to use it lies with you.
