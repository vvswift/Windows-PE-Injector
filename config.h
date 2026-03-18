#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace Config {
    inline const std::wstring BotId         = L"TEST-BOT";
    inline const std::string  ServerCfg     = R"({"srv":"127.0.0.1"})";
    inline const std::vector<uint8_t> Salsa20Key(32, 0); 
    inline const std::vector<uint8_t> Reserved{};
    inline const std::wstring ExeCmdlineDefault = L"ghosted.exe";
}
