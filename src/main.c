// https://dl.packetstormsecurity.net/papers/general/PE_Injection_Explained.pdf

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "kernel32.lib")

void entry_point();
void msg(char* str);
void mainCRTStartup();

DWORD WINAPI injection_main(LPVOID param) // this gets run in remote process upon successful injection
{
    DWORD new_module = (DWORD) param;
    msg("Injection successful, initializing runtime library");
    mainCRTStartup();
    msg("This should never appear, fix your shit Ivan.");
    return 0;
}

DWORD get_pid(const char* name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot == INVALID_HANDLE_VALUE) { msg("Failed to get process snapshot"); exit(0); }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(snapshot, &process_entry)) 
    { 
        CloseHandle(snapshot); 
        msg("Failed to get first process");
        exit(0);
    }

    do
    {
        if(_stricmp(process_entry.szExeFile, name) == 0)
        {
            CloseHandle(snapshot);
            msg("Got PID");
            return process_entry.th32ProcessID;
        }
    } while(Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    msg("Failed to get PID");
    return 0; // process not found
}

BOOL get_privileges(TCHAR* privilege)
{
    // call with get_privileges((TCHAR*) TEXT("SeDebugPrivilege"));
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if(LookupPrivilegeValue(NULL, privilege, &priv.Privileges[0].Luid) != FALSE
        && AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) ret = TRUE;

        if(GetLastError() == ERROR_NOT_ALL_ASSIGNED) // non admin or something
            ret = FALSE;
        CloseHandle(token);
    }

    if(ret == TRUE) msg("Obtained privileges");
    else msg("Insufficient privileges");
    return ret;
}

DWORD main();

HMODULE inject_image(HANDLE process, LPVOID image)
{
    msg("Injecting image...");
    DWORD i = 0;
    DWORD_PTR delta = 0;
    DWORD_PTR old_delta = 0;

    // get PE headers
    PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE) image + ((PIMAGE_DOS_HEADER) image)->e_lfanew);
    PIMAGE_DATA_DIRECTORY data_dir;

    // get image size
    DWORD image_size = headers->OptionalHeader.SizeOfImage;
    if(image_size == 0) msg("Image size is 0...?");
    LPVOID target_image = NULL;
    LPBYTE buffer = NULL; // copy of the image
    BOOL res = FALSE;
    if(headers->Signature != IMAGE_NT_SIGNATURE) msg("Invalid header signature");
    if(IsBadReadPtr(image, image_size)) msg("Calculated image size does not correspond to actual size");

    target_image = VirtualAllocEx(process, NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(target_image == NULL) msg("VirtualAllocEx for target image failed");
    buffer = (LPBYTE) VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(buffer == NULL) msg("VirtualAlloc for buffer image failed");
    RtlCopyMemory(buffer, image, image_size);

    data_dir = (PIMAGE_DATA_DIRECTORY) &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(data_dir == NULL) msg("Data directory is null");
    if(data_dir->Size == 0) msg("Data directory size is 0");
    if(data_dir->VirtualAddress == 0) msg("Data directory virtual address is 0");
    if(data_dir->Size > 0 && data_dir->VirtualAddress > 0)
    {
        msg("Starting base relocation...");
        // delta - offset in target process, old_delta - offset in current process
        delta = (DWORD_PTR)((LPBYTE) target_image - headers->OptionalHeader.ImageBase);
        old_delta = (DWORD_PTR)((LPBYTE) image - headers->OptionalHeader.ImageBase);

        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(buffer + data_dir->VirtualAddress);

        while(reloc->VirtualAddress != 0)
        {
            if(reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
            {
                // number of relocation descriptors
                DWORD n_reloc_desc = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                
                // ptr to first reloc descriptor
                LPWORD reloc_descs = (LPWORD)((LPBYTE) reloc + sizeof(IMAGE_BASE_RELOCATION));

                // loop through descs
                for(int i = 0; i < n_reloc_desc; i++)
                {
                    if(reloc_descs[i] > 0)
                    {
                        // rebase value
                        DWORD_PTR* p = (DWORD_PTR*)(buffer + (reloc->VirtualAddress + (0x0FFF & (reloc_descs[i]))));
                        *p -= old_delta;
                        *p += delta;
                    }
                }
            }

            // next relocation block
            reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE) reloc + reloc->SizeOfBlock);
        }
        msg("Finished base relocation");
        // for whatever reason a breakpoint instruction gets automatically added to the beginning
        // of any main() function, so remove it
        buffer[(DWORD) main - (DWORD) image] = 0x55; // push ebp

        res = WriteProcessMemory(process, target_image, buffer, image_size, NULL);
        if(res == FALSE) msg("WriteProcessMemory failed");
    } else msg("Base relocation failed");

    VirtualFree(buffer, 0, MEM_RELEASE);

    return (HMODULE) target_image;
}

void inject(DWORD pid, LPTHREAD_START_ROUTINE call_routine)
{
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    
    if(process == INVALID_HANDLE_VALUE) msg("Invalid remote process handle");
    HMODULE local_image = GetModuleHandle(NULL);
    if(local_image == INVALID_HANDLE_VALUE || local_image == NULL) msg("Invalid local process handle");
    HMODULE injected_image = (HMODULE) inject_image(process, local_image);
    if(injected_image == NULL) msg("Failed to inject image into target process");

    // get main routine address
    LPTHREAD_START_ROUTINE remote_thread = (LPTHREAD_START_ROUTINE)((LPBYTE) injected_image + (DWORD_PTR)((LPBYTE) call_routine - (LPBYTE) local_image));
    // call it
    if(remote_thread == NULL) msg("Failed to get start routine for injected image");
    HANDLE thread = CreateRemoteThread(process, NULL, 0, remote_thread, NULL, 0, NULL);
    if(thread == NULL) 
    { 
        VirtualFreeEx(process, local_image, 0, MEM_RELEASE); 
        msg("Failed to execute injected image");
    }
    CloseHandle(process);
}

DWORD main() // entry point after library is initialized, has all functionality
{
    msg("Runtime library initialized");
    printf("libc works\n");

    // WOOO

    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    char* buffer = malloc(1024 * 1024 * 50);
    sprintf(buffer, "Entered %s", moduleName);
    msg(buffer);

    LPVOID test = VirtualAlloc(NULL, 1024 * 1024 * 10, MEM_COMMIT, PAGE_READWRITE);
    printf("%d\n", test);
    getchar();

    VirtualFree(test, 0, MEM_RELEASE);
    free(buffer);
    
    msg("End of main, exiting");

    //ExitThread(0); // to avoid crashing the host // to crash the host
    return 0;
}

void entry_point() // entry point when started by system, avoid libc functions before injection is done
{
    msg("Starting...");
    get_privileges((TCHAR*) TEXT("SeDebugPrivilege"));
    inject(get_pid("notepad.exe"), injection_main);
}

void msg(char* str)
{
    MessageBoxA(NULL, str, "You will never get rid of me", 0);
}