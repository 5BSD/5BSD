/* SPDX-License-Identifier: BSD-2-Clause */
.text
.globl _start
_start:
 movl $20, %eax
 int $0x80
 testl %eax, %eax
 jle fail
 movl $5, %eax
 movl $path, %ebx
 xorl %ecx, %ecx
 xorl %edx, %edx
 int $0x80
 testl %eax, %eax
 js fail
 movl %eax, %ebx
 movl $3, %eax
 movl $buffer, %ecx
 movl $256, %edx
 int $0x80
 testl %eax, %eax
 jle fail
 movl $6, %eax
 int $0x80
 movl $4, %eax
 movl $1, %ebx
 movl $message, %ecx
 movl $message_end-message, %edx
 int $0x80
 cmpl $message_end-message, %eax
 jne fail
 movl $1, %eax
 xorl %ebx, %ebx
 int $0x80
fail:
 movl $1, %eax
 movl $1, %ebx
 int $0x80
.section .rodata
path: .asciz "/proc/self/stat"
message: .ascii "LINUX32_PROC_PASS\n"
message_end:
.bss
.lcomm buffer,256
.section .note.GNU-stack,"",@progbits
