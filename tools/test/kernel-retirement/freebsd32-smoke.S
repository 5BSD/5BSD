/* SPDX-License-Identifier: BSD-2-Clause */
.text
.globl _start
_start:
 movl $20, %eax
 int $0x80
 jc fail
 testl %eax, %eax
 jle fail
 pushl $message_end-message
 pushl $message
 pushl $1
 pushl $0
 movl $4, %eax
 int $0x80
 jc fail
 addl $16, %esp
 cmpl $message_end-message, %eax
 jne fail
 pushl $0
 jmp done
fail:
 pushl $1
done:
 pushl $0
 movl $1, %eax
 int $0x80
.section .rodata
message: .ascii "FREEBSD32_ELF_PASS\n"
message_end:
.section .note.GNU-stack,"",@progbits
