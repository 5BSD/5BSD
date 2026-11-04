/* SPDX-License-Identifier: BSD-2-Clause */
ENTRY(standalone_add)
SECTIONS {
    . = 0x100000;
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.* COMMON) }
}
