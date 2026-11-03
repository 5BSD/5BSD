/* SPDX-License-Identifier: BSD-2-Clause */
ENTRY(efi_entry)
SECTIONS {
  . = 0x1000;
  .text : { *(.text*) }
  . = ALIGN(0x1000);
  .data : { *(.data*) *(.rodata*) }
  .dynamic : { *(.dynamic) }
  .dynsym : { *(.dynsym) }
  .dynstr : { *(.dynstr) }
  .hash : { *(.hash) }
  .gnu.hash : { *(.gnu.hash) }
  .rela.dyn : { *(.rela*) }
  .discard : { *(.discard) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
