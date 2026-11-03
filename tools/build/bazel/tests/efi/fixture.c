/* SPDX-License-Identifier: BSD-2-Clause */
void efi_entry(void) { }
__attribute__((section(".data"))) volatile unsigned int image_marker = 0x1234abcd;
__attribute__((section(".discard"))) const char excluded[] = "excluded EFI fixture payload";
