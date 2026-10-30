# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual EFI Multiboot2 tag writers with guarded output capacities."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "multiboot2.h"
static void *ST = (void *)0x1234, *IH = (void *)0x5678;
'''
MAIN = r'''
int main(void)
{
 unsigned char storage[544], saved[544];
 char large[8192];
 memset(large, 'x', sizeof(large)); /* Deliberately no terminator. */
 for (size_t capacity = 0; capacity <= 512; capacity++) {
  for (int operation = 0; operation < 6; operation++) {
   memset(storage, 0xa5, sizeof(storage));
   struct mb2_builder b = {(char *)storage + 16, capacity};
   int error;
   switch (operation) {
   case 0: error = add_string(&b, MULTIBOOT_TAG_TYPE_CMDLINE, "abc"); break;
   case 1: error = add_efi(&b); break;
   case 2: error = add_module(&b, 0x1000, 0x2000, "header"); break;
   case 3: error = add_end(&b); break;
   case 4: error = add_string(&b, MULTIBOOT_TAG_TYPE_CMDLINE, large); break;
   default: error = add_module(&b, 0x1000, 0x2000, large); break;
   }
   const size_t needed[] = {16, 40, 24, 8};
   assert(error == ((operation < 4 && capacity >= needed[operation]) ? 0 : E2BIG));
   assert(b.remaining <= capacity);
   assert(b.next == (char *)storage + 16 + capacity - b.remaining);
   for (size_t i = 0; i < 16; i++) assert(storage[i] == 0xa5);
   for (size_t i = 16 + capacity; i < sizeof(storage); i++) assert(storage[i] == 0xa5);
   if (!error) {
    struct multiboot_tag *tag = (void *)(storage + 16);
    assert(capacity - b.remaining == needed[operation]);
    if (operation == 0) {
     assert(tag->type == MULTIBOOT_TAG_TYPE_CMDLINE && tag->size == 12);
     assert(!strcmp((char *)tag + sizeof(*tag), "abc"));
     for (size_t i = 28; i < 32; i++) assert(storage[i] == 0);
    } else if (operation == 1) {
     assert(tag->type == MULTIBOOT_TAG_TYPE_EFI_BS && tag->size == 8);
     struct multiboot_tag_efi64 *efi = (void *)(storage + 24);
     struct multiboot_tag_efi64_ih *ih = (void *)(storage + 40);
     assert(efi->pointer == (uintptr_t)ST && ih->pointer == (uintptr_t)IH);
    } else if (operation == 2) {
     struct multiboot_tag_module *m = (void *)tag;
     assert(m->mod_start == 0x1000 && m->mod_end == 0x2000);
     assert(!strcmp((char *)m + sizeof(*m), "header"));
    } else assert(tag->type == MULTIBOOT_TAG_TYPE_END && tag->size == 8);
   }
  }
 }
 memset(storage, 0xa5, sizeof(storage)); memcpy(saved, storage, sizeof(storage));
 struct mb2_builder b = {(char *)storage + 16, 512};
 assert(mb2_reserve(&b, SIZE_MAX) == NULL);
 assert(mb2_reserve(&b, (size_t)UINT32_MAX + 1) == NULL);
 assert(b.remaining == 512 && b.next == (char *)storage + 16);
 assert(!memcmp(saved, storage, sizeof(storage)));
 puts("PASS: 3078 guarded tag writes, exact-fit serialization and overflow rejection");
 return 0;
}
'''

def main():
    source = (ROOT / 'stand/efi/loader/arch/amd64/multiboot2.c').read_text()
    start = source.index('struct mb2_builder {')
    functions = source[start:source.index('static int\nexec(', start)]
    with tempfile.TemporaryDirectory() as directory:
        c = Path(directory) / 'test.c'
        binary = Path(directory) / 'test'
        c.write_text(PRE + functions + MAIN)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'stand/efi/loader/arch/amd64'),
                        str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)

if __name__ == '__main__':
    main()
