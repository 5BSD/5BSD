/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "usbhid.h"

/* End every report at an inaccessible page: no implicit padding is allowed. */
int
main(void)
{
 const uint32_t values[] = {0, 1, UINT32_MAX, 0x80000000, 0xabcdef01};
 long page = sysconf(_SC_PAGESIZE);
 unsigned char *map, *p, expected[8];
 unsigned width, offset, id, sign, v, bit, length, at;
 uint32_t mask, want, got;
 hid_item_t h;

 if (page <= 0) return (1);
 map = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
     MAP_PRIVATE | MAP_ANON, -1, 0);
 if (map == MAP_FAILED || mprotect(map + page, page, PROT_NONE) != 0)
  return (1);
 for (width = 1; width <= 32; width++)
 for (offset = 0; offset < 8; offset++)
 for (id = 0; id < 2; id++)
 for (sign = 0; sign < 2; sign++)
 for (v = 0; v < sizeof(values) / sizeof(values[0]); v++) {
  memset(&h, 0, sizeof(h));
  h.pos = offset;
  h.report_size = width;
  h.report_ID = id ? 7 : 0;
  h.logical_minimum = sign ? -1 : 0;
  length = (offset + width + 7) / 8 + id;
  p = map + page - length;
  memset(p, 0xa5, length);
  memset(expected, 0xa5, sizeof(expected));
  if (id) expected[0] = 7;
  /* Independent bit-by-bit model also checks preservation of adjacent bits. */
  for (bit = 0; bit < width; bit++) {
   at = offset + bit;
   if ((values[v] >> bit) & 1)
    expected[id + at / 8] |= 1U << (at % 8);
   else
    expected[id + at / 8] &= ~(1U << (at % 8));
  }
  hid_set_data(p, &h, (int32_t)values[v]);
  if (memcmp(p, expected, length) != 0) {
   fprintf(stderr, "write mismatch width=%u offset=%u id=%u\n", width, offset, id);
   return (1);
  }
  mask = UINT32_MAX >> (32 - width);
  want = values[v] & mask;
  if (sign && (want & (1U << (width - 1)))) want |= ~mask;
  got = (uint32_t)hid_get_data(p, &h);
  if (got != want) {
   fprintf(stderr, "read mismatch width=%u offset=%u id=%u\n", width, offset, id);
   return (1);
  }
 }
 munmap(map, page * 2);
 puts("5120 guarded HID field round trips passed");
 return (0);
}
