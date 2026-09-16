/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define IEEE80211_ELEMID_DSPARMS 3
#include "power_functions.h"
int main(void) {
 size_t page=sysconf(_SC_PAGESIZE);
 uint8_t *p=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(p!=MAP_FAILED && mprotect(p+page,page,PROT_NONE)==0);
 assert(lkpi_fullmac_ies_valid(p+page,0));
 for (unsigned type=0; type<256; type++) {
  for (unsigned size=0; size<256; size++) {
   uint8_t *ie=p+page-size-2; memset(ie,0,size+2);ie[0]=type;ie[1]=size;
   assert(lkpi_fullmac_ies_valid(ie,size+2)==(type!=3 || size==1));
   assert(!lkpi_fullmac_ies_valid(ie,size+1));
  }
 }
 uint8_t valid[]={0,0,1,1,2,3,1,6,221,0};
 memcpy(p+page-sizeof(valid),valid,sizeof(valid));
 assert(lkpi_fullmac_ies_valid(p+page-sizeof(valid),sizeof(valid)));
 assert(munmap(p,page*2)==0);
 puts("PASS: exhaustive IE type/length boundaries, truncated TLVs and missing DS channel");
}
