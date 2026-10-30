/* SPDX-License-Identifier: BSD-2-Clause */
/* Simulated firmware allocation, with real small-payload memory moves. */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t vm_offset_t;
typedef int EFI_STATUS;
#define M(x) ((uint64_t)(x)*1024*1024)
#define EFI_PAGE_SIZE 4096
#define EFI_SIZE_TO_PAGES(x) (((x)+4095)/4096)
#define roundup2(x,a) (((x)+(a)-1)&~((a)-1))
#define rounddown2(x,a) ((x)&~((a)-1))
#define EFI_ERROR(x) ((x)!=0)
#define EFI_STAGING_2M_ALIGN 1
#define EFI_ALLOC_MAX_ADDR 1
#define EFI_ALLOC_METHOD 1
#define AllocateAddress 0
#define EfiLoaderCode 0
#define panic(...) abort()
static uint64_t staging,staging_end,staging_base;
static int64_t stage_offset;
static uint64_t staging_slop=M(8),moved,copies;
static bool boot_services_active=true;
static int scenario;
static unsigned attempts;
static unsigned char memory[32*1024*1024];
static uint64_t get_staging_max(void){return M(4096);}
/* Firmware map: allocation is at the top of usable memory, with free
 * pages directly below. Extension above it is unavailable. No guest memory
 * is read or modified; copy lengths are counted, not executed. */
static int alloc(int method,int type,unsigned long pages,uint64_t *addr){
 (void)type; attempts++;
 if(scenario==3)return 1;
 if(scenario==2 && pages>512)return 1; /* fragmented: exact growth only */
 if(method==AllocateAddress && *addr+pages*4096==staging_base)return 0;
 if(scenario==1 && method==AllocateAddress && *addr==staging_end)return 0;
 return 1;
}
static int release(uint64_t base,unsigned long pages){(void)base;(void)pages;return 0;}
static struct {int(*AllocatePages)(int,int,unsigned long,uint64_t*);int(*FreePages)(uint64_t,unsigned long);} services={alloc,release},*BS=&services;
static void *count_move(void *dst,const void *src,size_t n){
 moved+=n;copies++;
 if(scenario==4){
  uint64_t base=M(4096)-sizeof(memory);
  assert((uintptr_t)dst>=base && (uintptr_t)src>=base);
  assert((uintptr_t)dst-base+n<=sizeof(memory));
  assert((uintptr_t)src-base+n<=sizeof(memory));
  memmove(memory+(uintptr_t)dst-base,memory+(uintptr_t)src-base,n);
 }
 return dst;
}
#define memmove count_move
#define memcpy count_move

/* INSERT_LOADER_FUNCTIONS */

int main(int argc,char **argv){
 assert(argc==2); const char *test=argv[1];
 staging_end=get_staging_max();staging_base=staging=staging_end-M(64);
 uint64_t original=staging, bytes=1673330688;
 if(strcmp(test,"large")==0){
  for(uint64_t off=0;off<bytes;off+=4096){
   assert(efi_check_space(staging+off+4096));
   assert(staging+off+4096+staging_slop<=staging_end);
   assert(staging-stage_offset==original);
  }
  printf("relocations=%llu copied_bytes=%llu\n",(unsigned long long)copies,(unsigned long long)moved);
  assert(copies<16 && moved<4*bytes);
 }else if(strcmp(test,"fragmented")==0){
  scenario=2;
  assert(efi_check_space(staging_end-staging_slop+4096));
  assert(attempts>1 && copies==1);
  assert(staging-stage_offset==original);
 }else if(strcmp(test,"unavailable")==0){
  scenario=3;
  assert(!efi_check_space(staging_end+4096));
  assert(staging==original && copies==0 && stage_offset==0);
 }else if(strcmp(test,"overflow")==0){
  assert(!efi_check_space(UINT64_MAX));
  assert(!efi_check_space(UINT64_MAX-4095));
  assert(attempts==0);
 }else if(strcmp(test,"after")==0){
  scenario=1; staging=staging_base=M(128);staging_end=M(192);
  assert(efi_check_space(staging_end+4096));
  assert(staging==M(128) && copies==0 && attempts==1);
 }else if(strcmp(test,"postexit")==0){
  boot_services_active=false;
  assert(efi_check_space(staging_end)); /* existing space; slop may be used */
  assert(attempts==0);
 }else if(strcmp(test,"contents")==0){
  scenario=4;staging=staging_base=staging_end-65536;staging_slop=4096;
  original=staging;
  uint64_t base=M(4096)-sizeof(memory);
  for(unsigned i=0;i<65536;i++)memory[staging-base+i]=(unsigned char)(i*17+3);
  for(uint64_t off=65536;off<M(8);off+=4096){
   assert(efi_check_space(staging+off+4096));
   assert(staging-stage_offset==original);
   assert(staging%M(2)==0);
  }
  for(unsigned i=0;i<65536;i++)assert(memory[staging-base+i]==(unsigned char)(i*17+3));
 }else return 2;
 return 0;
}
