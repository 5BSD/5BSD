/* SPDX-License-Identifier: BSD-2-Clause */
/* Host component benchmark. Descriptor is an input, not an authenticated boot. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "g_verity_verify.h"

struct input { int fd[2]; uint64_t calls[2], bytes[2]; };
static int
read_block(void *arg, int tree, uint64_t offset, void *buffer, size_t length)
{
 struct input *in = arg;
 size_t done = 0;
 ssize_t n;
 in->calls[tree]++;
 while (done < length) {
  n = pread(in->fd[tree], (char *)buffer + done, length - done, offset + done);
  if (n < 0) { if (errno == EINTR) continue; return errno; }
  if (n == 0) return EIO;
  done += n;
 }
 in->bytes[tree] += done;
 return 0;
}
static uint64_t
number(const char *s)
{
 char *end;
 unsigned long long n;
 errno = 0;
 if (*s < '0' || *s > '9') errx(1,"invalid integer: %s",s);
 n = strtoull(s,&end,10);
 if (errno || *end) errx(1,"invalid integer: %s",s);
 return n;
}
static double
now(clockid_t clock)
{
 struct timespec t;
 if (clock_gettime(clock,&t)) err(1,"clock_gettime");
 return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
int
main(int argc, char **argv)
{
 struct g_verity_root root;
 struct g_verity_cache cache = {0};
 uint64_t entries = 0, *tags = NULL;
 void *blocks = NULL;
 struct input in = {0};
 struct stat st;
 struct rusage usage;
 unsigned char wire[G_VERITY_ROOT_BYTES + 1], *data, *hash, *leaf, *output;
 uint64_t request, iterations, stride, slots, slot = 0, index, offset;
 double wall, cpu;
 size_t done;
 int fd, verified, cached, range_baseline, error;
 ssize_t n;
 if (argc != 9 && argc != 10) errx(1,"usage: %s data tree descriptor request_bytes iterations stride_blocks baseline|baseline-range|verified|cached starting_slot [cache_entries]",argv[0]);
 request=number(argv[4]); iterations=number(argv[5]); stride=number(argv[6]);
 range_baseline=strcmp(argv[7],"baseline-range")==0;
 cached=strcmp(argv[7],"cached")==0;
 verified=strcmp(argv[7],"verified")==0 || cached;
 if ((cached && argc != 10) || (!cached && argc != 9)) errx(1,"cache entries required only for cached mode");
 if (cached) entries=number(argv[9]);
 if (!verified && !range_baseline && strcmp(argv[7],"baseline")) errx(1,"invalid mode");
 slot=number(argv[8]);
 fd=open(argv[3],O_RDONLY|O_CLOEXEC); if(fd<0) err(1,"descriptor");
 n=read(fd,wire,sizeof(wire)); close(fd);
 if(n!=G_VERITY_ROOT_BYTES || g_verity_root_decode(wire,n,&root)) errx(1,"invalid descriptor");
 if (!request || request>SIZE_MAX || request>root.layout.data_bytes ||
     request%root.layout.block_size || !iterations) errx(1,"invalid workload");
 slots=(root.layout.data_bytes-request)/root.layout.block_size+1;
 if(slot>=slots || stride>=slots) errx(1,"slot/stride outside geometry");
 for(int i=0;i<2;i++) {
  in.fd[i]=open(argv[i+1],O_RDONLY|O_CLOEXEC);
  if(in.fd[i]<0 || fstat(in.fd[i],&st)) err(1,"input");
  if(!S_ISREG(st.st_mode) || (uint64_t)st.st_size !=
      (i ? root.layout.tree_bytes : root.layout.data_bytes)) errx(1,"input geometry");
 }
 data=malloc(root.layout.block_size);hash=malloc(root.layout.block_size);
 leaf=malloc(root.layout.block_size);output=malloc(request);
 if(!data || !hash || !leaf || !output) err(1,"malloc");
 if (cached) {
  if (entries > SIZE_MAX / root.layout.block_size) errx(1,"cache size overflow");
  if (entries != 0) {
   tags=malloc(entries * sizeof(*tags));blocks=malloc(entries * root.layout.block_size);
   if(!tags || !blocks) err(1,"cache allocation");
  }
  if(g_verity_cache_init(&cache,&root,tags,blocks,entries)) errx(1,"cache init");
 }
 wall=now(CLOCK_MONOTONIC);cpu=now(CLOCK_PROCESS_CPUTIME_ID);
 for(index=0;index<iterations;index++) {
  offset=slot*root.layout.block_size;
  if(verified) {
   if (cached)
    error=g_verity_cached_read_range(&cache,offset,request,read_block,&in,data,hash,output);
   else
    error=g_verity_read_range(root.layout.data_bytes,root.layout.block_size,
       root.salt,root.salt_len,root.root_hash,offset,request,read_block,&in,
       data,hash,leaf,output);
   if(error) errx(1,"verification: %s",strerror(error));
  } else if(range_baseline) {
   /* Ordinary contiguous read, without verifier block-sized syscall overhead. */
   error=read_block(&in,0,offset,output,request);
   if(error) errx(1,"range read: %s",strerror(error));
  } else {
   for(done=0;done<request;done+=root.layout.block_size) {
    error=read_block(&in,0,offset+done,data,root.layout.block_size);
    if(error) errx(1,"read: %s",strerror(error));
    memcpy(output+done,data,root.layout.block_size);
   }
  }
  /* Keep every output copy observable to the optimizer without timing I/O. */
  __asm__ __volatile__("" : : "r" (output) : "memory");
  slot=(slot+stride)%slots;
 }
 cpu=now(CLOCK_PROCESS_CPUTIME_ID)-cpu;wall=now(CLOCK_MONOTONIC)-wall;
 if(getrusage(RUSAGE_SELF,&usage)) err(1,"getrusage");
 printf("{\"mode\":\"%s\",\"request_bytes\":%" PRIu64 ",\"iterations\":%" PRIu64
     ",\"stride_blocks\":%" PRIu64 ",\"wall_seconds\":%.9f,\"cpu_seconds\":%.9f,"
     "\"data_calls\":%" PRIu64 ",\"hash_calls\":%" PRIu64
     ",\"data_bytes\":%" PRIu64 ",\"hash_bytes\":%" PRIu64
     ",\"maxrss_kib\":%ld,\"cache_entries\":%" PRIu64 "}\n",
     argv[7],request,iterations,stride,wall,cpu,in.calls[0],in.calls[1],
     in.bytes[0],in.bytes[1],usage.ru_maxrss,entries);
 for(int i=0;i<2;i++) close(in.fd[i]);
 free(blocks);free(tags);free(output);free(leaf);free(hash);free(data);
 return 0;
}
