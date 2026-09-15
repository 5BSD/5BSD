/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define GFP_KERNEL 0
#define SD_IO_RW_EXTENDED 53
#define MMC_DATA_WRITE (1U << 8)
#define MMC_DATA_READ (1U << 9)
#define min(a,b) ((a) < (b) ? (a) : (b))
struct scatterlist { unsigned length; unsigned char *buf; struct scatterlist *next; };
#define sg_next(s) ((s)->next)
#define for_each_sg(list, s, count, i) \
 for ((i)=0, (s)=(list); (i)<(count); (i)++, (s)=sg_next(s))
struct sdio_func { unsigned cur_blksize; };
struct mmc_host {
 void *bsd_private;
 unsigned max_blk_count, max_blk_size, max_req_size, max_segs, max_seg_size;
};
struct lkpi_sdio_card { struct { struct sdio_func *sdio_func[7]; } card; };
struct mmc_command { unsigned opcode, arg; int error; };
struct mmc_data {
 unsigned blksz, blocks, flags, sg_len, bytes_xfered;
 struct scatterlist *sg;
 int error;
};
struct mmc_request { struct mmc_command *cmd, *stop; struct mmc_data *data; };
static unsigned allocations, io_calls;
static bool fail_alloc, expected_write, expected_increment;
static int io_error;
static unsigned expected_length;
static unsigned char storage[1024], payload[1024];
static void *kmalloc(unsigned length, unsigned flags) {
 (void)flags; if (fail_alloc) return NULL; allocations++; return malloc(length);
}
static void kfree(void *p) { assert(allocations); allocations--; free(p); }
static unsigned copy_sg(struct scatterlist *s, unsigned n, void *buffer,
 unsigned length, bool to_buffer) {
 unsigned copied = 0;
 for (unsigned i = 0; i < n && copied < length && s; i++, s = s->next) {
  unsigned part = min(s->length, length-copied);
  if (to_buffer) memcpy((char *)buffer+copied, s->buf, part);
  else memcpy(s->buf, (char *)buffer+copied, part);
  copied += part;
 }
 return copied;
}
static unsigned sg_pcopy_to_buffer(struct scatterlist *s, unsigned n,
 void *b, unsigned len, unsigned skip) {
 assert(skip == 0); return copy_sg(s,n,b,len,true);
}
static unsigned sg_copy_from_buffer(struct scatterlist *s, unsigned n,
 void *b, unsigned len) { return copy_sg(s,n,b,len,false); }
static int lkpi_sdio_transfer(struct sdio_func *f, unsigned addr, void *b,
 unsigned length, bool write, bool increment) {
 assert(f && addr == 0x120 && length == expected_length);
 assert(write == expected_write && increment == expected_increment);
 io_calls++;
 if (io_error) return io_error;
 if (write) assert(memcmp(b,payload,length) == 0);
 else memcpy(b,payload,length);
 return 0;
}
#include "power_functions.h"
static struct sdio_func func = { .cur_blksize = 512 };
static struct lkpi_sdio_card card;
static struct mmc_host host;
static struct mmc_command cmd;
static struct mmc_data data;
static struct mmc_request request;
static struct scatterlist sg[2];
static void setup(bool write) {
 assert(allocations == 0);
 host = (struct mmc_host){ &card, 511, 512, 4096, 2, 4096 };
 card.card.sdio_func[0] = &func;
 cmd = (struct mmc_command){ SD_IO_RW_EXTENDED,
  (write ? 1U<<31 : 0) | 1U<<28 | 1U<<27 | 0x120<<9 | 2, 99 };
 sg[0] = (struct scatterlist){ 300, storage, &sg[1] };
 sg[1] = (struct scatterlist){ 724, storage+300, NULL };
 data = (struct mmc_data){ 512, 2, write ? MMC_DATA_WRITE : MMC_DATA_READ, 2, 99, sg, 99 };
 request = (struct mmc_request){ &cmd, NULL, &data };
 for (unsigned i=0; i<sizeof(payload); i++) payload[i] = i*17;
 memset(storage,0xa5,sizeof(storage));
 if (write) memcpy(storage,payload,sizeof(storage));
 io_calls=0; io_error=0; fail_alloc=false;
 expected_write=write; expected_increment=false; expected_length=1024;
}
static void rejected(void) {
 linux_mmc_wait_for_req(&host,&request);
 assert(cmd.error == -EINVAL && data.bytes_xfered == 0);
 assert(io_calls == 0 && allocations == 0);
}
int main(void) {
 /* Short read destinations must not consume the device's FIFO. */
 setup(false); sg[1].length--; rejected();
 for (unsigned i=0; i<sizeof(storage); i++) assert(storage[i] == 0xa5);
 setup(true); sg[1].length--; rejected();
 setup(false); cmd.arg--; rejected(); /* encoded blocks disagree */
 setup(false); cmd.arg &= ~0x1ffU; rejected(); /* unbounded block transfer */
 setup(false); data.blksz=256; rejected(); /* card block size disagrees */
 setup(false); data.blksz=1024; rejected();
 setup(false); data.blocks=UINT32_MAX; rejected();
 setup(false); data.flags=MMC_DATA_WRITE; rejected();
 setup(false); host.max_segs=1; rejected();
 setup(false); host.max_seg_size=512; rejected();
 setup(false); sg[0].next=NULL; rejected();
 setup(false); request.stop=&cmd; rejected();
 setup(false); cmd.arg &= ~(7U<<28); rejected();
 setup(false); cmd.arg |= 7U<<28; rejected();
 setup(false); cmd.opcode=52; rejected();
 setup(false); data.sg_len=0; rejected();
 setup(false); data.blocks=0; rejected();
 setup(false); data.blksz=0; rejected();
 for (unsigned write=0; write<2; write++) {
  setup(write); linux_mmc_wait_for_req(&host,&request);
  assert(cmd.error == 0 && data.bytes_xfered == 1024 && io_calls == 1);
  assert(memcmp(storage,payload,sizeof(storage)) == 0 && allocations == 0);
 }
 /* Byte mode's encoded zero means exactly 512 bytes. */
 setup(false); cmd.arg &= ~((1U<<27)|0x1ffU); cmd.arg |= 1U<<26;
 data.blocks=1; data.sg_len=1; sg[0].length=512;
 expected_length=512; expected_increment=true;
 linux_mmc_wait_for_req(&host,&request);
 assert(cmd.error == 0 && data.bytes_xfered == 512 && io_calls == 1);
 setup(false); cmd.arg &= ~(1U<<27); rejected(); /* byte mode with two blocks */
 setup(false); fail_alloc=true; linux_mmc_wait_for_req(&host,&request);
 assert(cmd.error == -ENOMEM && !io_calls && !data.bytes_xfered);
 setup(false); io_error=-EIO; linux_mmc_wait_for_req(&host,&request);
 assert(cmd.error == -EIO && io_calls == 1 && !data.bytes_xfered && !allocations);
 for (unsigned i=0; i<sizeof(storage); i++) assert(storage[i] == 0xa5);
 puts("PASS: MMC command/SG bounds before I/O, scatter copies, byte/block counts, allocation and transfer failures");
 return 0;
}
