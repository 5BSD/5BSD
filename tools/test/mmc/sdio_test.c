/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MMCCAM 1
#include "../../../sys/dev/mmc/mmcreg.h"
typedef void *device_t;
#include "../../../sys/dev/sdio/sdio_subr.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#define KASSERT(condition, message) assert(condition)
#define CAM_DEBUG(...) ((void)0)
#define device_printf(...) ((void)0)
#define device_get_softc(dev) (dev)
#define device_get_parent(dev) (dev)
#define CAM_PRIORITY_NORMAL 0
#define CAM_FLAG_NONE 0
#define CAM_DIR_NONE 0
#define CAM_DIR_IN 1
#define CAM_DIR_OUT 2
#define SA_XLOCKED 1

struct sx { pthread_mutex_t mutex; };
struct cam_periph { void *path; pthread_mutex_t mutex; };
struct ccb_hdr { void *path; };
struct ccb_mmcio { struct ccb_hdr ccb_h; struct mmc_command cmd; };
union ccb { struct ccb_hdr ccb_h; struct ccb_mmcio mmcio; };
struct sdiob_softc {
	struct sx host_lock;
	struct card_info cardinfo;
	struct cam_periph *periph;
	union ccb *ccb;
	device_t dev;
};
static struct sdiob_softc bus;
static struct cam_periph periph;
static _Thread_local unsigned host_depth, path_depth;
static unsigned maxphys = 128 * 1024;
static unsigned calls;
static int cam_error, command_error;
static uint32_t response;
static bool concurrent;
static atomic_int active, attempted;
struct transfer { uint32_t arg, len, blksz, blocks, flags; uint8_t *data; };
static struct transfer transfers[2048];

static void
sx_xlock(struct sx *lock)
{
	assert(!path_depth);
	assert(pthread_mutex_lock(&lock->mutex) == 0);
	host_depth++;
}

static void
sx_xunlock(struct sx *lock)
{
	assert(host_depth && !path_depth);
	host_depth--;
	assert(pthread_mutex_unlock(&lock->mutex) == 0);
}

static void
sx_assert(struct sx *lock, int assertion)
{
	(void)lock;
	assert(assertion == SA_XLOCKED && host_depth);
}

static void
cam_periph_lock(struct cam_periph *p)
{
	assert(host_depth && !path_depth);
	assert(pthread_mutex_lock(&p->mutex) == 0);
	path_depth++;
}

static void
cam_periph_unlock(struct cam_periph *p)
{
	assert(path_depth == 1);
	path_depth--;
	assert(pthread_mutex_unlock(&p->mutex) == 0);
}

static union ccb *
xpt_alloc_ccb(void)
{
	union ccb *ccb = calloc(1, sizeof(*ccb));
	assert(ccb != NULL);
	return (ccb);
}

static void
xpt_setup_ccb(struct ccb_hdr *h, void *path, int priority)
{
	(void)priority;
	h->path = path;
}

static void
cam_fill_mmcio(struct ccb_mmcio *io, int retries, void *callback,
    unsigned direction, uint32_t opcode, uint32_t arg, uint32_t flags,
    struct mmc_data *data, unsigned timeout)
{
	(void)retries; (void)callback; (void)direction; (void)timeout;
	io->cmd.opcode = opcode;
	io->cmd.arg = arg;
	io->cmd.flags = flags;
	io->cmd.data = data;
}

static int sdioerror(union ccb *c, unsigned a, unsigned b)
{
	(void)c; (void)a; (void)b;
	return (0);
}

static int
cam_periph_runccb(union ccb *ccb,
    int (*errorfn)(union ccb *, unsigned, unsigned), unsigned flags,
    unsigned sense, void *stats)
{
	struct mmc_command *cmd = &ccb->mmcio.cmd;
	uint32_t arg = cmd->arg;
	(void)errorfn; (void)flags; (void)sense; (void)stats;
	assert(path_depth && host_depth);
	assert(atomic_fetch_add(&active, 1) == 0);
	assert(calls < nitems(transfers));
	transfers[calls].arg = arg;
	if (cmd->data != NULL) {
		transfers[calls].len = cmd->data->len;
		transfers[calls].blksz = cmd->data->block_size;
		transfers[calls].blocks = cmd->data->block_count;
		transfers[calls].flags = cmd->data->flags;
		transfers[calls].data = cmd->data->data;
	}
	calls++;
	/* Model CAM waiting for completion with its path mutex released. */
	cam_periph_unlock(&periph);
	if (concurrent) {
		struct timespec delay = { .tv_nsec = 1000000 };
		while (atomic_load(&attempted) != 2)
			sched_yield();
		nanosleep(&delay, NULL);
	}
	assert(host_depth && cmd->arg == arg);
	cam_periph_lock(&periph);
	cmd->error = command_error;
	cmd->resp[0] = response;
	assert(atomic_fetch_sub(&active, 1) == 1);
	return (cam_error);
}

#define SDIO_CLAIM_HOST sdiob_claim_host
#define SDIO_RELEASE_HOST sdiob_release_host
#define SDIO_READ_DIRECT sdiob_read_direct
#define SDIO_WRITE_DIRECT sdiob_write_direct
#define sdio_get_support_multiblk(dev) (((struct sdiob_softc *)(dev))->cardinfo.support_multiblk)
#include "sdt_test.h"
#include "power_functions.h"

static void
reset(void)
{
	assert(!host_depth && !path_depth);
	calls = 0;
	cam_error = command_error = 0;
	response = 0;
	concurrent = false;
	memset(transfers, 0, sizeof(transfers));
	bus.cardinfo.support_multiblk = true;
	for (unsigned i = 0; i < nitems(bus.cardinfo.f); i++) {
		bus.cardinfo.f[i].dev = &bus;
		bus.cardinfo.f[i].fn = i;
		bus.cardinfo.f[i].cur_blksize = 512;
		bus.cardinfo.f[i].max_blksize = 2048;
	}
}

static void
error_tests(void)
{
	static const struct { uint32_t response; int error; } cases[] = {
		{ 0xab, 0 }, { R5_IO_CURRENT_STATE_MASK | 0xff, 0 },
		{ R5_COM_CRC_ERROR, EILSEQ }, { R5_ILLEGAL_COMMAND, EIO },
		{ R5_ERROR, EIO }, { R5_FUNCTION_NUMBER, EINVAL },
		{ R5_OUT_OF_RANGE, ERANGE },
	};
	uint8_t value, buffer[4];
	for (unsigned i = 0; i < nitems(cases); i++) {
		reset(); response = cases[i].response; value = 0x42;
		assert(sdiob_read_direct(&bus, 1, 0x20, &value) == cases[i].error);
		assert(value == (cases[i].error ? 0x42 : (response & 0xff)));
		assert(sdiob_write_direct(&bus, 1, 0x20, 0x55) == cases[i].error);
		assert(sdiob_rw_extended(&bus, 1, 0x20, false, 4, buffer, true) == cases[i].error);
	}
	reset(); cam_error = ENXIO;
	assert(sdiob_read_direct(&bus, 1, 0, &value) == ENXIO);
	command_error = MMC_ERR_TIMEOUT;
	assert(sdiob_read_direct(&bus, 1, 0, &value) == ETIMEDOUT);
	command_error = MMC_ERR_BADCRC;
	assert(sdiob_rw_extended(&bus, 1, 0, true, 4, buffer, false) == EILSEQ);
	command_error = MMC_ERR_FIFO;
	assert(sdiob_read_direct(&bus, 1, 0, &value) == EIO);
	reset();
	assert(sdiob_read_direct(&bus, 8, 0, &value) == EINVAL);
	assert(sdiob_read_direct(&bus, 1, 0x20000, &value) == EINVAL);
	assert(calls == 0);
}

static void
transfer_tests(void)
{
	uint8_t *buffer = calloc(1, 512 * 600);
	assert(buffer != NULL);
	reset(); bus.cardinfo.support_multiblk = false;
	bus.cardinfo.f[1].cur_blksize = 1024;
	assert(sdiob_rw_extended(&bus, 1, 0x20, false, 1025, buffer, true) == 0);
	assert(calls == 3);
	assert((transfers[0].arg & 0x1ff) == 0 && transfers[0].len == 512);
	assert(transfers[0].blksz == 512 && transfers[0].blocks == 1);
	assert(transfers[0].flags & MMC_DATA_BLOCK_SIZE);
	assert(((transfers[1].arg >> 9) & 0x1ffff) == 0x220);
	assert(transfers[2].len == 1 && transfers[2].data == buffer + 1024);
	reset();
	assert(sdiob_rw_extended(&bus, 2, 0x100, true, 512 * 600, buffer, false) == 0);
	assert(calls == 3);
	for (unsigned i = 0; i < calls; i++) {
		assert(transfers[i].arg & SD_IOE_RW_BLK);
		assert(((transfers[i].arg >> 9) & 0x1ffff) == 0x100);
		assert(transfers[i].len <= maxphys);
		assert(transfers[i].blocks <= 511);
		assert(transfers[i].blksz == 512);
	}
	reset(); bus.cardinfo.f[1].cur_blksize = 0;
	assert(sdiob_rw_extended(&bus, 1, 0, false, 1, buffer, true) == EINVAL);
	assert(sdiob_rw_extended(&bus, 1, 0, false, 0, NULL, true) == 0);
	assert(sdiob_rw_extended(&bus, 8, 0, false, 1, buffer, true) == EINVAL);
	assert(sdiob_rw_extended(&bus, 1, 0x1ffff, false, 2, buffer, true) == ERANGE);
	assert(calls == 0);
	reset(); response = R5_ERROR;
	assert(sdiob_rw_extended(&bus, 2, 0, false, 512 * 600, buffer, false) == EIO);
	assert(calls == 1);
	free(buffer);
}

static void *
concurrent_reader(void *arg)
{
	uint8_t value;
	uint8_t fn = (uintptr_t)arg;
	atomic_fetch_add(&attempted, 1);
	sdio_claim_host(&bus.cardinfo.f[fn]);
	assert(sdiob_read_direct(&bus, fn, 0x10 * fn, &value) == 0);
	assert(sdiob_read_direct(&bus, fn, 0x10 * fn + 1, &value) == 0);
	sdio_release_host(&bus.cardinfo.f[fn]);
	return (NULL);
}

static void
claim_tests(void)
{
	pthread_t first, second;
	reset(); concurrent = true;
	assert(pthread_create(&first, NULL, concurrent_reader, (void *)1) == 0);
	assert(pthread_create(&second, NULL, concurrent_reader, (void *)2) == 0);
	assert(pthread_join(first, NULL) == 0);
	assert(pthread_join(second, NULL) == 0);
	assert(calls == 4 && atomic_load(&active) == 0);
	assert((transfers[0].arg >> 28) == (transfers[1].arg >> 28));
	assert((transfers[2].arg >> 28) == (transfers[3].arg >> 28));
	reset();
	assert(sdio_enable_func(&bus.cardinfo.f[1]) == 0 && calls == 2);
	assert((transfers[1].arg & 0xff) == 2);
	assert(sdio_set_block_size(&bus.cardinfo.f[1], 0x123) == 0);
	assert((transfers[2].arg & 0xff) == 0x23);
	assert((transfers[3].arg & 0xff) == 1);
	assert(bus.cardinfo.f[1].cur_blksize == 0x123);
	assert(sdio_set_block_size(&bus.cardinfo.f[1], 0) == EINVAL);
	reset(); response = R5_ERROR;
	assert(sdio_enable_func(&bus.cardinfo.f[1]) == EIO);
	assert(sdio_set_block_size(&bus.cardinfo.f[1], 256) == EIO);
	assert(bus.cardinfo.f[1].cur_blksize == 512);
	assert(!host_depth && !path_depth);
}

static void
boundary_tests(void)
{
 uint8_t buffer[8193];
 const unsigned blocks[]={1,3,4,64,512,1024,4096};
 for (unsigned b=0;b<nitems(blocks);b++) {
  const unsigned sizes[]={1,4,blocks[b],blocks[b]+1,2*blocks[b]+1};
  for (unsigned n=0;n<nitems(sizes);n++) {
   reset();sdt_count=0;bus.cardinfo.f[1].cur_blksize=blocks[b];
   unsigned length=sizes[n],addr=0x20000-length,total=0;
   assert(sdiob_rw_extended(&bus,1,addr,false,length,buffer,true)==0);
   for (unsigned i=0;i<calls;i++) {
    assert(((transfers[i].arg>>9)&0x1ffff)==addr+total);
    assert(transfers[i].len && transfers[i].len<=maxphys);
    total+=transfers[i].len;
   }
   assert(total==length);
   reset();sdt_count=0;
   assert(sdiob_rw_extended(&bus,1,addr,true,length+1,buffer,true)==ERANGE && calls==0);
  }
 }
}

static void
probe_tests(void)
{
	uint8_t buffer[1025] = {0};
	reset(); sdt_count = 0;
	assert(sdiob_write_direct(&bus, 2, 0x1234, 0xab) == 0);
	assert(sdt_count == 2);
	assert(strcmp(sdt_events[0].name, "command__start") == 0);
	assert(sdt_events[0].args[0] == (uintptr_t)&bus);
	assert(sdt_events[0].args[1] == SD_IO_RW_DIRECT);
	assert(sdt_events[0].args[2] == 2 && sdt_events[0].args[3] == 0x1234);
	assert(sdt_events[0].args[4] == 1 && sdt_events[0].args[5] == 1);
	assert(strcmp(sdt_events[1].name, "command__done") == 0);
	assert(sdt_events[1].args[2] == 0);
	/* Failed commands must close the pair with the translated errno. */
	command_error = MMC_ERR_TIMEOUT;
	assert(sdiob_rw_extended(&bus, 1, 0x40, false, 4, buffer, true) == ETIMEDOUT);
	assert(sdt_count == 4 && sdt_events[2].args[1] == SD_IO_RW_EXTENDED);
	assert(sdt_events[2].args[4] == 0 && sdt_events[2].args[5] == 4);
	assert(sdt_events[3].args[2] == ETIMEDOUT);
	reset(); sdt_count = 0;
	assert(sdiob_rw_extended(&bus, 1, 0x40, true, sizeof(buffer), buffer, true) == 0);
	unsigned total = 0;
	assert(sdt_count == calls * 2);
	for (unsigned i = 0; i < sdt_count; i += 2) {
		assert(strcmp(sdt_events[i].name, "command__start") == 0);
		assert(sdt_events[i].args[3] == 0x40 + total);
		total += sdt_events[i].args[5];
		assert(strcmp(sdt_events[i + 1].name, "command__done") == 0);
		assert(sdt_events[i + 1].args[2] == 0);
	}
	assert(total == sizeof(buffer));
	/* Invalid input does not pretend to have issued a CAM command. */
	sdt_count = 0;
	assert(sdiob_read_direct(&bus, 8, 0, buffer) == EINVAL);
	assert(sdt_count == 0);
}

int
main(void)
{
	pthread_mutexattr_t attr;
	assert(pthread_mutexattr_init(&attr) == 0);
	assert(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
	assert(pthread_mutex_init(&bus.host_lock.mutex, &attr) == 0);
	assert(pthread_mutexattr_destroy(&attr) == 0);
	assert(pthread_mutex_init(&periph.mutex, NULL) == 0);
	bus.periph = &periph;
	error_tests(); transfer_tests(); claim_tests(); boundary_tests(); probe_tests();
	free(bus.ccb);
	assert(pthread_mutex_destroy(&periph.mutex) == 0);
	assert(pthread_mutex_destroy(&bus.host_lock.mutex) == 0);
	puts("PASS: SDIO status decoding, transfer limits, FIFO/incrementing access, host claims across CAM waits, register updates");
	return (0);
}
