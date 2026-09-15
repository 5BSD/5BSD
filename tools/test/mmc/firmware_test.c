/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#ifndef __DECONST
#define __DECONST(t, p) ((t)(uintptr_t)(p))
#endif
#define M_LKPI_FW 0
#define M_WAITOK 1
#define M_ZERO 2
#define GFP_KERNEL 0
#define FIRMWARE_GET_NOWARN 0
#define KASSERT(condition, message) assert(condition)
#define device_printf(...) ((void)0)
#define linux_set_current(td) ((void)(td))
#define curthread NULL
typedef unsigned gfp_t;
struct device {
 int refs; void *bsddev;
 int (*bsd_async_get)(struct device *);
 void (*bsd_async_put)(struct device *);
};
struct module { int unused; };
struct linker_file { int refs; };
typedef struct linker_file *linker_file_t;
static struct linker_file module = { .refs = 1 };
static bool module_present = true;
static int async_refs, async_error, unbinds;
static bool unbind_requested;
static int linker_file_foreach(int (*fn)(linker_file_t, void *), void *arg) {
 return module_present ? fn(&module, arg) : 0;
}
static int linker_release_module(void *name, void *version, linker_file_t file) {
 (void)name; (void)version; assert(file->refs > 1); file->refs--; return 0;
}
static int async_get(struct device *dev) {
 (void)dev;
 if (async_error) return async_error;
 async_refs++; return 0;
}
static void async_put(struct device *dev) {
 (void)dev; assert(async_refs > 0 && module.refs > 1);
 if (--async_refs == 0 && unbind_requested) { unbinds++; unbind_requested = false; }
}
struct firmware { const void *data; size_t datasize; };
struct linuxkpi_firmware { const struct firmware *fbdfw; const uint8_t *data; size_t size; };
struct task { void (*fn)(void *, int); void *arg; };
struct lkpi_fw_task {
	struct task fw_task;
	gfp_t gfp;
	char *fw_name;
	struct device *dev;
	linker_file_t module;
	void *drv;
	void (*cont)(const struct linuxkpi_firmware *, void *);
};
static unsigned allocations, callbacks;
static int enqueue_error;
static bool present;
static struct task *queued;
static const char expected[] = "brcm/brcmfmac43455-sdio.raspberrypi,4-model-b.bin";
static const struct firmware firmware = { .data = "firmware", .datasize = 8 };
static const struct linuxkpi_firmware *delivered;
static void *alloc(size_t n) { void *p = calloc(1, n); assert(p); allocations++; return p; }
static void dealloc(void *p) { if (p) { assert(allocations > 0); allocations--; free(p); } }
static char *dupstr(const char *s) { char *p = alloc(strlen(s) + 1); strcpy(p, s); return p; }
#define malloc(n, type, flags) alloc(n)
#define free(p, type) dealloc(p)
#define strdup(s, type) dupstr(s)
#define TASK_INIT(t, pri, f, a) do { (t)->fn = (f); (t)->arg = (a); } while (0)
#define taskqueue_thread NULL
static int taskqueue_enqueue(void *q, struct task *t) {
	(void)q;
	if (enqueue_error) return enqueue_error;
	assert(queued == NULL); queued = t; return 0;
}
static struct device *get_device(struct device *d) { d->refs++; return d; }
static void put_device(struct device *d) { assert(--d->refs >= 1); }
static const struct firmware *firmware_get_flags(const char *name, uint32_t flags) {
	(void)flags;
	return present && strcmp(name, expected) == 0 ? &firmware : NULL;
}
#include "sdt_test.h"
#include "power_functions.h"
static void callback(const struct linuxkpi_firmware *fw, void *arg) {
	struct device *dev = arg;
	assert(sdt_count >= 3);
	assert(strcmp(sdt_events[sdt_count - 1].name, "callback__start") == 0);
	assert(sdt_events[sdt_count - 1].args[0] == (uintptr_t)dev);
	assert(strcmp((const char *)sdt_events[sdt_count - 1].args[1], expected) == 0);
	assert(sdt_events[sdt_count - 1].args[2] == (fw != NULL));
	assert(dev->refs == 2); callbacks++; delivered = fw;
}
static void failing_callback(const struct linuxkpi_firmware *fw, void *arg) {
 assert(fw == NULL); assert(async_refs == 1 && module.refs == 2);
 unbind_requested = true;
 assert(unbinds == 0);
 callback(fw, arg);
}
static void chained_callback(const struct linuxkpi_firmware *fw, void *arg) {
 assert(fw == NULL && async_refs == 1 && module.refs == 2);
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, arg, GFP_KERNEL, arg, failing_callback) == 0);
 assert(async_refs == 2 && module.refs == 3);
}
static void freeing_callback(const struct linuxkpi_firmware *fw, void *arg) {
 callback(fw, arg);
 dealloc(__DECONST(void *, fw));
}
static void run_queued(void) {
	struct task *t = queued;
	assert(t != NULL); queued = NULL; t->fn(t->arg, 1);
}
int main(void) {
	struct device dev = { .refs = 1 };
	char *name = dupstr(expected);
	present = true;
	assert(linuxkpi_request_firmware_nowait(NULL, true, name, &dev,
	    GFP_KERNEL, &dev, callback) == 0);
	assert(dev.refs == 2);
	memset(name, 'x', strlen(name)); dealloc(name);
	run_queued();
	assert(sdt_count == 4);
	assert(strcmp(sdt_events[0].name, "request__start") == 0);
	assert(strcmp(sdt_events[1].name, "request__done") == 0);
	assert(sdt_events[1].args[2] == 0 && sdt_events[1].args[3] == 8);
	assert(strcmp(sdt_events[3].name, "callback__done") == 0);
	assert(callbacks == 1 && delivered && delivered->size == 8);
	assert(memcmp(delivered->data, "firmware", 8) == 0);
	dealloc(__DECONST(void *, delivered));
	assert(dev.refs == 1 && allocations == 0);
	/* A failed load must allow brcmfmac's NULL-based filename fallback. */
	present = false;
	assert(linuxkpi_request_firmware_nowait(NULL, true, expected, &dev,
	    GFP_KERNEL, &dev, callback) == 0);
	run_queued();
	assert(callbacks == 2 && delivered == NULL);
	assert(sdt_count == 8 && (int)sdt_events[5].args[2] == -ENOENT);
	assert(sdt_events[5].args[3] == 0);
	assert(dev.refs == 1 && allocations == 0);
	/* Failed submission must neither call back nor retain the request. */
	enqueue_error = EBUSY;
	assert(linuxkpi_request_firmware_nowait(NULL, true, expected, &dev,
	    GFP_KERNEL, &dev, callback) == -EBUSY);
	assert(queued == NULL && callbacks == 2 && dev.refs == 1 && allocations == 0);
	assert(linuxkpi_request_firmware_nowait(NULL, true, NULL, &dev,
	    GFP_KERNEL, &dev, callback) == -EINVAL);
	/* Retain both code and bus-private state through failure callback return. */
 enqueue_error = 0;
 dev.bsd_async_get = async_get; dev.bsd_async_put = async_put;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, failing_callback) == 0);
 assert(module.refs == 2 && async_refs == 1); /* unload must be busy */
 run_queued();
 assert(module.refs == 1 && async_refs == 0 && unbinds == 1);
 assert(allocations == 0 && dev.refs == 1);
 /* A fallback queued by the callback inherits uninterrupted protection. */
 unbinds = 0;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, chained_callback) == 0);
 run_queued();
 assert(module.refs == 2 && async_refs == 1 && queued != NULL);
 run_queued();
 assert(module.refs == 1 && async_refs == 0 && unbinds == 1 && allocations == 0);
 /* Submission failures release every acquired reference, exactly once. */
 enqueue_error = EBUSY;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, callback) == -EBUSY);
 assert(module.refs == 1 && async_refs == 0 && allocations == 0);
 async_error = -ENODEV;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, callback) == -ENODEV);
 assert(module.refs == 1 && async_refs == 0 && allocations == 0 && dev.refs == 1);
 module_present = false;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, callback) == -ENODEV);
 assert(module.refs == 1 && allocations == 0 && queued == NULL);
 /* callback__done must not dereference firmware released by the callback. */
 module_present = present = true; enqueue_error = async_error = 0;
 sdt_count = 0;
 assert(linuxkpi_request_firmware_nowait((struct module *)&module, true,
     expected, &dev, GFP_KERNEL, &dev, freeing_callback) == 0);
 run_queued();
 assert(sdt_count == 4 && strcmp(sdt_events[3].name, "callback__done") == 0);
 assert(allocations == 0 && dev.refs == 1 && module.refs == 1);
 puts("PASS: firmware filename/device/module ownership, deferred unbind, missing firmware and submission failures");
	return 0;
}
