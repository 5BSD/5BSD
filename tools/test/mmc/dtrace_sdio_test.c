/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include "sdt_test.h"
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define nitems(x) (sizeof(x) / sizeof((x)[0]))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define linux_set_current(td) ((void)0)
#define curthread NULL
#define max(a,b) ((a) > (b) ? (a) : (b))
#define hz 1000
#define SDIO_CCCR_INTx 5
typedef uint8_t u8;
typedef void *device_t;
struct device { void *driver; };
struct sdio_func { unsigned num; struct device dev; void (*irq_handler)(struct sdio_func *); };
struct lkpi_sdio_card {
 struct { struct sdio_func *sdio_func[7]; } card;
 unsigned probing; bool stopping; device_t bus;
 void *irq_queue; int irq_task;
};
struct sdio_driver {
 int bsd_driver, drv; bool bsd_unloading;
 int (*probe)(struct sdio_func *, const void *);
};
struct lkpi_sdio_softc {
 struct sdio_driver *driver; struct lkpi_sdio_card *card; struct sdio_func *func;
};
static struct lkpi_sdio_softc sc;
static struct lkpi_sdio_card card;
static struct sdio_driver driver;
static struct sdio_func func = {.num = 1};
static unsigned fn = 1, holds, releases, cleanups, irq_calls, polls, enqueues;
static bool no_card;
static int probe_error, poll_error;
static struct sdio_driver *device_get_driver(device_t dev) { (void)dev; return (void *)&driver.bsd_driver; }
static struct lkpi_sdio_softc *device_get_softc(device_t dev) { (void)dev; return &sc; }
static unsigned sdio_get_funcnum(device_t dev) { (void)dev; return fn; }
static device_t device_get_parent(device_t dev) { return dev; }
static struct lkpi_sdio_card *lkpi_sdio_card_get(device_t dev) { (void)dev; return no_card ? NULL : &card; }
static void lkpi_sdio_card_put(struct lkpi_sdio_card *c) { assert(c == &card); releases++; }
static const void *lkpi_sdio_match(device_t dev, struct sdio_driver *d) { (void)dev; assert(d == &driver); return &func; }
static void linux_sdio_release_irq(struct sdio_func *f) { assert(f == &func); }
static void lkpi_devres_release_free_list(struct device *d) { assert(d == &func.dev); cleanups++; }
static int probe(struct sdio_func *f, const void *id) { assert(f == &func && id == &func && card.probing == 1); return probe_error; }
static void irq(struct sdio_func *f) { assert(f == &func && holds == 1); irq_calls++; }
static void claim(device_t bus) { assert(bus == &card && holds++ == 0); }
static void release(device_t bus) { assert(bus == &card && --holds == 0); }
#define SDIO_CLAIM_HOST claim
#define SDIO_RELEASE_HOST release
static int read_direct(device_t bus, unsigned f, unsigned addr, u8 *status) {
 assert(bus == &card && f == 0 && addr == SDIO_CCCR_INTx && holds == 1);
 polls++; if (poll_error == 0) *status = 2; return poll_error;
}
#define SDIO_READ_DIRECT read_direct
static void taskqueue_enqueue_timeout(void *queue, int *task, unsigned ticks) {
 (void)queue; assert(task == &card.irq_task && ticks == 10); enqueues++;
}
#include "power_functions.h"
int main(void) {
 driver.probe = probe; card.card.sdio_func[0] = &func; card.bus = &card;
 const int expected[] = {EBUSY, ENOMEM, ENXIO, EIO, 0};
 for (unsigned i = 0; i < nitems(expected); i++) {
  sdt_count = 0; driver.bsd_unloading = i == 0; no_card = i == 1;
  fn = i == 2 ? 8 : 1; probe_error = i == 3 ? -EIO : 0;
  assert(lkpi_sdio_attach(&sc) == expected[i]);
  assert(sdt_count == 2 && card.probing == 0);
  assert(strcmp(sdt_events[0].name, "attach__start") == 0);
  assert(sdt_events[0].args[1] == fn);
  assert(strcmp(sdt_events[1].name, "attach__done") == 0);
  assert(sdt_events[1].args[0] == (uintptr_t)&sc);
  assert(sdt_events[1].args[1] == (uintptr_t)expected[i]);
 }
 assert(releases == 2 && cleanups == 1);
 func.irq_handler = irq; sdt_count = 0;
 lkpi_sdio_irq_task(&card, 1);
 assert(sdt_count == 2 && irq_calls == 1 && enqueues == 1 && holds == 0);
 assert(strcmp(sdt_events[0].name, "irq__poll") == 0);
 assert(sdt_events[0].args[1] == 0 && sdt_events[0].args[2] == 2);
 assert(strcmp(sdt_events[1].name, "irq__dispatch") == 0);
 assert(sdt_events[1].args[0] == (uintptr_t)&func);
 poll_error = EIO; sdt_count = 0;
 lkpi_sdio_irq_task(&card, 1);
 assert(sdt_count == 1 && sdt_events[0].args[1] == EIO);
 assert(sdt_events[0].args[2] == 0 && irq_calls == 1 && enqueues == 2);
 card.stopping = true; sdt_count = 0;
 lkpi_sdio_irq_task(&card, 1);
 assert(sdt_count == 0 && holds == 0 && polls == 2);
 puts("PASS: SDT attach success/failures, IRQ status/error/dispatch and stopped polling");
 return 0;
}
