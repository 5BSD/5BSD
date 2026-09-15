/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define KASSERT(c, m) assert(c)
#define DS_ATTACHING 1
#define DS_ATTACHED 2
#define MOD_LOAD 1
#define MOD_QUIESCE 2
#define MOD_UNLOAD 3
#define MOD_SHUTDOWN 4
#define M_WAITOK 0
#define PWAIT 0
#define SDIOB_NAME_S "sdiob"
#define max(a,b) ((a) > (b) ? (a) : (b))
#define hz 100
#define device_printf(...) ((void)0)
#define linux_set_current(t) ((void)0)
#define curthread NULL
#define taskqueue_thread_enqueue NULL
typedef void *module_t;
typedef void *devclass_t;
struct sdio_func;
struct lkpi_sdio_softc;
struct native_device { int state; struct lkpi_sdio_softc *sc; };
typedef struct native_device *device_t;
struct device_driver { int unused; };
struct device { int refs; device_t bsddev; struct device_driver *driver; struct sdio_func *func; };
struct timeout_task { int c; bool queued; };
struct taskqueue { int unused; };
struct lkpi_sdio_card {
 TAILQ_ENTRY(lkpi_sdio_card) link;
 struct { struct device dev; struct sdio_func *sdio_func[7]; } card;
 unsigned users, async_users, probing, unbind_pending;
 struct timeout_task unbind_task;
 bool unbind_scheduled, detaching, stopping;
};
struct sdio_func { struct device dev; struct lkpi_sdio_card *card; unsigned num; };
struct sdio_driver {
 void (*remove)(struct sdio_func *);
 struct device_driver drv;
 const void *id_table;
 const char *name;
 int bsd_driver;
 bool bsd_registered, bsd_unloading;
 TAILQ_ENTRY(sdio_driver) bsd_link;
};
struct lkpi_sdio_softc { struct lkpi_sdio_card *card; struct sdio_func *func; struct sdio_driver *driver; };
static TAILQ_HEAD(, lkpi_sdio_card) lkpi_sdio_cards = TAILQ_HEAD_INITIALIZER(lkpi_sdio_cards);
static TAILQ_HEAD(, sdio_driver) lkpi_sdio_drivers = TAILQ_HEAD_INITIALIZER(lkpi_sdio_drivers);
static struct taskqueue queue;
static struct taskqueue *lkpi_sdio_unbind_queue = &queue;
static unsigned lkpi_sdio_unbind_jobs;
static struct lkpi_sdio_card card;
static struct sdio_func funcs[2];
static struct native_device natives[2];
static struct lkpi_sdio_softc softc[2];
static int locks, removed[2], nremoved, drains, delete_error, queue_frees;
static bool reject_reentry;
static void bus_topo_lock(void) { locks++; }
static void bus_topo_unlock(void) { assert(locks > 0); locks--; }
static void bus_topo_assert(void) { assert(locks > 0); }
static struct lkpi_sdio_card *lkpi_sdio_card(struct sdio_func *f) { return f->card; }
#define dev_to_sdio_func(d) ((d)->func)
static struct device *get_device(struct device *d) { d->refs++; return d; }
static void put_device(struct device *d) { assert(d->refs > 0); d->refs--; }
static void *device_get_softc(device_t d) { return d->sc; }
static int device_detach(device_t);
static int lkpi_sdio_async_get(struct device *);
static void driver_remove(struct sdio_func *f) {
 assert(card.async_users == 0 && card.probing == 0 && card.detaching);
 if (reject_reentry) assert(lkpi_sdio_async_get(&f->dev) == -ENODEV);
 assert(nremoved < 2); removed[nremoved++] = f->num;
}
static const int table;
static struct sdio_driver driver = { .remove = driver_remove, .id_table = &table, .name = "test_sdio" };
static void linux_sdio_release_irq(struct sdio_func *f) { (void)f; }
static void lkpi_devres_release_free_list(struct device *d) { (void)d; }
static void lkpi_sdio_card_put(struct lkpi_sdio_card *c) {
 assert(c->async_users == 0 && c->users > 0);
 if (--c->users == 0) { c->stopping = true; TAILQ_REMOVE(&lkpi_sdio_cards,c,link); }
}
static void callout_drain(int *c) { (void)c; drains++; }
static int taskqueue_enqueue_timeout(struct taskqueue *q, struct timeout_task *t, int delay) {
 assert(q == &queue && delay > 0); t->queued = true; return 0;
}
static struct taskqueue *taskqueue_create(const char *n, int f, void *e, void *c) {
 (void)n; (void)f; (void)e; (void)c; return &queue;
}
static int taskqueue_start_threads(struct taskqueue **q, int n, int p, const char *name) {
 (void)q; (void)n; (void)p; (void)name; return 0;
}
static void taskqueue_free(struct taskqueue *q) {
 assert(q == &queue && lkpi_sdio_unbind_jobs == 0 && !card.unbind_task.queued);
 queue_frees++;
}
static devclass_t devclass_find(const char *name) { (void)name; return &queue; }
static int devclass_delete_driver(devclass_t dc, int *drv) {
 (void)dc; assert(drv == &driver.bsd_driver);
 if (delete_error) return delete_error;
 for (unsigned i = 0; i < 2; i++) {
  int error = device_detach(&natives[i]); if (error) return error;
 }
 return 0;
}
#include "sdt_test.h"
#include "power_functions.h"
static int device_detach(device_t d) {
 int error;
 bus_topo_assert();
 if (d->state == DS_ATTACHING) return EBUSY;
 if (d->state != DS_ATTACHED) return 0;
 error = lkpi_sdio_detach(d);
 if (error == 0) d->state = 0;
 return error;
}
static void run_job(void) {
 assert(card.unbind_task.queued); card.unbind_task.queued = false;
 lkpi_sdio_unbind_task(&card, 1);
}
static void reset(void) {
 assert(lkpi_sdio_unbind_jobs == 0);
 memset(&card, 0, sizeof(card));
 card.users = 2; card.card.dev.refs = 1;
 TAILQ_INIT(&lkpi_sdio_cards); TAILQ_INSERT_TAIL(&lkpi_sdio_cards,&card,link);
 TAILQ_INIT(&lkpi_sdio_drivers); TAILQ_INSERT_TAIL(&lkpi_sdio_drivers,&driver,bsd_link);
 driver.bsd_registered = true; driver.bsd_unloading = false;
 lkpi_sdio_unbind_queue = &queue;
 nremoved = drains = delete_error = 0; reject_reentry = true;
 for (int i = 0; i < 2; i++) {
  natives[i] = (struct native_device){ .state = DS_ATTACHED, .sc = &softc[i] };
  funcs[i] = (struct sdio_func){ .dev = { .refs = 1, .bsddev = &natives[i],
      .driver = &driver.drv, .func = &funcs[i] }, .card = &card, .num = i + 1 };
  softc[i] = (struct lkpi_sdio_softc){ .card = &card, .func = &funcs[i], .driver = &driver };
  card.card.sdio_func[i] = &funcs[i];
 }
}
int main(void) {
 reset();
 assert(lkpi_sdio_async_get(&funcs[0].dev) == 0);
 assert(lkpi_sdio_async_get(&funcs[0].dev) == 0);
 bus_topo_lock(); assert(device_detach(&natives[0]) == EBUSY); assert(device_detach(&natives[1]) == EBUSY); bus_topo_unlock();
 lkpi_sdio_release_driver(&funcs[1].dev); lkpi_sdio_release_driver(&funcs[0].dev);
 assert(nremoved == 0 && card.unbind_pending == 3 && lkpi_sdio_unbind_jobs == 1 && card.card.dev.refs == 2);
 assert(linux_sdio_module_event(NULL,MOD_QUIESCE,(void *)&table) == EBUSY);
 assert(linux_sdio_module_event(NULL,MOD_UNLOAD,(void *)&table) == EBUSY);
 assert(lkpi_sdio_modevent(NULL,MOD_UNLOAD,NULL) == EBUSY);
 assert(lkpi_sdio_async_get(&funcs[0].dev) == -ENODEV);
 run_job(); assert(nremoved == 0 && card.unbind_task.queued);
 lkpi_sdio_async_put(&funcs[0].dev); run_job(); assert(nremoved == 0);
 lkpi_sdio_async_put(&funcs[0].dev); run_job();
 assert(nremoved == 2 && removed[0] == 2 && removed[1] == 1);
 assert(card.stopping && card.async_users == 0 && card.unbind_pending == 0);
 assert(locks == 0 && card.card.dev.refs == 1 && lkpi_sdio_unbind_jobs == 0);
 /* Inline firmware submission failure while F2's probe is still running. */
 reset(); card.probing = 1; natives[1].state = DS_ATTACHING;
 lkpi_sdio_release_driver(&funcs[1].dev); lkpi_sdio_release_driver(&funcs[0].dev);
 run_job(); assert(nremoved == 0 && card.unbind_pending == 3);
 card.probing = 0;
 run_job(); assert(nremoved == 0 && card.unbind_pending == 3); /* newbus still attaching */
 natives[1].state = DS_ATTACHED;
 run_job(); assert(nremoved == 2 && card.stopping && drains == 3);
 assert(card.card.dev.refs == 1 && lkpi_sdio_unbind_jobs == 0);
 /* A manual detach in progress must veto both normal and forced unload. */
 reset(); card.detaching = true;
 assert(linux_sdio_module_event(NULL,MOD_QUIESCE,(void *)&table) == EBUSY);
 assert(linux_sdio_module_event(NULL,MOD_UNLOAD,(void *)&table) == EBUSY);
 assert(driver.bsd_registered && nremoved == 0);
 card.detaching = false; card.probing = 1;
 assert(linux_sdio_module_event(NULL,MOD_UNLOAD,(void *)&table) == EBUSY);
 card.probing = 0; delete_error = EBUSY;
 assert(linux_sdio_module_event(NULL,MOD_UNLOAD,(void *)&table) == EBUSY);
 assert(driver.bsd_registered && !driver.bsd_unloading && nremoved == 0);
 delete_error = 0;
 assert(linux_sdio_module_event(NULL,MOD_UNLOAD,(void *)&table) == 0);
 assert(!driver.bsd_registered && nremoved == 2 && TAILQ_EMPTY(&lkpi_sdio_drivers));
 linux_sdio_unregister_driver(&driver); /* subsequent SYSUNINIT is idempotent */
 assert(nremoved == 2);
 assert(lkpi_sdio_modevent(NULL,MOD_UNLOAD,NULL) == 0 && queue_frees == 1);
 puts("PASS: SDIO callback/probe exclusion, deferred retry after inline failure, unload veto, detach error propagation and worker lifetime");
 return 0;
}
