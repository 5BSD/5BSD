/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint32_t u32;
#define SIGTERM 15
#define BRCMF_SDIOD_NOMEDIUM 2
#define BRCMF_SDIOD_DOWN 0
#define SD_REG(r) 0
#define SBSDIO_FUNC1_CHIPCLKCSR 1
#define SBSDIO_HT_AVAIL_REQ 1
#define SBSDIO_FORCE_HT 2
#define brcmf_dbg(...) ((void)0)
#define brcmf_err(...) ((void)0)
struct device { void *data; };
struct brcmf_core { u32 base; };
struct brcmf_sdio {
 struct brcmf_core *sdio_core;void *watchdog_tsk,*ci,*glomd;
 int datawork,txq,rxctl_lock;u32 hostintmask,rxlen,tx_seq,rx_seq;bool rxskip;
};
struct brcmf_sdio_dev { struct brcmf_sdio *bus;int state;void *func1,*func2; };
struct brcmf_bus { struct { struct brcmf_sdio_dev *sdio; } bus_priv; };
static bool watchdog,irq,worker,host;
static unsigned freed,flushes,registers,wakes;
#define dev_get_drvdata(d) ((struct brcmf_bus *)(d)->data)
static void send_sig(int sig,void *t,int force) { (void)sig;(void)force;assert(t && watchdog); }
static void kthread_stop(void *t) { assert(t);watchdog=false; }
static void put_task_struct(void *t) { assert(t && !watchdog); }
static void brcmf_sdiod_intr_unregister(struct brcmf_sdio_dev *s) { (void)s;irq=false; }
static void brcmf_sdiod_change_state(struct brcmf_sdio_dev *s,int state) { s->state=state; }
static void cancel_work_sync(int *w) { (void)w;assert(!host && !watchdog && !irq);worker=false; }
static void sdio_claim_host(void *f) { (void)f;assert(!host);host=true; }
static void sdio_release_host(void *f) { (void)f;assert(host);host=false; }
static void brcmf_sdio_bus_sleep(struct brcmf_sdio *b,bool a,bool p) { (void)b;(void)a;(void)p;assert(host && !worker); }
static void brcmf_sdiod_writel(struct brcmf_sdio_dev *s,u32 a,u32 v,void *e) {
 (void)s;(void)a;(void)v;(void)e;assert(host && !worker);registers++;
}
static u8 brcmf_sdiod_readb(struct brcmf_sdio_dev *s,u32 a,int *e) { (void)s;(void)a;assert(host);*e=0;registers++;return 0; }
static void brcmf_sdiod_writeb(struct brcmf_sdio_dev *s,u32 a,u8 v,int *e) { (void)s;(void)a;(void)v;assert(host);*e=0;registers++; }
static bool brcmf_chip_is_ulp(void *c) { (void)c;return false; }
static void sdio_disable_func(void *f) { (void)f;assert(host && !worker); }
static void brcmu_pktq_flush(int *q,bool all,void *a,void *b) { (void)q;(void)all;(void)a;(void)b;assert(!worker && !host);flushes++; }
static void brcmu_pkt_buf_free_skb(void *p) { assert(!worker);if(p){assert(!freed);freed++;free(p);} }
static void brcmf_sdio_free_glom(struct brcmf_sdio *b) { (void)b;assert(!worker); }
#define spin_lock_bh(p) ((void)(p))
#define spin_unlock_bh(p) ((void)(p))
static void brcmf_sdio_dcmd_resp_wake(struct brcmf_sdio *b) { assert(!worker && b->rxlen==0);wakes++; }
#include "power_functions.h"
int main(void) {
 for(unsigned absent=0;absent<2;absent++) {
  struct brcmf_core core={0};
  struct brcmf_sdio bus={.sdio_core=&core,.watchdog_tsk=(void *)1,.glomd=malloc(1),.rxlen=99,.rxskip=true,.tx_seq=9,.rx_seq=7};
  struct brcmf_sdio_dev sd={.bus=&bus,.state=absent?BRCMF_SDIOD_NOMEDIUM:1};
  struct brcmf_bus b={.bus_priv={.sdio=&sd}};struct device dev={.data=&b};
  watchdog=irq=worker=true;freed=flushes=registers=wakes=0;
  brcmf_sdio_bus_stop(&dev);
  assert(!watchdog && !irq && !worker && !host && bus.glomd==NULL && freed==1);
  assert(bus.watchdog_tsk==NULL && bus.rxlen==0 && !bus.rxskip && !bus.tx_seq && !bus.rx_seq);
  if(absent)assert(registers==0 && sd.state==BRCMF_SDIOD_NOMEDIUM);
  else assert(registers>0 && sd.state==BRCMF_SDIOD_DOWN);
  brcmf_sdio_bus_stop(&dev);assert(freed==1 && flushes==2 && wakes==2);
 }
 puts("PASS: SDIO stop retires producers/RX before freeing queues, skips absent hardware and tolerates repeated cleanup");
 return 0;
}
