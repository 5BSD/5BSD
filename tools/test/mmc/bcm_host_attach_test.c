/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned u_int;
typedef int phandle_t;
typedef uint32_t pcell_t;
typedef void *device_t;
#define TRUE 1
#define BCM_DMA_CH_INVALID (-1)
#define BCM_DMA_CH_ANY (-1)
#define SDHCI_PLATFORM_TRANSFER 1
#define SDHCI_NON_REMOVABLE 2
#define SDHCI_CAN_VDD_330 1
#define SDHCI_CAN_VDD_180 2
#define SDHCI_CAN_DO_HISPD 4
#define SDHCI_CLOCK_BASE_SHIFT 8
#define SDHCI_BLOCK_SIZE 1
#define SDHCI_TRANSFER_MODE 2
#define SDHCI_BUFFER 32
#define BCM2835_MBOX_POWER_ID_EMMC 0
#define SYS_RES_MEMORY 1
#define SYS_RES_IRQ 2
#define RF_ACTIVE 1
#define RF_SHAREABLE 2
#define INTR_TYPE_BIO 1
#define INTR_MPSAFE 2
#define BUS_SPACE_MAXADDR UINT64_MAX
#define BCM_DMA_MAXSIZE 4096
#define ALLOCATED_DMA_SEGS 2
#define BCM_SDHCI_BUFFER_SIZE 512
#define BUS_DMA_ALLOCNOW 1
struct bcm_mmc_conf { int clock_id, default_freq, quirks; };
static struct bcm_mmc_conf conf = { 0, 50, 0 };
static struct { uintptr_t ocd_data; } compat = { (uintptr_t)&conf };
struct mmc_helper { void *vmmc_supply, *vqmmc_supply; };
struct sdhci_slot { unsigned opt,caps,quirks; int host; };
struct bcm_sdhci_softc {
 device_t sc_dev;
 void *sc_req,*sc_mem_res,*sc_irq_res,*sc_intrhand,*sc_bst;
 uintptr_t sc_bsh, sc_sdhci_buffer_phys;
 struct bcm_mmc_conf *conf;
 struct sdhci_slot sc_slot;
 struct mmc_helper sc_mmc_helper;
 int sc_dma_ch;
 void *sc_dma_tag,*sc_dma_map;
 unsigned blksz_and_count,cmd_and_mode;
};
static struct bcm_sdhci_softc host;
static int bootverbose, bcm2835_sdhci_pio_mode, bcm2835_sdhci_hs;
enum stage { OK, POWER, MEM, IRQ, SLOT, HANDLER, PARSE, CHANNEL, DMA_HANDLER, TAG, MAP };
static enum stage fail;
static bool memory,irq,slot,intr,channel,tag,map,started;
static unsigned regulators,dma_requests,cleanups;
static bool native_transfer;
#define device_get_softc(d) ((void)(d), &host)
#define ofw_bus_search_compatible(d,t) ((void)(d), &compat)
#define device_printf(...) ((void)0)
#define bcm2835_mbox_set_power_state(a,b) (fail==POWER ? EIO : 0)
static int get_freq(unsigned *f) { *f=50000000; return 0; }
#define bcm2835_mbox_get_clock_rate(id,f) get_freq(f)
#define ofw_bus_get_node(d) ((void)(d), 1)
#define OF_getencprop(n,p,v,l) ((void)(n),(void)(p),(void)(v),(void)(l),0)
#define OF_hasprop(n,p) ((void)(n),(void)(p),1)
static void *resource(int type, int *rid) {
 assert(*rid==0);
 if(type==SYS_RES_MEMORY) { if(fail==MEM)return NULL; assert(!memory); memory=true; }
 else { if(fail==IRQ)return NULL; assert(memory&&!irq);irq=true; }
 return (void *)(uintptr_t)type;
}
#define bus_alloc_resource_any(d,t,r,f) resource(t,r)
#define rman_get_bustag(r) (r)
#define rman_get_bushandle(r) ((uintptr_t)(r))
#define rman_get_start(r) ((uintptr_t)(r))
static int init_slot(struct sdhci_slot *s) {
 (void)s; assert(memory && irq && !intr && !slot);
 if(fail==SLOT)return EIO;
 slot=true;if(native_transfer)s->opt&=~SDHCI_PLATFORM_TRANSFER;return 0;
}
#define sdhci_init_slot(d,s,n) init_slot(s)
static int setup_intr(void **handle) {
 assert(slot&&!intr);if(fail==HANDLER)return EIO;
 intr=true;*handle=(void *)3;return 0;
}
#define bus_setup_intr(d,r,t,f,fn,a,h) setup_intr(h)
static int parse(struct mmc_helper *h) {
 assert(slot&&intr);if(fail==PARSE)return ENXIO;
 h->vmmc_supply=(void *)4;h->vqmmc_supply=(void *)5;regulators=2;return 0;
}
#define mmc_fdt_parse(d,n,h,s) parse(h)
static int allocate(void) {
 dma_requests++;assert(slot&&!channel);
 if(fail==CHANNEL)return BCM_DMA_CH_INVALID;
 channel=true;return 3;
}
#define bcm_dma_allocate(c) allocate()
#define bcm_dma_setup_intr(c,f,a) ((void)(c),(void)(a),fail==DMA_HANDLER ? -1 : 0)
static int tag_create(void **t) {
 assert(channel&&!tag);if(fail==TAG)return ENOMEM;
 tag=true;*t=(void *)6;return 0;
}
#define bus_dma_tag_create(a,b,c,d,e,f,g,h,i,j,k,l,m,t) tag_create(t)
static int map_create(void *t,void **m) {
 assert(t&&tag&&!map);if(fail==MAP)return ENOMEM;
 map=true;*m=(void *)7;return 0;
}
#define bus_dmamap_create(t,f,m) map_create(t,m)
#define SDHCI_READ_4(d,s,r) ((unsigned)(r)+100)
#define bus_identify_children(d) ((void)(d))
#define bus_attach_children(d) ((void)(d))
static void start_slot(struct sdhci_slot *s) {
 assert(slot&&intr&&s==&host.sc_slot);
 assert(host.blksz_and_count==101&&host.cmd_and_mode==102);
 if(s->opt&SDHCI_PLATFORM_TRANSFER)assert(channel&&tag&&map);
 else assert(!channel&&!tag&&!map);
 started=true;
}
#define sdhci_start_slot(s) start_slot(s)
static void teardown(void) { assert(intr&&slot&&!started);intr=false; }
#define bus_teardown_intr(d,r,h) teardown()
static void dma_free(int c) { assert(c==3&&channel&&!started);channel=false; }
#define bcm_dma_free(c) dma_free(c)
static void map_destroy(void) { assert(tag&&map&&!channel);map=false; }
#define bus_dmamap_destroy(t,m) map_destroy()
static void tag_destroy(void) { assert(tag&&!map&&!channel);tag=false; }
#define bus_dma_tag_destroy(t) tag_destroy()
static void cleanup_slot(void) { assert(slot&&!intr&&!channel&&!tag&&!map);slot=false;cleanups++; }
#define sdhci_cleanup_slot(s) cleanup_slot()
static void release_regulator(void *r) { assert(r&&regulators);regulators--; }
#define regulator_release(r) release_regulator(r)
static void release_resource(int type) {
 assert(!intr&&!slot&&!regulators);
 if(type==SYS_RES_IRQ){assert(irq);irq=false;}
 else {assert(memory&&!irq);memory=false;}
}
#define bus_release_resource(d,t,n,r) release_resource(t)
#include "power_functions.h"
static void reset(enum stage stage, bool pio) {
 memset(&host,0,sizeof(host));fail=stage;bcm2835_sdhci_pio_mode=pio;
 memory=irq=slot=intr=channel=tag=map=started=false;
 regulators=dma_requests=cleanups=0;native_transfer=false;
}
int main(void) {
 for(enum stage s=POWER;s<=MAP;s++) {
  reset(s,false);
  assert(bcm_sdhci_attach((void *)1)!=0);
  assert(!memory&&!irq&&!slot&&!intr&&!channel&&!tag&&!map&&!regulators&&!started);
  assert(cleanups==(s>SLOT ? 1u : 0u));
 }
 reset(OK,false);assert(bcm_sdhci_attach((void *)1)==0&&started&&dma_requests==1);
 /* A missing DMA controller cannot prevent a configured PIO boot. */
 reset(CHANNEL,true);assert(bcm_sdhci_attach((void *)1)==0&&started&&dma_requests==0);
 assert(host.sc_slot.opt&SDHCI_NON_REMOVABLE);
 /* Generic slot initialization may choose native SDMA instead of BCM DMA. */
 reset(CHANNEL,false);native_transfer=true;
 assert(bcm_sdhci_attach((void *)1)==0 && started && dma_requests==0);
 assert(!(host.sc_slot.opt&SDHCI_PLATFORM_TRANSFER));
 puts("PASS: host attach faults unwind all resources, initialize before IRQ, seed before CAM, and permit PIO without DMA");
 return 0;
}
