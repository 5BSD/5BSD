/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_MMC_SDIO_FUNC_H_
#define _LINUXKPI_MMC_SDIO_FUNC_H_

#include <linux/device.h>
#include <linux/mmc/core.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <linux/delay.h>
#include <sys/queue.h>
int linux_sdio_module_event(module_t, int, void *);
#define MODULE_DEVICE_TABLE_BUS_sdio(_bus, _table) \
    static moduledata_t lkpi_ ## _table ## _mod = { \
        "sdiob/lkpi_" #_table, linux_sdio_module_event, \
        __DECONST(void *, _table) \
    }; \
    DECLARE_MODULE(lkpi_ ## _table, lkpi_ ## _table ## _mod, \
        SI_SUB_DRIVERS, SI_ORDER_MIDDLE); \
    MODULE_PNP_INFO("U32:class;U32:vendor;U32:device", \
        sdiob, lkpi_ ## _table, _table, nitems(_table) - 1)
#define SDIO_ANY_ID (~0U)
struct sdio_device_id {
	unsigned int class, vendor, device;
	unsigned long driver_data;
};
#define SDIO_DEVICE(v, d) .class = SDIO_ANY_ID, .vendor = (v), .device = (d)
#define SDIO_DEVICE_CLASS(c) .class = (c), .vendor = SDIO_ANY_ID, .device = SDIO_ANY_ID
struct sdio_func;
typedef void (sdio_irq_handler_t)(struct sdio_func *);
struct sdio_func {
	struct mmc_card *card;
	struct device dev;
	unsigned int num;
	u8 class;
	u16 vendor, device;
	unsigned int max_blksize, cur_blksize, enable_timeout;
	sdio_irq_handler_t *irq_handler;
};
struct sdio_driver {
	const char *name;
	const struct sdio_device_id *id_table;
	int (*probe)(struct sdio_func *, const struct sdio_device_id *);
	void (*remove)(struct sdio_func *);
	void (*shutdown)(struct sdio_func *);
	struct device_driver drv;
	/* Native registration, owned by LinuxKPI. */
	driver_t bsd_driver;
	devclass_t bsd_class;
	TAILQ_ENTRY(sdio_driver) bsd_link;
	bool bsd_registered;
	bool bsd_unloading;
};
#define sdio_get_drvdata(f) dev_get_drvdata(&(f)->dev)
#define sdio_set_drvdata(f, d) dev_set_drvdata(&(f)->dev, (d))
#define dev_to_sdio_func(d) container_of(d, struct sdio_func, dev)
#define sdio_func_id(f) dev_name(&(f)->dev)
void linux_sdio_claim_host(struct sdio_func *);
#define sdio_claim_host linux_sdio_claim_host
void linux_sdio_release_host(struct sdio_func *);
#define sdio_release_host linux_sdio_release_host
int linux_sdio_enable_func(struct sdio_func *);
#define sdio_enable_func linux_sdio_enable_func
int linux_sdio_disable_func(struct sdio_func *);
#define sdio_disable_func linux_sdio_disable_func
int linux_sdio_set_block_size(struct sdio_func *, unsigned int);
#define sdio_set_block_size linux_sdio_set_block_size
int linux_sdio_claim_irq(struct sdio_func *, sdio_irq_handler_t *);
#define sdio_claim_irq linux_sdio_claim_irq
int linux_sdio_release_irq(struct sdio_func *);
#define sdio_release_irq linux_sdio_release_irq
unsigned int linux_sdio_align_size(struct sdio_func *, unsigned int);
#define sdio_align_size linux_sdio_align_size
u8 linux_sdio_readb(struct sdio_func *, unsigned int, int *);
#define sdio_readb linux_sdio_readb
u16 linux_sdio_readw(struct sdio_func *, unsigned int, int *);
#define sdio_readw linux_sdio_readw
u32 linux_sdio_readl(struct sdio_func *, unsigned int, int *);
#define sdio_readl linux_sdio_readl
void linux_sdio_writeb(struct sdio_func *, u8, unsigned int, int *);
#define sdio_writeb linux_sdio_writeb
void linux_sdio_writew(struct sdio_func *, u16, unsigned int, int *);
#define sdio_writew linux_sdio_writew
void linux_sdio_writel(struct sdio_func *, u32, unsigned int, int *);
#define sdio_writel linux_sdio_writel
u8 linux_sdio_f0_readb(struct sdio_func *, unsigned int, int *);
#define sdio_f0_readb linux_sdio_f0_readb
void linux_sdio_f0_writeb(struct sdio_func *, u8, unsigned int, int *);
#define sdio_f0_writeb linux_sdio_f0_writeb
int linux_sdio_memcpy_fromio(struct sdio_func *, void *, unsigned int, int);
#define sdio_memcpy_fromio linux_sdio_memcpy_fromio
int linux_sdio_memcpy_toio(struct sdio_func *, unsigned int, void *, int);
#define sdio_memcpy_toio linux_sdio_memcpy_toio
int linux_sdio_readsb(struct sdio_func *, void *, unsigned int, int);
#define sdio_readsb linux_sdio_readsb
int linux_sdio_writesb(struct sdio_func *, unsigned int, void *, int);
#define sdio_writesb linux_sdio_writesb
mmc_pm_flag_t linux_sdio_get_host_pm_caps(struct sdio_func *);
#define sdio_get_host_pm_caps linux_sdio_get_host_pm_caps
int linux_sdio_set_host_pm_flags(struct sdio_func *, mmc_pm_flag_t);
#define sdio_set_host_pm_flags linux_sdio_set_host_pm_flags
int linux_sdio_register_driver(struct sdio_driver *);
#define sdio_register_driver linux_sdio_register_driver
void linux_sdio_unregister_driver(struct sdio_driver *);
#define sdio_unregister_driver linux_sdio_unregister_driver
/* MMCCAM currently negotiates modes that do not require retuning. */
static inline void
sdio_retune_crc_disable(struct sdio_func *func)
{
	(void)func;
}
/* MMCCAM currently negotiates modes that do not require retuning. */
static inline void
sdio_retune_crc_enable(struct sdio_func *func)
{
	(void)func;
}
/* MMCCAM currently negotiates modes that do not require retuning. */
static inline void
sdio_retune_hold_now(struct sdio_func *func)
{
	(void)func;
}
/* MMCCAM currently negotiates modes that do not require retuning. */
static inline void
sdio_retune_release(struct sdio_func *func)
{
	(void)func;
}

#endif
