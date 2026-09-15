/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_MMC_CARD_H_
#define _LINUXKPI_MMC_CARD_H_

#include <linux/device.h>
#include <linux/mmc/host.h>
#define sdio_func linux_sdio_func
#define MMC_QUIRK_LENIENT_FN0 (1U << 0)
struct sdio_func;
struct mmc_card {
	struct device dev;
	struct mmc_host *host;
	struct sdio_func *sdio_func[7];
	unsigned int quirks;
};
int linux_mmc_hw_reset(struct mmc_card *);
#define mmc_hw_reset linux_mmc_hw_reset

#endif
