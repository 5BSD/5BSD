/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_MMC_HOST_H_
#define _LINUXKPI_MMC_HOST_H_

#include <linux/device.h>
#include <linux/mmc/core.h>
#include <linux/mmc/pm.h>
#define mmc_host linux_mmc_host
#define MMC_CAP_NONREMOVABLE (1U << 8)
#define MMC_CAP_POWER_OFF_CARD (1U << 14)
struct mmc_request;
struct mmc_host {
	struct device *parent;
	unsigned int caps;
	unsigned int max_segs, max_seg_size, max_req_size;
	unsigned int max_blk_size, max_blk_count;
	mmc_pm_flag_t pm_caps;
	void *bsd_private;
};
void linux_mmc_wait_for_req(struct mmc_host *, struct mmc_request *);
#define mmc_wait_for_req linux_mmc_wait_for_req

#endif
