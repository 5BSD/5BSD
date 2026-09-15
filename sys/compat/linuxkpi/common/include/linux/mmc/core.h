/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_MMC_CORE_H_
#define _LINUXKPI_MMC_CORE_H_

#include <linux/types.h>
#include <linux/scatterlist.h>
#define mmc_command linux_mmc_command
#define mmc_data linux_mmc_data
#define mmc_request linux_mmc_request
#define MMC_RSP_PRESENT (1U << 0)
#define MMC_RSP_CRC (1U << 2)
#define MMC_RSP_OPCODE (1U << 4)
#define MMC_RSP_R5 (MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)
#define MMC_RSP_SPI_R5 ((1U << 7) | (1U << 8))
#define MMC_CMD_ADTC (1U << 5)
#define MMC_DATA_WRITE (1U << 8)
#define MMC_DATA_READ (1U << 9)
struct mmc_command {
	unsigned int opcode, arg, flags;
	u32 resp[4];
	int error;
};
struct mmc_data {
	unsigned int blksz, blocks, flags, sg_len, bytes_xfered;
	unsigned int timeout_ns, timeout_clks;
	struct scatterlist *sg;
	int error;
};
struct mmc_request {
	struct mmc_command *cmd, *stop;
	struct mmc_data *data;
};
struct mmc_card;
void linux_mmc_set_data_timeout(struct mmc_data *, const struct mmc_card *);
#define mmc_set_data_timeout linux_mmc_set_data_timeout

#endif
