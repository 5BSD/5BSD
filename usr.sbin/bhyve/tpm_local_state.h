/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_TPM_LOCAL_STATE_H_
#define _BHYVE_TPM_LOCAL_STATE_H_

#include <stddef.h>
#include <stdint.h>

#define TPM_CRB_LOCAL_DATA_SIZE 0xf80U
#define TPM_PPI_LOCAL_DATA_SIZE 0x400U
#define TPM_CRB_LOCAL_STATE_SIZE (12U + 36U + TPM_CRB_LOCAL_DATA_SIZE)
#define TPM_PPI_LOCAL_STATE_SIZE (12U + TPM_PPI_LOCAL_DATA_SIZE)

struct tpm_crb_local_state {
	uint32_t loc_state;
	uint32_t loc_sts;
	uint32_t ctrl_sts;
	uint32_t cmd_size;
	uint64_t cmd_addr;
	uint32_t rsp_size;
	uint64_t rsp_addr;
	uint8_t data[TPM_CRB_LOCAL_DATA_SIZE];
};

int tpm_crb_local_state_encode(const struct tpm_crb_local_state *,
    uint8_t *, size_t);
int tpm_crb_local_state_decode(const uint8_t *, size_t,
    struct tpm_crb_local_state *);
int tpm_ppi_local_state_encode(const uint8_t *, size_t, uint8_t *, size_t);
int tpm_ppi_local_state_decode(const uint8_t *, size_t, uint8_t *, size_t);

#endif
