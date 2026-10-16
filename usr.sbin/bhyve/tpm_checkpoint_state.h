/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_TPM_CHECKPOINT_STATE_H_
#define _BHYVE_TPM_CHECKPOINT_STATE_H_

#include <stddef.h>
#include <stdint.h>

#define TPM_CHECKPOINT_BLOB_COUNT 3U
#define TPM_CHECKPOINT_STORAGE_ID_SIZE 16U
#define TPM_CHECKPOINT_KEY_ID_SIZE 16U
#define TPM_CHECKPOINT_HEADER_SIZE 84U

struct tpm_checkpoint_blob {
	const uint8_t *data;
	size_t length;
	uint32_t flags;
};

struct tpm_checkpoint_view {
	uint8_t storage_id[TPM_CHECKPOINT_STORAGE_ID_SIZE];
	uint8_t key_id[TPM_CHECKPOINT_KEY_ID_SIZE];
	const uint8_t *intf;
	size_t intf_length;
	const uint8_t *ppi;
	size_t ppi_length;
	/* Index zero is permanent, one volatile, two savestate. */
	struct tpm_checkpoint_blob blobs[TPM_CHECKPOINT_BLOB_COUNT];
};

int tpm_checkpoint_state_size(const struct tpm_checkpoint_view *, size_t *);
int tpm_checkpoint_state_encode(const struct tpm_checkpoint_view *,
    uint8_t *, size_t);
int tpm_checkpoint_state_decode(const uint8_t *, size_t,
    struct tpm_checkpoint_view *);
int tpm_checkpoint_storage_id_parse(const char *,
    uint8_t [TPM_CHECKPOINT_STORAGE_ID_SIZE]);

#endif
