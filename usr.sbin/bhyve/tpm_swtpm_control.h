/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_TPM_SWTPM_CONTROL_H_
#define _BHYVE_TPM_SWTPM_CONTROL_H_

#include <sys/types.h>

#include <stdint.h>

#define SWTPM_CONTROL_BLOB_PERMANENT 1U
#define SWTPM_CONTROL_BLOB_VOLATILE 2U
#define SWTPM_CONTROL_BLOB_SAVESTATE 3U
#define SWTPM_CONTROL_STATE_DECRYPTED 1U
#define SWTPM_CONTROL_STATE_ENCRYPTED 2U
/* swtpm's non-CUSE SET_STATEBLOB rejects payloads above 512 KiB. */
#define SWTPM_CONTROL_MAX_BLOB (512U * 1024U)

#define SWTPM_CONTROL_CAP_INIT (1U << 0)
#define SWTPM_CONTROL_CAP_GET_STATEBLOB (1U << 8)
#define SWTPM_CONTROL_CAP_SET_STATEBLOB (1U << 9)
#define SWTPM_CONTROL_CAP_STOP (1U << 10)
#define SWTPM_CONTROL_CAP_GET_CONFIG (1U << 11)
#define SWTPM_CONTROL_CAP_LOCK_STORAGE (1U << 16)
#define SWTPM_CONTROL_CONFIG_MIGRATION_KEY (1U << 1)

int tpm_swtpm_control_capabilities(int fd, uint32_t *caps);
int tpm_swtpm_control_get_config(int fd, uint32_t *flags);
int tpm_swtpm_control_get_blob(int fd, uint32_t type, uint8_t **blob,
    size_t *length, uint32_t *flags);
int tpm_swtpm_control_blob_validate(uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags);
int tpm_swtpm_control_set_blob(int fd, uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags);
int tpm_swtpm_control_stop(int fd);
int tpm_swtpm_control_init(int fd, uint32_t flags);
int tpm_swtpm_control_lock_storage(int fd, uint32_t retries);

#endif
