/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_TPM_STATE_TRANSACTION_H_
#define _BHYVE_TPM_STATE_TRANSACTION_H_

enum tpm_state_phase {
	TPM_STATE_RUNNING = 0,
	TPM_STATE_QUIESCED,
	TPM_STATE_STOPPED,
	TPM_STATE_UNCERTAIN,
};

struct tpm_state_transaction {
	enum tpm_state_phase phase;
};

struct tpm_state_transaction_ops {
	int (*pause)(void *);
	int (*resume)(void *);
	int (*stop)(void *);
	int (*init)(void *);
};

int tpm_state_transaction_begin_read(struct tpm_state_transaction *,
    const struct tpm_state_transaction_ops *, void *, void *);
int tpm_state_transaction_begin_write(struct tpm_state_transaction *,
    const struct tpm_state_transaction_ops *, void *, void *);
int tpm_state_transaction_end(struct tpm_state_transaction *,
    const struct tpm_state_transaction_ops *, void *, void *);

#endif
