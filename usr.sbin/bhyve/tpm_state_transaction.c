/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>

#include "tpm_state_transaction.h"

static int
tpm_state_ops_validate(const struct tpm_state_transaction_ops *ops,
    void *intf, void *backend)
{

	if (ops == NULL || intf == NULL || backend == NULL ||
	    ops->pause == NULL || ops->resume == NULL || ops->stop == NULL ||
	    ops->init == NULL)
		return (EOPNOTSUPP);
	return (0);
}

int
tpm_state_transaction_begin_read(struct tpm_state_transaction *transaction,
    const struct tpm_state_transaction_ops *ops, void *intf, void *backend)
{
	int error;

	if (transaction == NULL)
		return (EINVAL);
	if (transaction->phase != TPM_STATE_RUNNING)
		return (transaction->phase >= TPM_STATE_QUIESCED &&
		    transaction->phase <= TPM_STATE_UNCERTAIN ? EBUSY : EPROTO);
	error = tpm_state_ops_validate(ops, intf, backend);
	if (error != 0)
		return (error);
	error = ops->pause(intf);
	if (error != 0)
		return (error);
	transaction->phase = TPM_STATE_QUIESCED;
	return (0);
}

int
tpm_state_transaction_begin_write(struct tpm_state_transaction *transaction,
    const struct tpm_state_transaction_ops *ops, void *intf, void *backend)
{
	int error;

	if (transaction == NULL)
		return (EINVAL);
	if (transaction->phase == TPM_STATE_RUNNING) {
		error = tpm_state_transaction_begin_read(transaction, ops, intf,
		    backend);
		if (error != 0)
			return (error);
	} else if (transaction->phase != TPM_STATE_QUIESCED)
		return (transaction->phase == TPM_STATE_STOPPED ||
		    transaction->phase == TPM_STATE_UNCERTAIN ? EBUSY : EPROTO);
	error = tpm_state_ops_validate(ops, intf, backend);
	if (error != 0)
		return (error);
	error = ops->stop(backend);
	if (error != 0) {
		/* STOP may have committed before its reply was lost. */
		transaction->phase = TPM_STATE_UNCERTAIN;
		return (error);
	}
	transaction->phase = TPM_STATE_STOPPED;
	return (0);
}

int
tpm_state_transaction_end(struct tpm_state_transaction *transaction,
    const struct tpm_state_transaction_ops *ops, void *intf, void *backend)
{
	int error;

	if (transaction == NULL)
		return (EINVAL);
	if (transaction->phase != TPM_STATE_QUIESCED &&
	    transaction->phase != TPM_STATE_STOPPED)
		return (transaction->phase == TPM_STATE_RUNNING ? EINVAL :
		    EPROTO);
	error = tpm_state_ops_validate(ops, intf, backend);
	if (error != 0)
		return (error);
	if (transaction->phase == TPM_STATE_STOPPED) {
		error = ops->init(backend);
		if (error != 0) {
			/* INIT may have committed before its reply was lost. */
			transaction->phase = TPM_STATE_UNCERTAIN;
			return (error);
		}
		transaction->phase = TPM_STATE_QUIESCED;
	}
	error = ops->resume(intf);
	if (error == 0)
		transaction->phase = TPM_STATE_RUNNING;
	return (error);
}
