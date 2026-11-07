/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: what other kernel subsystems may ask of a served
 * descriptor.  Compiled in under `device dq` (opt_dq.h: DEV_DQ).
 */

#ifndef _DEV_DQ_DQ_KERN_H_
#define	_DEV_DQ_DQ_KERN_H_

#ifdef _KERNEL

#include <dev/dq/dq.h>

struct file;
struct ucred;

/*
 * The served mark is fp->f_type == DTYPE_DQ, but only an object carries an
 * identity (an observer descriptor does not), so this function also asks
 * the table: a descriptor that is not a dq object answers ENOTTY.  On
 * success *ident is a copy of the presented identity, *objectp the object
 * id on its queue and *noncep the controller's identity nonce (0 if none).
 * No lock is held on return; the identity may change again afterwards.
 */
int	dq_file_ident(struct file *fp, struct dq_ident_file *ident,
	    uint64_t *objectp, uint64_t *noncep);

/*
 * The controller's credential (B9): what a MAC policy evaluates a requester
 * against for a served file whose object carries no label of its own
 * (D22).  Valid while fp is held; NULL for a descriptor that is not a dq
 * object.  Never a reference: do not crfree it.
 */
struct ucred *dq_file_cred(struct file *fp);

#endif /* _KERNEL */
#endif /* !_DEV_DQ_DQ_KERN_H_ */
