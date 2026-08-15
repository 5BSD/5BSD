/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC SysV IPC Label Management
 *
 * Handles SysV IPC (message queues, semaphores, shared memory)
 * label lifecycle and access checks.
 * IPC object labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/ucred.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * ============================================================
 * SysV Message Queue Labels
 * ============================================================
 */

void
abac_sysvmsg_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_sysvmsg_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_sysvmsg_cleanup(struct label *msglabel)
{
	struct abac_label *vl;

	vl = SLOT(msglabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
abac_sysvmsg_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel, struct msg *msgptr, struct label *msglabel)
{
	struct abac_label *credlabel, *mlabel;

	if (cred == NULL || cred->cr_label == NULL || msglabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	mlabel = SLOT(msglabel);

	if (credlabel != NULL && mlabel != NULL)
		abac_label_copy(credlabel, mlabel);
}

/*
 * ============================================================
 * SysV Message Queue (msq) Labels and Checks
 * ============================================================
 */

void
abac_sysvmsq_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_sysvmsq_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_sysvmsq_cleanup(struct label *msqlabel)
{
	struct abac_label *vl;

	vl = SLOT(msqlabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
abac_sysvmsq_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqlabel)
{
	struct abac_label *credlabel, *mlabel;

	if (cred == NULL || cred->cr_label == NULL || msqlabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	mlabel = SLOT(msqlabel);

	if (credlabel != NULL && mlabel != NULL)
		abac_label_copy(credlabel, mlabel);
}

int
abac_sysvmsq_check_msgmsq(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msgrcv(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msglabel == NULL)
		return (0);
	obj = SLOT(msglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msgrmid(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msglabel == NULL)
		return (0);
	obj = SLOT(msglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_UNLINK, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msqget(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_OPEN, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msqctl(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel, int cmd)
{
	struct abac_label *subj, *obj;
	int error;
	uint32_t op;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* IPC_STAT is read, IPC_SET/IPC_RMID are write */
	op = (cmd == IPC_STAT) ? ABAC_OP_STAT : ABAC_OP_WRITE;
	error = abac_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msqrcv(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvmsq_check_msqsnd(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (msqklabel == NULL)
		return (0);
	obj = SLOT(msqklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_WRITE, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * ============================================================
 * SysV Semaphore Labels and Checks
 * ============================================================
 */

void
abac_sysvsem_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_sysvsem_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_sysvsem_cleanup(struct label *semalabel)
{
	struct abac_label *vl;

	vl = SLOT(semalabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
abac_sysvsem_create(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semalabel)
{
	struct abac_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || semalabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(semalabel);

	if (credlabel != NULL && slabel != NULL)
		abac_label_copy(credlabel, slabel);
}

int
abac_sysvsem_check_semctl(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, int cmd)
{
	struct abac_label *subj, *obj;
	int error;
	uint32_t op;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* IPC_STAT/GETVAL/etc are read, IPC_SET/IPC_RMID/SETVAL are write */
	switch (cmd) {
	case IPC_STAT:
	case GETVAL:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
	case GETALL:
		op = ABAC_OP_STAT;
		break;
	default:
		op = ABAC_OP_WRITE;
		break;
	}

	error = abac_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvsem_check_semget(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_OPEN, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvsem_check_semop(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, size_t accesstype)
{
	struct abac_label *subj, *obj;
	int error;
	uint32_t op;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (semaklabel == NULL)
		return (0);
	obj = SLOT(semaklabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* accesstype: SEM_R for read, SEM_A for alter */
	op = (accesstype & SEM_A) ? ABAC_OP_WRITE : ABAC_OP_READ;
	error = abac_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * ============================================================
 * SysV Shared Memory Labels and Checks
 * ============================================================
 */

void
abac_sysvshm_init_label(struct label *label)
{
	struct abac_label *vl;

	vl = abac_label_alloc(M_WAITOK);
	SLOT_SET(label, vl);
}

void
abac_sysvshm_destroy_label(struct label *label)
{
	struct abac_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		abac_label_free(vl);
	SLOT_SET(label, NULL);
}

void
abac_sysvshm_cleanup(struct label *shmlabel)
{
	struct abac_label *vl;

	vl = SLOT(shmlabel);
	if (vl != NULL)
		memset(vl, 0, sizeof(*vl));
}

void
abac_sysvshm_create(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmlabel)
{
	struct abac_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || shmlabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(shmlabel);

	if (credlabel != NULL && slabel != NULL)
		abac_label_copy(credlabel, slabel);
}

int
abac_sysvshm_check_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	struct abac_label *subj, *obj;
	int error;
	uint32_t op;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* SHM_RDONLY means read, otherwise read+write */
	op = (shmflg & SHM_RDONLY) ? ABAC_OP_READ : (ABAC_OP_READ | ABAC_OP_WRITE);
	error = abac_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvshm_check_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int cmd)
{
	struct abac_label *subj, *obj;
	int error;
	uint32_t op;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* IPC_STAT is read, IPC_SET/IPC_RMID are write */
	op = (cmd == IPC_STAT) ? ABAC_OP_STAT : ABAC_OP_WRITE;
	error = abac_rules_check(cred, subj, obj, op, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvshm_check_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Detach is always allowed if you have any access */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_READ, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_sysvshm_check_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_ENABLED();

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (shmseglabel == NULL)
		return (0);
	obj = SLOT(shmseglabel);
	if (obj == NULL)
		obj = &abac_default_object;

	error = abac_rules_check(cred, subj, obj, ABAC_OP_OPEN, NULL);

	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
