/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <machine/vmm.h>

#include "vmm_intinfo.h"

#define	IDT_VE	20	/* Virtualization Exception (Intel specific). */

enum exc_class {
	EXC_BENIGN,
	EXC_CONTRIBUTORY,
	EXC_PAGEFAULT
};

static int
intinfo_validate(uint64_t info)
{
	uint32_t type, vector;

	if ((info & VM_INTINFO_VALID) == 0)
		return (info == 0 ? 0 : EINVAL);
	if ((info >> 32) != 0 && (info & VM_INTINFO_DEL_ERRCODE) == 0)
		return (EINVAL);
	if ((info & VM_INTINFO_RSVD) != 0)
		return (EINVAL);
	type = info & VM_INTINFO_TYPE;
	vector = VM_INTINFO_VECTOR(info);
	if ((type == VM_INTINFO_NMI && vector != IDT_NMI) ||
	    (type == VM_INTINFO_HWEXCEPTION && vector >= 32))
		return (EINVAL);
	return (0);
}

static enum exc_class
exception_class(uint64_t info)
{
	uint32_t type, vector;

	type = info & VM_INTINFO_TYPE;
	vector = VM_INTINFO_VECTOR(info);

	/* Intel SDM, Volume 3, Table 6-4. */
	switch (type) {
	case VM_INTINFO_HWINTR:
	case VM_INTINFO_SWINTR:
	case VM_INTINFO_NMI:
		return (EXC_BENIGN);
	default:
		/*
		 * SVM and VT-x share the values for NMI, hardware interrupt,
		 * and software interrupt.  SVM uses type 3 for all exceptions,
		 * while VT-x gives #BP and #OF software-exception types.
		 */
		break;
	}

	switch (vector) {
	case IDT_PF:
	case IDT_VE:
		return (EXC_PAGEFAULT);
	case IDT_DE:
	case IDT_TS:
	case IDT_NP:
	case IDT_SS:
	case IDT_GP:
		return (EXC_CONTRIBUTORY);
	default:
		return (EXC_BENIGN);
	}
}

int
vm_intinfo_plan(uint64_t info1, uint64_t info2,
    struct vm_intinfo_plan *plan)
{
	struct vm_intinfo_plan candidate;
	enum exc_class exc1, exc2;
	uint32_t type1, vector1;
	int error;

	if (plan == NULL)
		return (EINVAL);
	error = intinfo_validate(info1);
	if (error == 0)
		error = intinfo_validate(info2);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	if ((info1 & VM_INTINFO_VALID) == 0) {
		if ((info2 & VM_INTINFO_VALID) != 0) {
			candidate.entry = info2;
			candidate.valid = true;
		}
		*plan = candidate;
		return (0);
	}
	if ((info2 & VM_INTINFO_VALID) == 0) {
		candidate.entry = info1;
		candidate.valid = true;
		*plan = candidate;
		return (0);
	}

	/*
	 * An exception while delivering #DF enters shutdown (triple fault).
	 */
	type1 = info1 & VM_INTINFO_TYPE;
	vector1 = VM_INTINFO_VECTOR(info1);
	if (type1 == VM_INTINFO_HWEXCEPTION && vector1 == IDT_DF) {
		candidate.triple_fault = true;
		*plan = candidate;
		return (0);
	}

	/* Intel SDM, Volume 3, Table 6-5. */
	exc1 = exception_class(info1);
	exc2 = exception_class(info2);
	if ((exc1 == EXC_CONTRIBUTORY && exc2 == EXC_CONTRIBUTORY) ||
	    (exc1 == EXC_PAGEFAULT && exc2 != EXC_BENIGN)) {
		candidate.entry = IDT_DF | VM_INTINFO_VALID |
		    VM_INTINFO_HWEXCEPTION | VM_INTINFO_DEL_ERRCODE;
	} else {
		candidate.entry = info2;
	}
	candidate.valid = true;
	*plan = candidate;
	return (0);
}
