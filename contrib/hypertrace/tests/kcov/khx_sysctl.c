/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * sysctl(9) support for the kernel-source harness: the static OID linker
 * set, a lookup helper, a kernel-buffer request (sysctl_old_kernel /
 * sysctl_new_kernel semantics from kern_sysctl.c) and the scalar/string
 * handlers with kern_sysctl.c's contracts.  Not production code.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include "khx_kern.h"

struct sysctl_oid sysctl___dev;
struct sysctl_oid sysctl___debug;
struct sysctl_oid sysctl___kern;
struct sysctl_oid sysctl___security;
struct sysctl_oid sysctl___security_bsd;

SET_DECLARE(sysctl_set, struct sysctl_oid);

/* Keep the set present even when a suite defines no OIDs. */
static int khx_sysctl_dummy_val;
SYSCTL_INT(_debug, OID_AUTO, khx_sysctl_dummy, CTLFLAG_RD,
    &khx_sysctl_dummy_val, 0, "harness");

struct sysctl_oid *
khx_sysctl_find(const char *parent, const char *name)
{
	struct sysctl_oid **oidp, **pp, *p;

	SET_FOREACH(oidp, sysctl_set) {
		if (strcmp((*oidp)->oid_name, name) != 0)
			continue;
		if (parent == NULL)
			return (*oidp);
		/* oid_parent points at the parent node's children list. */
		SET_FOREACH(pp, sysctl_set) {
			p = *pp;
			if (&p->oid_children == (*oidp)->oid_parent &&
			    strcmp(p->oid_name, parent) == 0)
				return (*oidp);
		}
		if (strcmp(parent, "dev") == 0 &&
		    (*oidp)->oid_parent == &sysctl___dev.oid_children)
			return (*oidp);
		if (strcmp(parent, "kern") == 0 &&
		    (*oidp)->oid_parent == &sysctl___kern.oid_children)
			return (*oidp);
		if (strcmp(parent, "debug") == 0 &&
		    (*oidp)->oid_parent == &sysctl___debug.oid_children)
			return (*oidp);
	}
	return (NULL);
}

static int
khx_old_kernel(struct sysctl_req *req, const void *p, size_t l)
{
	size_t i = 0;

	if (req->oldptr) {
		i = l;
		if (req->oldlen <= req->oldidx)
			i = 0;
		else if (i > req->oldlen - req->oldidx)
			i = req->oldlen - req->oldidx;
		if (i > 0)
			bcopy(p, (char *)req->oldptr + req->oldidx, i);
	}
	req->oldidx += l;
	if (req->oldptr && i != l)
		return (ENOMEM);
	return (0);
}

static int
khx_new_kernel(struct sysctl_req *req, void *p, size_t l)
{
	if (!req->newptr)
		return (0);
	if (req->newlen - req->newidx < l)
		return (EINVAL);
	bcopy((const char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (0);
}

int
khx_sysctl_call(struct sysctl_oid *oid, struct thread *td, void *old,
    size_t *oldlen, const void *new, size_t newlen)
{
	struct sysctl_req req;
	int error;

	memset(&req, 0, sizeof(req));
	req.td = td;
	req.oldptr = old;
	req.oldlen = oldlen != NULL ? *oldlen : 0;
	req.oldfunc = khx_old_kernel;
	req.newptr = new;
	req.newlen = newlen;
	req.newfunc = khx_new_kernel;
	req.validlen = req.oldlen;
	error = oid->oid_handler(oid, oid->oid_arg1, oid->oid_arg2, &req);
	if (oldlen != NULL)
		*oldlen = req.oldidx;
	return (error);
}

int
sysctl_handle_int(SYSCTL_HANDLER_ARGS)
{
	int tmpout, error;

	tmpout = arg1 ? *(int *)arg1 : (int)arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(int));
	if (error || !req->newptr)
		return (error);
	return (!arg1 ? EPERM : SYSCTL_IN(req, arg1, sizeof(int)));
}

int
sysctl_handle_32(SYSCTL_HANDLER_ARGS)
{
	int32_t tmpout;
	int error;

	tmpout = arg1 ? *(int32_t *)arg1 : (int32_t)arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(tmpout));
	if (error || !req->newptr)
		return (error);
	return (!arg1 ? EPERM : SYSCTL_IN(req, arg1, sizeof(tmpout)));
}

int
sysctl_handle_64(SYSCTL_HANDLER_ARGS)
{
	uint64_t tmpout;
	int error;

	tmpout = arg1 ? *(uint64_t *)arg1 : (uint64_t)arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(tmpout));
	if (error || !req->newptr)
		return (error);
	return (!arg1 ? EPERM : SYSCTL_IN(req, arg1, sizeof(tmpout)));
}

int
sysctl_handle_long(SYSCTL_HANDLER_ARGS)
{
	long tmpout;
	int error;

	tmpout = arg1 ? *(long *)arg1 : (long)arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(tmpout));
	if (error || !req->newptr)
		return (error);
	return (!arg1 ? EPERM : SYSCTL_IN(req, arg1, sizeof(tmpout)));
}

int
sysctl_handle_string(SYSCTL_HANDLER_ARGS)
{
	size_t outlen;
	int error;

	if (arg2 == 0)
		outlen = arg2 = strlen(arg1) + 1;
	else
		outlen = strnlen(arg1, arg2 - 1) + 1;
	error = SYSCTL_OUT(req, req->oldptr != NULL ? arg1 : NULL, outlen);
	if (error || !req->newptr)
		return (error);
	if (req->newlen - req->newidx >= (size_t)arg2)
		return (EINVAL);
	arg2 = req->newlen - req->newidx;
	error = SYSCTL_IN(req, arg1, arg2);
	if (error == 0)
		((char *)arg1)[arg2] = '\0';
	return (error);
}
