/*-
 * Copyright (c) 2022-present Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kassert.h>
#include <sys/libkern.h>
#include <sys/sx.h>

#include <fs/p9fs/p9_transport.h>

static TAILQ_HEAD(, p9_trans_module) transports;
static struct sx transports_lock;

static void
p9_transport_init(void *dummy __unused)
{

	TAILQ_INIT(&transports);
	sx_init(&transports_lock, "p9 transports");
}

SYSINIT(p9_transport, SI_SUB_DRIVERS, SI_ORDER_FIRST, p9_transport_init, NULL);

static void
p9_transport_uninit(void *dummy __unused)
{

	KASSERT(TAILQ_EMPTY(&transports),
	    ("%s: transport registry is not empty", __func__));
	sx_destroy(&transports_lock);
}

SYSUNINIT(p9_transport, SI_SUB_DRIVERS, SI_ORDER_FIRST,
    p9_transport_uninit, NULL);

int
p9_register_trans(struct p9_trans_module *m)
{
	struct p9_trans_module *other;
	int error;

	if (m == NULL || m->name == NULL)
		return (EINVAL);
	error = 0;
	sx_xlock(&transports_lock);
	if (m->registered) {
		error = EALREADY;
		goto out;
	}
	TAILQ_FOREACH(other, &transports, link) {
		if (strcmp(other->name, m->name) == 0) {
			error = EEXIST;
			goto out;
		}
	}
	m->references = 0;
	m->registered = true;
	TAILQ_INSERT_TAIL(&transports, m, link);
out:
	sx_xunlock(&transports_lock);
	return (error);
}

int
p9_unregister_trans(struct p9_trans_module *m)
{
	int error;

	if (m == NULL)
		return (EINVAL);
	error = 0;
	sx_xlock(&transports_lock);
	if (!m->registered)
		error = ENOENT;
	else if (m->references != 0)
		error = EBUSY;
	else {
		TAILQ_REMOVE(&transports, m, link);
		m->registered = false;
	}
	sx_xunlock(&transports_lock);
	return (error);
}

struct p9_trans_module *
p9_get_trans_by_name(const char *name)
{
	struct p9_trans_module *m, *result;

	if (name == NULL)
		return (NULL);
	result = NULL;
	sx_xlock(&transports_lock);
	TAILQ_FOREACH(m, &transports, link) {
		if (strcmp(m->name, name) == 0) {
			KASSERT(m->registered,
			    ("%s: unregistered transport is linked", __func__));
			m->references++;
			result = m;
			break;
		}
	}
	sx_xunlock(&transports_lock);
	return (result);
}

void
p9_put_trans(struct p9_trans_module *m)
{

	KASSERT(m != NULL, ("%s: NULL transport", __func__));
	sx_xlock(&transports_lock);
	KASSERT(m->registered, ("%s: unregistered transport", __func__));
	KASSERT(m->references != 0,
	    ("%s: transport has no references", __func__));
	m->references--;
	sx_xunlock(&transports_lock);
}
