/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * The 5BSD "jail <name>" rule option: a rule that names its jail matches
 * whatever jail currently has that name.  The rule keeps the jail's full
 * name (relative names given inside a jail are made absolute when the
 * rule is loaded) and the jail id it resolves to; jail creation, renaming
 * and removal queue a task that re-resolves the named rules of every
 * vnet.  While no jail has the name the rule matches no socket's jail.
 */

#include "openbsd_compat.h"

#include <sys/jail.h>
#include <sys/osd.h>

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

SDT_PROBE_DECLARE(pf, rule, jail, resolve);
int	pf_fbsd_vnet_ready(void);

struct pf_jail_ent {
	int	jid;
	char	name[PF_JAIL_NAME_SIZE];
};

/* Look up a living jail by full name; PF_JAIL_NOJID if there is none. */
static int
pf_jail_lookup(const char *name)
{
	struct prison *pr;
	int jid = PF_JAIL_NOJID;

	sx_slock(&allprison_lock);
	pr = prison_find_name(&prison0, name);
	if (pr != NULL) {
		if (prison_isalive(pr))
			jid = pr->pr_id;
		mtx_unlock(&pr->pr_mtx);
	}
	sx_sunlock(&allprison_lock);
	return (jid);
}

/*
 * DIOCADDRULE and friends, no pf locks held: make the name absolute for
 * the loading process's jail and resolve it.
 */
int
pf_jail_rule_copyin(struct pf_rule *r)
{
	struct prison *pr = curthread->td_ucred->cr_prison;
	char full[PF_JAIL_NAME_SIZE];

	if (r->jail.op != PF_OP_EQ && r->jail.op != PF_OP_NE)
		return (EINVAL);
	if (strnlen(r->jail.name, sizeof(r->jail.name)) == 0 ||
	    strnlen(r->jail.name, sizeof(r->jail.name)) >=
	    sizeof(r->jail.name))
		return (EINVAL);
	if (pr != &prison0) {
		if (snprintf(full, sizeof(full), "%s.%s", pr->pr_name,
		    r->jail.name) >= (int)sizeof(full))
			return (ENAMETOOLONG);
		strlcpy(r->jail.name, full, sizeof(r->jail.name));
	}
	r->jail.jid[0] = r->jail.jid[1] = pf_jail_lookup(r->jail.name);
	return (0);
}

/* DIOCGETRULE: give the caller the name relative to its own jail. */
void
pf_jail_rule_copyout(struct pf_rule *r)
{
	struct prison *pr = curthread->td_ucred->cr_prison;
	size_t len;

	if (!r->jail.byname || pr == &prison0)
		return;
	len = strlen(pr->pr_name);
	if (strncmp(r->jail.name, pr->pr_name, len) == 0 &&
	    r->jail.name[len] == '.')
		memmove(r->jail.name, r->jail.name + len + 1,
		    strlen(r->jail.name + len + 1) + 1);
}

/* ------------------------------------------------------------------ */
/* Re-resolution when jails come and go                                */
/* ------------------------------------------------------------------ */

static int
pf_jail_snapshot_lookup(const struct pf_jail_ent *ents, int n,
    const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(ents[i].name, name) == 0)
			return (ents[i].jid);
	return (PF_JAIL_NOJID);
}

static void
pf_jail_resolve_queue(struct pf_rulequeue *rq, const struct pf_jail_ent *ents,
    int n)
{
	struct pf_rule *r;
	int jid;

	TAILQ_FOREACH(r, rq, entries) {
		if (!r->jail.byname)
			continue;
		jid = pf_jail_snapshot_lookup(ents, n, r->jail.name);
		if (jid == r->jail.jid[0])
			continue;
		SDT_PROBE3(pf, rule, jail, resolve, r, r->jail.jid[0], jid);
		r->jail.jid[0] = r->jail.jid[1] = jid;
	}
}

static void
pf_jail_resolve_ruleset(struct pf_ruleset *rs, const struct pf_jail_ent *ents,
    int n)
{
	pf_jail_resolve_queue(rs->rules.active.ptr, ents, n);
	pf_jail_resolve_queue(rs->rules.inactive.ptr, ents, n);
}

static void
pf_jail_resolve_task(void *arg __unused)
{
	VNET_ITERATOR_DECL(vnet_iter);
	struct pf_jail_ent *ents;
	struct pf_anchor *a;
	struct prison *pr;
	int n, max;

	/* Snapshot the living jails; never take allprison_lock under pf. */
	for (;;) {
		max = 1;
		sx_slock(&allprison_lock);
		TAILQ_FOREACH(pr, &allprison, pr_list)
			max++;
		sx_sunlock(&allprison_lock);
		ents = malloc(max * sizeof(*ents), M_PF, M_WAITOK);
		n = 0;
		sx_slock(&allprison_lock);
		TAILQ_FOREACH(pr, &allprison, pr_list) {
			if (!prison_isalive(pr))
				continue;
			if (n == max)
				break;
			ents[n].jid = pr->pr_id;
			strlcpy(ents[n].name, pr->pr_name, sizeof(ents[n].name));
			n++;
		}
		sx_sunlock(&allprison_lock);
		if (n < max)
			break;
		free(ents, M_PF);	/* jails were created meanwhile */
	}

	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		if (pf_fbsd_vnet_ready()) {
			NET_LOCK();
			PF_LOCK();
			pf_jail_resolve_ruleset(&pf_main_ruleset, ents, n);
			RB_FOREACH(a, pf_anchor_global, &pf_anchors)
				pf_jail_resolve_ruleset(&a->ruleset, ents, n);
			PF_UNLOCK();
			NET_UNLOCK();
		}
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();
	free(ents, M_PF);
}

static struct task pf_jail_task = TASK_INITIALIZER(pf_jail_resolve_task, NULL);
static int pf_jail_osd_slot;

static int
pf_jail_changed(void *obj __unused, void *data __unused)
{
	task_add(systq, &pf_jail_task);
	return (0);
}

void	pf_jail_attach(void);
void
pf_jail_attach(void)
{
	osd_method_t methods[PR_MAXMETHOD] = {
		[PR_METHOD_CREATE] = pf_jail_changed,
		[PR_METHOD_SET] = pf_jail_changed,
		[PR_METHOD_REMOVE] = pf_jail_changed,
	};

	pf_jail_osd_slot = osd_jail_register(NULL, methods);
}
