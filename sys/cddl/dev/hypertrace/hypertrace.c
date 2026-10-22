/*-
 * Copyright (c) 2021, 2023 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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

/*
 * The HyperTrace module is meant to be called from a tracing framework, such as
 * DTrace. It is responsible for managing virtual probes and providers in a way
 * that allows the tracing system to enable and disable virtual probes in a
 * race-free way (assuming the system relies on memory barriers and syncs with
 * an asynchronous way to fully disable tracing).
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/dtrace_bsd.h>
#include <sys/hash.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mbufid.h>
#include <sys/priv.h>
#include <sys/sysctl.h>

#include <machine/vmm.h>

#include "dtrace_cddl.h"
#include "hypertrace.h"

static MALLOC_DEFINE(M_HYPERTRACE, "HyperTrace", "");

static int        sysctl_num_probes(SYSCTL_HANDLER_ARGS);
static lwpid_t    hypertrace_priv_gettid(const void *);
static uint16_t   hypertrace_priv_getns(const void *);
static const char *hypertrace_priv_getname(const void *);
static int        hypertrace_priv_getreg(const void *, int, uint64_t *);
static int        hypertrace_priv_guest_copyin(const void *, uint64_t, void *, size_t);
static int        hypertrace_priv_guest_user_copyin(const void *, uint64_t, void *, size_t);
static int        hypertrace_priv_guest_user_copyout(const void *, uint64_t, const void *, size_t);
static int        hypertrace_priv_rmprobe(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_is_enabled(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_check_epoch(uint16_t, uint64_t);
static int        hypertrace_priv_create_probes(uint16_t, uint64_t, void *, size_t);
static int        hypertrace_priv_enable(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_disable(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_suspend(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_resume(uint16_t, hypertrace_id_t);

lwpid_t    (*vmm_gettid)(const void *);
uint16_t   (*vmm_getid)(const void *);
uint64_t   (*vmm_getepoch)(const void *);
const char *(*vmm_getname)(const void *);
int        (*vmm_getreg)(const void *, int, uint64_t *);
int        (*vmm_guest_copyin)(const void *, uint64_t, void *, size_t);
int        (*vmm_guest_user_copyin)(const void *, uint64_t, void *, size_t);
int        (*vmm_guest_user_copyout)(const void *, uint64_t, const void *, size_t);

static d_open_t hypertrace_open;
static d_ioctl_t hypertrace_ioctl;
static int      hypertrace_unload(void);
static void     hypertrace_load(void *);

static struct cdevsw hypertrace_cdevsw = {
	.d_version         = D_VERSION,
	.d_open            = hypertrace_open,
	.d_ioctl           = hypertrace_ioctl,
	.d_name            = "hypertrace",
};

SYSCTL_NODE(_dev, OID_AUTO, hypertrace, CTLFLAG_RD, NULL, NULL);
SYSCTL_PROC(_dev_hypertrace, OID_AUTO, nprobes,
    CTLFLAG_RD | CTLTYPE_U64 | CTLFLAG_MPSAFE, NULL, 0, sysctl_num_probes, "LU",
    NULL);

/* Bound one guest's share of the global provider table. */
#define HASH_SIZE 4096
#define HASH_MASK (HASH_SIZE - 1)
#define HYPERTRACE_MAX_PROVIDERS_PER_VM 256

static struct cdev            *hypertrace_cdev;
static int         __unused   hypertrace_verbose = 0;
static hypertrace_map_t       *hypertrace_map;
static kmutex_t               provmtx;
static hypertrace_vprovider_t **provtab;
/* Lifetime/namespace allocation survives VMM unload while probes remain. */
static uint64_t hypertrace_vm_epochs[HYPERTRACE_MAX_VMS];
static uint8_t hypertrace_vm_gate_tokens[HYPERTRACE_MAX_VMS][16];
_Static_assert(sizeof(struct hypertrace_epoch_gate) == 56,
    "HyperTrace epoch gate ioctl ABI must be 56 bytes");
_Static_assert(__builtin_offsetof(struct hypertrace_epoch_gate, suspended) == 16,
    "HyperTrace epoch gate state offset must be fixed");
_Static_assert(__builtin_offsetof(struct hypertrace_epoch_gate, token) == 24,
    "HyperTrace epoch gate token offset must be fixed");
_Static_assert(__builtin_offsetof(struct hypertrace_epoch_gate,
    previous_token) == 40,
    "HyperTrace epoch gate previous-token offset must be fixed");

static int
privcheck(struct thread *td)
{
	if (jailed(td->td_ucred))
		return (EPERM);

	return (0);
}

static int
sysctl_num_probes(SYSCTL_HANDLER_ARGS)
{
	int err = 0;
	size_t num_probes = 0;
	__unused uint16_t vmid;

	err = privcheck(req->td);
	if (err)
		return (EPERM);

	dtrace_hypertrace_config_lock();
	/* map_count() fails only for an out-of-range VM ID; 0 counts all. */
	err = map_count(hypertrace_map, 0, &num_probes);
	dtrace_hypertrace_config_unlock();
	ASSERT(err == 0);

	err = SYSCTL_OUT(req, &num_probes, sizeof(num_probes));
	return (err);
}

static void
hypertrace_load(void *dummy __unused)
{
	/*
	 * Create the device node.
	 */
	hypertrace_cdev = make_dev(&hypertrace_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "dtrace/hypertrace");
}

static int
hypertrace_unload(void)
{

	destroy_dev(hypertrace_cdev);
	return (0);
}

static int
hypertrace_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;
	size_t count, i;

	switch (type) {
	case MOD_LOAD:
		/*
		 * Initialize the provtab and initialize the probe map.
		 */
		provtab = kmem_zalloc(
		    sizeof(hypertrace_vprovider_t *) * HASH_SIZE, KM_SLEEP);
		mutex_init(&provmtx, "hypertrace provider table mutex",
		    MUTEX_DEFAULT, NULL);

		hypertrace_map = map_init();
		/*
		 * Set up the hooks.
		 */
		dtrace_hypertrace_config_lock();
		hypertrace_gettid        = hypertrace_priv_gettid;
		hypertrace_getns         = hypertrace_priv_getns;
		hypertrace_getname       = hypertrace_priv_getname;
		hypertrace_getreg        = hypertrace_priv_getreg;
		hypertrace_guest_copyin  = hypertrace_priv_guest_copyin;
		hypertrace_guest_user_copyin = hypertrace_priv_guest_user_copyin;
		hypertrace_guest_user_copyout = hypertrace_priv_guest_user_copyout;
		hypertrace_rmprobe       = hypertrace_priv_rmprobe;
		hypertrace_is_enabled    = hypertrace_priv_is_enabled;
		hypertrace_create_probes = hypertrace_priv_create_probes;
		hypertrace_check_epoch = hypertrace_priv_check_epoch;
		hypertrace_enable        = hypertrace_priv_enable;
		hypertrace_disable       = hypertrace_priv_disable;
		hypertrace_suspend       = hypertrace_priv_suspend;
		hypertrace_resume        = hypertrace_priv_resume;
		dtrace_hypertrace_config_unlock();
		break;

	case MOD_QUIESCE:
		/* The linker treats EOPNOTSUPP as successful quiescence.  Refuse
		 * the unload walk while the VMM or any virtual probe still owns us. */
		dtrace_hypertrace_config_lock();
		error = map_count(hypertrace_map, 0, &count);
		ASSERT(error == 0);	/* VM ID 0 (all) is always valid */
		if (count != 0 || vmm_getid != NULL)
			error = EBUSY;
		dtrace_hypertrace_config_unlock();
		break;

	case MOD_UNLOAD:
		dtrace_hypertrace_config_lock();
		error = map_count(hypertrace_map, 0, &count);
		ASSERT(error == 0);	/* VM ID 0 (all) is always valid */
		if (count != 0 || vmm_getid != NULL) {
			dtrace_hypertrace_config_unlock();
			return (EBUSY);
		}
		/*
		 * Destroy the hooks.
		 */
		hypertrace_gettid        = NULL;
		hypertrace_getns         = NULL;
		hypertrace_getname       = NULL;
		hypertrace_getreg        = NULL;
		hypertrace_guest_copyin  = NULL;
		hypertrace_guest_user_copyin = NULL;
		hypertrace_guest_user_copyout = NULL;
		hypertrace_rmprobe       = NULL;
		hypertrace_is_enabled    = NULL;
		hypertrace_create_probes = NULL;
		hypertrace_check_epoch = NULL;
		hypertrace_enable        = NULL;
		hypertrace_disable       = NULL;
		hypertrace_suspend       = NULL;
		hypertrace_resume        = NULL;

		/*
		 * Free the provtab and tear down the probe map.
		 */
		for (i = 0; i < HASH_SIZE; i++) {
			if (provtab[i] != NULL)
				kmem_free(provtab[i], sizeof(*provtab[i]));
		}
		mutex_destroy(&provmtx);
		kmem_free(
		    provtab, sizeof(hypertrace_vprovider_t *) * HASH_SIZE);
		map_teardown(hypertrace_map);
		hypertrace_map = NULL;
		provtab = NULL;
		dtrace_hypertrace_config_unlock();
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;

	}

	return (error);
}

/*
 * Placeholder for future things.
 */
static int
hypertrace_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	return (0);
}

static int
hypertrace_ioctl(struct cdev *dev __unused, u_long command, caddr_t data,
    int fflag __unused, struct thread *td)
{
	struct hypertrace_epoch_query *query;
	struct hypertrace_epoch_gate *gate;
	static const uint8_t zero_token[16];
	uint8_t *owner;
	int suspended;
	int error;

	if (command != HYPERTRACE_IOC_EPOCH_QUERY &&
	    command != HYPERTRACE_IOC_EPOCH_SUSPEND &&
	    command != HYPERTRACE_IOC_EPOCH_RESUME &&
	    command != HYPERTRACE_IOC_EPOCH_GATE_QUERY &&
	    command != HYPERTRACE_IOC_HANDLE_QUERY)
		return (ENOTTY);
	error = privcheck(td);
	if (error != 0)
		return (error);
	error = priv_check(td, PRIV_DTRACE_KERNEL);
	if (error != 0)
		return (error);
	if (command == HYPERTRACE_IOC_HANDLE_QUERY) {
		dtrace_hypertrace_config_lock();
		error = dtrace_handle_query((dtrace_handle_lifetime_t *)data);
		dtrace_hypertrace_config_unlock();
		return (error);
	}
	if (command == HYPERTRACE_IOC_EPOCH_QUERY) {
		query = (struct hypertrace_epoch_query *)data;
		if (query->vmid == 0 || query->vmid >= HYPERTRACE_MAX_VMS ||
		    query->epoch == 0 || query->live != 0 ||
		    query->reserved2 != 0 || query->reserved[0] != 0 ||
		    query->reserved[1] != 0 || query->reserved[2] != 0)
			return (EINVAL);
		dtrace_hypertrace_config_lock();
		query->live = hypertrace_vm_epochs[query->vmid] == query->epoch;
		dtrace_hypertrace_config_unlock();
		return (0);
	}
	gate = (struct hypertrace_epoch_gate *)data;
	if (gate->vmid == 0 || gate->vmid >= HYPERTRACE_MAX_VMS ||
	    gate->epoch == 0 || gate->suspended != 0 || gate->reserved2 != 0 ||
	    gate->reserved[0] != 0 || gate->reserved[1] != 0 ||
	    gate->reserved[2] != 0 ||
	    (command == HYPERTRACE_IOC_EPOCH_GATE_QUERY ?
	    memcmp(gate->token, zero_token, sizeof(gate->token)) != 0 :
	    memcmp(gate->token, zero_token, sizeof(gate->token)) == 0) ||
	    (command != HYPERTRACE_IOC_EPOCH_SUSPEND &&
	    memcmp(gate->previous_token, zero_token,
	    sizeof(gate->previous_token)) != 0))
		return (EINVAL);
	dtrace_hypertrace_config_lock();
	owner = hypertrace_vm_gate_tokens[gate->vmid];
	if (hypertrace_vm_epochs[gate->vmid] != gate->epoch)
		error = ESTALE;
	else if (command == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
		gate->suspended = dtrace_hypertrace_epoch_suspended(gate->vmid,
		    gate->epoch);
		memcpy(gate->token, owner, sizeof(gate->token));
		error = 0;
	} else if (command == HYPERTRACE_IOC_EPOCH_SUSPEND) {
		suspended = dtrace_hypertrace_epoch_suspended(gate->vmid,
		    gate->epoch);
		if (suspended)
			error = memcmp(owner, gate->token,
			    sizeof(gate->token)) == 0 ? 0 : EBUSY;
		else if (memcmp(owner, gate->token,
		    sizeof(gate->token)) == 0)
			error = EBUSY; /* A completed ticket cannot resuspend. */
		else if (memcmp(owner, gate->previous_token,
		    sizeof(gate->previous_token)) != 0)
			error = ESTALE; /* The observed owner changed. */
		else {
			error = dtrace_hypertrace_epoch_suspend(gate->vmid,
			    gate->epoch);
			if (error == 0)
				memcpy(owner, gate->token, sizeof(gate->token));
		}
	} else if (memcmp(owner, gate->token, sizeof(gate->token)) != 0)
		error = ESTALE;
	else
		error = dtrace_hypertrace_epoch_resume(gate->vmid, gate->epoch);
	dtrace_hypertrace_config_unlock();
	return (error);
}

static int
hypertrace_priv_is_enabled(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (-ESRCH);

	return (ht_probe->htpb_enabled);
}

static int
hypertrace_priv_enable(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	ht_probe->htpb_enabled = 1;
	ht_probe->htpb_running = 1;

	return (0);
}

static int
hypertrace_priv_disable(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	ht_probe->htpb_running = 0;
	ht_probe->htpb_enabled = 0;

	return (0);
}

static int
hypertrace_priv_suspend(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	ht_probe->htpb_running = 0;
	return (0);
}

static int
hypertrace_priv_resume(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	ht_probe->htpb_running = 1;
	return (0);
}

int
hypertrace_probe(const void *vmhdl, hypertrace_id_t id, hypertrace_args_t *dtv_args)
{
	hypertrace_probe_t *ht_probe;
	const void *previous;
	uint16_t vmid;
	dtrace_icookie_t cookie;
	int error;

	if (vmhdl == NULL || dtv_args == NULL || id <= 0 ||
	    id > DTRACE_SENSIBLE_PROBELIMIT)
		return (EINVAL);
	vmid = hypertrace_priv_getns(vmhdl);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS)
		return (EINVAL);

	/* Protect the map lookup as well as DIF execution from reclamation. */
	cookie = dtrace_interrupt_disable();
	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL) {
		dtrace_interrupt_enable(cookie);
		return (ESRCH);
	}

	error = ESTALE;
	/* Probes are created only for a live (non-zero) epoch. */
	ASSERT(ht_probe->htpb_epoch != 0);
	if (vmm_getepoch != NULL &&
	    ht_probe->htpb_epoch == vmm_getepoch(vmhdl)) {
		error = EACCES;
		if (ht_probe->htpb_enabled != 0 && ht_probe->htpb_running == 1) {
			previous = curthread->t_hypertrace_vmhdl;
			curthread->t_hypertrace_vmhdl = vmhdl;
			dtrace_probe(id, (uintptr_t)dtv_args, 0, 0, 0, 0);
			curthread->t_hypertrace_vmhdl = previous;
			error = 0;
		}
	}
	dtrace_interrupt_enable(cookie);
	return (error);
}

/*
 * Get the thread ID of the VM.
 */
static lwpid_t
hypertrace_priv_gettid(const void *vmhdl)
{

	return (vmm_gettid == NULL ? 0 : vmm_gettid(vmhdl));
}

/*
 * Get a unique identifier of each vm (uint16_t). This is used to scope
 * thread-local storage in the DTrace probe context.
 */
static uint16_t
hypertrace_priv_getns(const void *vmhdl)
{

	return (vmm_getid == NULL ? 0 : vmm_getid(vmhdl));
}

static const char *
hypertrace_priv_getname(const void *vmhdl)
{

	return (vmm_getname == NULL ? 0 : vmm_getname(vmhdl));
}

static int
hypertrace_priv_getreg(const void *vmhdl, int reg, uint64_t *value)
{
	if (vmhdl == NULL || value == NULL || vmm_getreg == NULL)
		return (ENXIO);
	return (vmm_getreg(vmhdl, reg, value));
}

static int
hypertrace_priv_guest_copyin(const void *vmhdl, uint64_t gla, void *dst,
    size_t length)
{
	if (vmhdl == NULL || dst == NULL || length == 0)
		return (EINVAL);
	if (vmm_guest_copyin == NULL)
		return (EOPNOTSUPP);
	return (vmm_guest_copyin(vmhdl, gla, dst, length));
}

static int
hypertrace_priv_guest_user_copyin(const void *vmhdl, uint64_t gla, void *dst,
    size_t length)
{
	if (vmhdl == NULL || dst == NULL || length == 0 || length > 8)
		return (EINVAL);
	if (vmm_guest_user_copyin == NULL)
		return (EOPNOTSUPP);
	return (vmm_guest_user_copyin(vmhdl, gla, dst, length));
}

static int
hypertrace_priv_guest_user_copyout(const void *vmhdl, uint64_t gla,
    const void *src, size_t length)
{
	if (vmhdl == NULL || src == NULL || length == 0 || length > 8)
		return (EINVAL);
	if (vmm_guest_user_copyout == NULL)
		return (EOPNOTSUPP);
	return (vmm_guest_user_copyout(vmhdl, gla, src, length));
}

/*
 * Get a vprovider with a given provider name. We assume provider names are
 * unique and correctly deduplicated already. This subroutine is meant to be as
 * a main interface to allocate, or get an existing vprovider.
 */
/* Caller holds provmtx. A removed slot cannot stop a duplicate search. */
static hypertrace_vprovider_t *
hypertrace_find_vprovider(const char *provider, uint32_t hash_ndx,
    uint32_t *first_free)
{
	hypertrace_vprovider_t *vprov;
	uint32_t i;

	*first_free = HASH_SIZE;
	for (i = 0; i < HASH_SIZE; i++) {
		uint32_t slot = (hash_ndx + i) & HASH_MASK;
		vprov = provtab[slot];
		if (vprov == NULL) {
			if (*first_free == HASH_SIZE)
				*first_free = slot;
		} else if (strcmp(provider, vprov->name) == 0)
			return (vprov);
	}
	return (NULL);
}

static hypertrace_vprovider_t *
hypertrace_get_vprovider(const char *provider)
{
	hypertrace_vprovider_t *vprov, *candidate;
	uint32_t hash_ndx, first_free;

	hash_ndx = murmur3_32_hash(provider, strlen(provider),
	    HASHINIT) & HASH_MASK;
	mutex_enter(&provmtx);
	vprov = hypertrace_find_vprovider(provider, hash_ndx, &first_free);
	if (vprov != NULL || first_free == HASH_SIZE) {
		mutex_exit(&provmtx);
		return (vprov);
	}
	mutex_exit(&provmtx);
	candidate = kmem_zalloc(sizeof(*candidate), KM_SLEEP);
	mutex_enter(&provmtx);
	vprov = hypertrace_find_vprovider(provider, hash_ndx, &first_free);
	if (vprov != NULL || first_free == HASH_SIZE) {
		mutex_exit(&provmtx);
		kmem_free(candidate, sizeof(*candidate));
		return (vprov);
	}
	strlcpy(candidate->name, provider, sizeof(candidate->name));
	candidate->hash_ndx = first_free;
	provtab[first_free] = candidate;
	mutex_exit(&provmtx);
	return (candidate);
}

static uint16_t vm_provider_counts[HYPERTRACE_MAX_VMS];

static int
hypertrace_provider_reserve(hypertrace_vprovider_t *vprov, uint16_t vmid)
{
	/* The only caller checked the provider and the VM's epoch. */
	ASSERT(vprov != NULL && vmid > 0 && vmid < HYPERTRACE_MAX_VMS);
	if (vprov->vm_refs[vmid] == UINT32_MAX)
		return (EOVERFLOW);
	if (vprov->vm_refs[vmid] == 0) {
		if (vm_provider_counts[vmid] >=
		    HYPERTRACE_MAX_PROVIDERS_PER_VM)
			return (ENOSPC);
		vm_provider_counts[vmid]++;
	}
	vprov->vm_refs[vmid]++;
	return (0);
}

static void
hypertrace_provider_release(hypertrace_vprovider_t *vprov, uint16_t vmid)
{
	ASSERT(vprov != NULL && vmid > 0 && vmid < HYPERTRACE_MAX_VMS);
	ASSERT(vprov->vm_refs[vmid] > 0 && vm_provider_counts[vmid] > 0);
	if (--vprov->vm_refs[vmid] == 0)
		vm_provider_counts[vmid]--;
}

static uint64_t
hypertrace_priv_epoch_byid(uint16_t id)
{
	/* The only caller range-checks the ID first. */
	ASSERT(id > 0 && id < HYPERTRACE_MAX_VMS);
	return (hypertrace_vm_epochs[id]);
}

int
hypertrace_vm_alloc(uint16_t *id, uint64_t *epoch)
{
	size_t count;
	uint16_t candidate;
	uint64_t token;
	int error = ENOSPC, merr;

	if (id == NULL || epoch == NULL)
		return (EINVAL);
	dtrace_hypertrace_config_lock();
	for (candidate = 1; candidate < HYPERTRACE_MAX_VMS; candidate++) {
		if (hypertrace_vm_epochs[candidate] != 0)
			continue;
		/* candidate < HYPERTRACE_MAX_VMS: map_count() cannot fail. */
		merr = map_count(hypertrace_map, candidate, &count);
		ASSERT(merr == 0);
		(void)merr;
		if (count != 0)
			continue;
		do {
			arc4random_buf(&token, sizeof(token));
		} while (token == 0);
		if (dtrace_hypertrace_epoch_publish(candidate, token) != 0)
			continue;
		hypertrace_vm_epochs[candidate] = token;
		mbufid_v2_vm_epoch_publish(candidate, token);
		*id = candidate;
		*epoch = token;
		error = 0;
		break;
	}
	dtrace_hypertrace_config_unlock();
	return (error);
}

int
hypertrace_vm_release(uint16_t id, uint64_t epoch)
{
	int error = ESTALE;

	dtrace_hypertrace_config_lock();
	if (id != 0 && id < HYPERTRACE_MAX_VMS && epoch != 0 &&
	    hypertrace_vm_epochs[id] == epoch &&
	    dtrace_hypertrace_epoch_revoke(id, epoch) == 0) {
		mbufid_v2_vm_epoch_revoke(id, epoch);
		hypertrace_vm_epochs[id] = 0;
		explicit_bzero(hypertrace_vm_gate_tokens[id],
		    sizeof(hypertrace_vm_gate_tokens[id]));
		error = 0;
	}
	dtrace_hypertrace_config_unlock();
	return (error);
}

/* Caller holds the DTrace configuration locks, excluding map mutations. */
static int
hypertrace_priv_check_epoch(uint16_t vmid, uint64_t epoch)
{
	hypertrace_probe_t *probe;
	size_t i;

	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
	    hypertrace_priv_epoch_byid(vmid) != epoch)
		return (ESTALE);
	if (dtrace_hypertrace_epoch_suspended(vmid, epoch))
		return (EBUSY);
	/* A VM ID is reallocated only after its map namespace is empty
	 * (hypertrace_vm_alloc()), and its probes carry the epoch they were
	 * created for, so every probe here belongs to this lifetime. */
#ifdef INVARIANTS
	for (i = 0; i < hypertrace_map->nprobes[vmid]; i++) {
		probe = hypertrace_map->probes[vmid][i];
		ASSERT(probe == NULL || probe->htpb_epoch == epoch);
	}
#else
	(void)probe;
	(void)i;
#endif
	return (0);
}

static int
hypertrace_priv_create_probes(uint16_t vmid, uint64_t epoch, void *_vprobes, size_t nvprobes)
{
	size_t i;
	int error;
	dtrace_probedesc_t *vprobe;
	hypertrace_probe_t *htp;
	hypertrace_vprovider_t *vprov = NULL;
	dtrace_id_t id;
	dtrace_probedesc_t *vprobes = (dtrace_probedesc_t *)_vprobes;

	if (vmid == HYPERTRACE_HOSTID || vmid >= HYPERTRACE_MAX_VMS ||
	    vprobes == NULL || nvprobes == 0 ||
	    nvprobes > DTRACE_SENSIBLE_PROBELIMIT)
		return (EINVAL);
	error = hypertrace_priv_check_epoch(vmid, epoch);
	if (error != 0)
		return (error);
	/* Validate the whole input before creating any provider or probe. */
	for (i = 0; i < nvprobes; i++) {
		vprobe = &vprobes[i];
		if (vprobe->dtpd_id == 0 ||
		    vprobe->dtpd_id > DTRACE_SENSIBLE_PROBELIMIT ||
		    memchr(vprobe->dtpd_provider, 0, sizeof(vprobe->dtpd_provider)) == NULL ||
		    memchr(vprobe->dtpd_mod, 0, sizeof(vprobe->dtpd_mod)) == NULL ||
		    memchr(vprobe->dtpd_func, 0, sizeof(vprobe->dtpd_func)) == NULL ||
		    memchr(vprobe->dtpd_name, 0, sizeof(vprobe->dtpd_name)) == NULL)
			return (EINVAL);
	}
	for (i = 0; i < nvprobes; i++) {
		vprobe = &vprobes[i];
		vprov = hypertrace_get_vprovider(vprobe->dtpd_provider);
		if (vprov == NULL) {
			error = ENOSPC;
			goto rollback;
		}
		error = hypertrace_provider_reserve(vprov, vmid);
		if (error != 0)
			goto rollback;

		id = dtrace_vprobe_create(vmid, vprobe->dtpd_id,
		    vprobe->dtpd_provider, vprobe->dtpd_mod, vprobe->dtpd_func,
		    vprobe->dtpd_name, &error);
		if (id == DTRACE_IDNONE) {
			hypertrace_provider_release(vprov, vmid);
			goto rollback;
		}

		htp = kmem_zalloc(sizeof(hypertrace_probe_t), KM_SLEEP);
		ASSERT(htp != NULL);

		htp->htpb_provider = vprov;
		htp->htpb_id = id;
		htp->htpb_vmid = vmid;
		htp->htpb_epoch = epoch;

		/*
		 * Probes are enabled by default.
		 *
		 * XXX: Implement a user-controlled thing based on
		 * /dev/dtrace/hypertrace.
		 */
		htp->htpb_enabled = 1;
		htp->htpb_running = 1;
		error = map_insert(hypertrace_map, htp);
		if (error != 0) {
			kmem_free(htp, sizeof(*htp));
			dtrace_vprobe_discard(vmid, id);
			hypertrace_provider_release(vprov, vmid);
			goto rollback;
		}
		vprov->nprobes++;
	}

	return (0);
rollback:
	/* Configuration locks exclude new enablings during this entire batch. */
	while (i != 0) {
		id = vprobes[--i].dtpd_id;
		(void)hypertrace_priv_disable(vmid, id);
		(void)hypertrace_priv_rmprobe(vmid, id);
		dtrace_vprobe_discard(vmid, id);
	}
	/* Drop providers reserved by the failed entry but never given a probe. */
	mutex_enter(&provmtx);
	for (i = 0; i < HASH_SIZE; i++) {
		vprov = provtab[i];
		if (vprov != NULL && vprov->nprobes == 0) {
			provtab[i] = NULL;
			kmem_free(vprov, sizeof(*vprov));
		}
	}
	mutex_exit(&provmtx);
	return (error);
}

static int
hypertrace_priv_rmprobe(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_vprovider_t *vprov;
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	if (ht_probe->htpb_enabled)
		return (EAGAIN);

	map_rm(hypertrace_map, ht_probe);

	vprov = ht_probe->htpb_provider;
	if (vprov == NULL)
		panic("probe's provider is NULL.");
	hypertrace_provider_release(vprov, vmid);

	if (--vprov->nprobes == 0) {
		mutex_enter(&provmtx);
		provtab[vprov->hash_ndx] = NULL;
		mutex_exit(&provmtx);
		kmem_free(vprov, sizeof(hypertrace_vprovider_t));
	}

	kmem_free(ht_probe, sizeof(hypertrace_probe_t));
	return (0);
}

SYSINIT(hypertrace_load, SI_SUB_DTRACE_PROVIDER,
    SI_ORDER_ANY, hypertrace_load, NULL);
SYSUNINIT(hypertrace_unload, SI_SUB_DTRACE_PROVIDER,
    SI_ORDER_ANY, hypertrace_unload, NULL);

DEV_MODULE(hypertrace, hypertrace_modevent, NULL);
MODULE_VERSION(hypertrace, 1);
MODULE_DEPEND(hypertrace, dtrace, 1, 1, 1);
MODULE_DEPEND(hypertrace, opensolaris, 1, 1, 1);
