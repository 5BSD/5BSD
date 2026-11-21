/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Isolated VM fixture for callback completion versus service unload.
 *
 * Every wait here is event driven and has no timeout: a blocked callback
 * sleeps on its release variable and the sysctl that sets it wakes it; a test
 * waits for a callback to be entered by reading a wait_* sysctl, which sleeps
 * (interruptibly) until the callback wakes it.  A test that fails releases
 * everything from its cleanup.  The mac_capability_destroy_wait event tells
 * the fixture that service destroy is held up, and by what
 * (wait_destroy_waiting returns the reason); writing a release
 * sysctl then returns whether destroy had already returned.  Together they
 * show, without timing, that unload was waiting when the callback was
 * released.  The wait_* oids block, so they are CTLFLAG_SKIP (sysctl -a
 * does not read them).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/sleepqueue.h>
#include <machine/atomic.h>
#include "mac_capability.h"

static struct mac_capability_service *cleanup_svc;
static u_int entered, release_callback, destroy_entered, destroy_returned;
static u_int destroy_waiting;
static u_int fail_init;
static u_int block_stage, stage_entered, release_stage, fail_stage;

SYSCTL_NODE(_debug, OID_AUTO, capability_cleanup_test, CTLFLAG_RD, 0,
    "Private VM cleanup fixture");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, entered, CTLFLAG_RD,
    &entered, 0, "Callback entered");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, destroy_entered, CTLFLAG_RD,
    &destroy_entered, 0, "Service destroy entered");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, fail_init, CTLFLAG_RW,
    &fail_init, 0, "Fail initialization before publication");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, block_stage, CTLFLAG_RW,
    &block_stage, 0,
    "Block authorization (1), initialization (2) or descriptor close (3)");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, stage_entered, CTLFLAG_RD,
    &stage_entered, 0, "Blocked stage entered");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, fail_stage, CTLFLAG_RW,
    &fail_stage, 0, "Fail blocked construction stage");

/*
 * Write: set a release variable and wake whoever sleeps on it.  The value
 * read back is destroy_returned as it was before the release.
 */
static int
cleanup_release_sysctl(SYSCTL_HANDLER_ARGS)
{
	u_int *var = arg1, value, returned;
	int error;

	returned = atomic_load_acq_int(&destroy_returned);
	error = SYSCTL_OUT(req, &returned, sizeof(returned));
	if (error != 0 || req->newptr == NULL)
		return (error);
	error = SYSCTL_IN(req, &value, sizeof(value));
	if (error != 0)
		return (error);
	atomic_store_rel_int(var, value);
	wakeup(var);
	return (0);
}
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, release,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE, &release_callback, 0,
    cleanup_release_sysctl, "IU", "Release blocked callback");
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, release_stage,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE, &release_stage, 0,
    cleanup_release_sysctl, "IU", "Release blocked stage");

/* Read: sleep until the variable is nonzero, return it.  A signal ends it. */
static int
cleanup_wait_sysctl(SYSCTL_HANDLER_ARGS)
{
	u_int *var = arg1, value;
	int error = 0;

	DROP_GIANT();
	for (;;) {
		sleepq_lock(var);
		if ((value = atomic_load_acq_int(var)) != 0) {
			sleepq_release(var);
			break;
		}
		sleepq_add(var, NULL, "capfixwait", SLEEPQ_SLEEP |
		    SLEEPQ_INTERRUPTIBLE, 0);
		if ((error = sleepq_wait_sig(var, 0)) != 0)
			break;
	}
	PICKUP_GIANT();
	if (error != 0)
		return (error);
	return (sysctl_handle_int(oidp, &value, 0, req));
}
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, wait_entered,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP, &entered, 0,
    cleanup_wait_sysctl, "IU", "Wait for the blocked callback");
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, wait_stage_entered,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP, &stage_entered,
    0, cleanup_wait_sysctl, "IU", "Wait for the blocked stage");
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, wait_destroy_entered,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP, &destroy_entered,
    0, cleanup_wait_sysctl, "IU", "Wait for service destroy");
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, wait_destroy_waiting,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP, &destroy_waiting,
    0, cleanup_wait_sysctl, "IU", "Wait for service destroy to be held up");

static int
cleanup_destroy_wait_reason_sysctl(SYSCTL_HANDLER_ARGS)
{
	const char *name;

	switch (atomic_load_acq_int(&destroy_waiting)) {
	case 0:
		name = "none";
		break;
	case MAC_CAPABILITY_DESTROY_WAIT_ADMISSION:
		name = "admission";
		break;
	case MAC_CAPABILITY_DESTROY_WAIT_INFLIGHT:
		name = "inflight";
		break;
	case MAC_CAPABILITY_DESTROY_WAIT_CALLBACK:
		name = "callback";
		break;
	case MAC_CAPABILITY_DESTROY_WAIT_REFS:
		name = "refs";
		break;
	case MAC_CAPABILITY_DESTROY_WAIT_REAP:
		name = "reap";
		break;
	default:
		name = "unknown";
		break;
	}
	return (sysctl_handle_string(oidp, __DECONST(char *, name), 0, req));
}
SYSCTL_PROC(_debug_capability_cleanup_test, OID_AUTO, destroy_wait_reason,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    cleanup_destroy_wait_reason_sysctl, "A",
    "What service destroy first waited for");

static void
cleanup_set(u_int *var, u_int value)
{

	atomic_store_rel_int(var, value);
	wakeup(var);
}

/* Sleep until released (a test's cleanup releases everything). */
static void
cleanup_block(u_int *release, const char *wmesg)
{

	/* The revoke callback runs under unload, which holds Giant. */
	DROP_GIANT();
	for (;;) {
		sleepq_lock(release);
		if (atomic_load_acq_int(release) != 0) {
			sleepq_release(release);
			break;
		}
		sleepq_add(release, NULL, wmesg, SLEEPQ_SLEEP, 0);
		sleepq_wait(release, 0);
	}
	PICKUP_GIANT();
}

static int
cleanup_stage(u_int stage)
{
	if (atomic_load_acq_int(&block_stage) != stage)
		return (0);
	cleanup_set(&stage_entered, stage);
	cleanup_block(&release_stage, "capinitfixture");
	return (atomic_load_acq_int(&fail_stage) != 0 ? EIO : 0);
}

static int
cleanup_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge)
{
	*badge = 0;
	return (cleanup_stage(1));
}

static int
cleanup_init(struct mac_capability_instance *s __unused, void *arg __unused)
{
	return (atomic_load_acq_int(&fail_init) != 0 ? EIO : cleanup_stage(2));
}

static int
cleanup_call(struct mac_capability_instance *s __unused,
    const void *req __unused, size_t reqlen __unused,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused, void *reply __unused, size_t *replylen __unused,
    struct file **reply_fds __unused, int *reply_nfds __unused,
    void *arg __unused)
{
	return (EOPNOTSUPP);
}

/* A descriptor close runs as in-flight work on the instance (op bracket). */
static void
cleanup_fdclose(struct mac_capability_instance *s __unused, int fd __unused,
    struct thread *td __unused, void *arg __unused)
{
	(void)cleanup_stage(3);
}

/*
 * Service destroy is held up.  Runs with a mutex held (mac_capability.h): it
 * only stores and wakes.  The first reason is kept.
 */
static eventhandler_tag cleanup_destroy_wait_tag;
static void
cleanup_destroy_wait(void *arg __unused, const char *service,
    enum mac_capability_destroy_wait_reason reason)
{
	if (strcmp(service, "test_cleanup") != 0)
		return;
	if (atomic_cmpset_int(&destroy_waiting, 0, reason))
		wakeup(&destroy_waiting);
}

static void
cleanup_revoke(struct mac_capability_instance *s __unused,
    uint64_t badge __unused, enum mac_capability_revoke_reason reason __unused,
    void *arg __unused)
{
	cleanup_set(&entered, 1);
	cleanup_block(&release_callback, "capcleanfixture");
}

static const struct mac_capability_ops cleanup_ops = {
	.co_connect = cleanup_connect,
	.co_init = cleanup_init,
	.co_call = cleanup_call,
	.co_fdclose = cleanup_fdclose,
	.co_revoke = cleanup_revoke,
};

static int
cleanup_modevent(module_t mod __unused, int type, void *arg __unused)
{
	int error;
	struct mac_capability_service_params p = {
		.name = "test_cleanup", .ops = &cleanup_ops, .instance_limit = 4,
		.flags = MAC_CAPABILITY_SVC_MINTABLE,
	};

	switch (type) {
	case MOD_LOAD:
		cleanup_destroy_wait_tag = EVENTHANDLER_REGISTER(
		    mac_capability_destroy_wait, cleanup_destroy_wait, NULL,
		    EVENTHANDLER_PRI_ANY);
		error = mac_capability_service_create(&p, &cleanup_svc);
		if (error != 0)
			EVENTHANDLER_DEREGISTER(mac_capability_destroy_wait,
			    cleanup_destroy_wait_tag);
		return (error);
	case MOD_UNLOAD:
		cleanup_set(&destroy_entered, 1);
		mac_capability_service_destroy(cleanup_svc);
		EVENTHANDLER_DEREGISTER(mac_capability_destroy_wait,
		    cleanup_destroy_wait_tag);
		atomic_store_rel_int(&destroy_returned, 1);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cleanup_mod = {
	"mac_capability_test_cleanup", cleanup_modevent, NULL,
};
DECLARE_MODULE(mac_capability_test_cleanup, cleanup_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(mac_capability_test_cleanup, 1);
MODULE_DEPEND(mac_capability_test_cleanup, mac_capability, 1, 1, 1);
