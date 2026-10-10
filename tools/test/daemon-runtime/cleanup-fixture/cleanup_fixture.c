/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Isolated VM fixture for callback completion versus service unload.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <machine/atomic.h>
#include "mac_capability.h"

static struct mac_capability_service *cleanup_svc;
static u_int entered, release_callback, destroy_entered, fail_init;
SYSCTL_NODE(_debug, OID_AUTO, capability_cleanup_test, CTLFLAG_RD, 0,
    "Private VM cleanup fixture");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, entered, CTLFLAG_RD,
    &entered, 0, "Callback entered");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, release, CTLFLAG_RW,
    &release_callback, 0, "Release blocked callback");
SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, destroy_entered, CTLFLAG_RD,
    &destroy_entered, 0, "Service destroy entered");

SYSCTL_UINT(_debug_capability_cleanup_test, OID_AUTO, fail_init, CTLFLAG_RW,
    &fail_init, 0, "Fail initialization before publication");

static int
cleanup_init(struct mac_capability_instance *s __unused, void *arg __unused)
{
	return (atomic_load_acq_int(&fail_init) != 0 ? EIO : 0);
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

static void
cleanup_revoke(struct mac_capability_instance *s __unused,
    uint64_t badge __unused, enum mac_capability_revoke_reason reason __unused,
    void *arg __unused)
{
	atomic_store_rel_int(&entered, 1);
	/* Bound even a failed userspace test; never leave a fixture stuck. */
	for (int i = 0; i < 10 * hz &&
	    atomic_load_acq_int(&release_callback) == 0; i++)
		pause("capcleanfixture", 1);
}

static const struct mac_capability_ops cleanup_ops = {
	.co_init = cleanup_init,
	.co_call = cleanup_call,
	.co_revoke = cleanup_revoke,
};

static int
cleanup_modevent(module_t mod __unused, int type, void *arg __unused)
{
	struct mac_capability_service_params p = {
		.name = "test_cleanup", .ops = &cleanup_ops, .instance_limit = 4,
	};

	switch (type) {
	case MOD_LOAD:
		return (mac_capability_service_create(&p, &cleanup_svc));
	case MOD_UNLOAD:
		atomic_store_rel_int(&destroy_entered, 1);
		mac_capability_service_destroy(cleanup_svc);
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
