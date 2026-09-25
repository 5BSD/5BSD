# A Kernel Extension

A kernel extension on 5BSD is an ordinary FreeBSD kernel module with two
differences in how it reaches the running system. It is loaded through
BSDExtension (`system.SystemExtension`) rather than by whoever happens to be
root, because module loading is kernel code execution and the plane treats
it as the highest-value operation in the fleet; and if it is a security
policy or a capability service it has a larger surface to plug into: 62 MAC
hooks that FreeBSD does not have, and the mac_capability service KPI that
lets a module answer messages on a capability channel. This chapter covers
the load path, then the two module shapes, then the KPI changes an
out-of-tree module has to know about. Both module skeletons shown here were
built out of tree with `bsd.kmod.mk` against the 5BSD `sys/` tree with
`-Werror`.

## Loading through BSDExtension

The broker is born in capability mode as the unprivileged `capability`
user, so it cannot call kldload(2) itself: the raw syscall runs
`priv_check(PRIV_KLD_LOAD)` and, once the plane is live, the
`mpo_kld_check_load` hook of the system service refuses any caller that
does not hold the `kldload` gate. What BSDExtension holds instead is that
gate. Its manifest declares

```
capabilities {
    system = ["kldload", "kldunload"];
}
```

and Capsule mints a matching system token from the veriexec-verified
declaration, switchboard delivers it, and the broker authorizes it with
`service_provider_authorize_capabilities(3)`. Every load then goes
`service_system_kldload(token, name, &fileid)` to the mac_capability system
service, which checks `sys_holds_gate(cred, SYS_GATE_KLDLOAD)` and calls
`kern_kldload_gated()` in `sys/kern/kern_linker.c`, a variant of the kldload
path with the privilege check replaced by the held claim (securelevel still
applies). The module path is resolved by a kernel-space namei under a
transient credential with `CRED_FLAG_CAPMODE` cleared, so the broker's
sandbox never loosens. Enumeration is deliberately open: `kldfind(2)` and
`kldstat(2)` are ungated and capability-mode enabled, which is what lets
DTrace resolve kernel types under a production plane.

The wire protocol is `lib/libcapsulert/sysext_proto.h`.

| Op | Meaning | Allow-list applies |
|---|---|---|
| `SYSEXT_OP_ENSURE` | load a module by name; already loaded is success | yes |
| `SYSEXT_OP_STAT` | is it loaded, without loading | yes (a denied name is `EPERM`, not "not loaded") |
| `SYSEXT_OP_LIST` | the names the allow-list permits | no |
| `SYSEXT_OP_RELOAD` | re-read the policy file; needs `SERVICE_RIGHTS_ADMIN` on the session | no |

There is no unload operation. The broker unloads only what it loaded on a
bundle's behalf, during reclaim, when the bundle is gone and no other
bundle claims the module (`usr.sbin/BSDExtension/reclaim.c`). A module the
broker found already loaded is recorded but never unloaded.

The allow-list is `allowed_extensions` in the broker's config, delivered as
`Config/bsdextension.ucl` under its unit directory (the man pages give the
global `/Capabilities/Config/bsdextension.ucl` path, which is where the
non-sandboxed `-c` mode reads it). It replaces, not extends, the built-in
list, which is exactly the set the base system loads on demand:

```
allowed_extensions = [
    "cryptodev",   # bsdcrypto: /dev/crypto (OCF) for the crypto provider
    "vhid",        # blued: virtual-HID transport for the Bluetooth stack
    "zfs",         # bsdfilesystem: ZFS backing /Capabilities storage
    "linux64",     # sysextctl: Linux application runtime
]
```

The first array element must follow `[` directly; the bundled libucl
mis-parses a comment as the first token and rejects the file. A name is a
single filename component: no `/`, not `.` or `..`, under 64 bytes. Only
SYSTEM-domain callers can resolve `system.SystemExtension` at all, so a
user bundle can never cause kernel code to load whatever the list says.

## Why a daemon never kldloads itself

Because it cannot, and because it should not need to. A born-in-capmode unit
running as `capability` fails `PRIV_KLD_LOAD`; a root unit is refused by the
gate hook once any claim covers `SYS_GATE_KLDLOAD`. The manifest key
`kmod_requires` that once declared a module dependency is rejected by the
parser. The pattern is self-service with fail-soft, as BSDCrypto does in
`usr.sbin/BSDCrypto/bsdcrypto.c`:

```c
if (service_ensure_extension(ctx, "cryptodev") == -1)
	logcmp_log(LOG_NOTICE, "ensure cryptodev module: %m; continuing "
	    "(cryptodev may be built into the kernel)");
```

A built-in module is not a loadable file, so the load reports `ENOENT`; a
daemon that treated that as fatal would loop until switchboard's circuit
breaker disabled it. The client API is three functions in libservice(3)
and the program below compiles with `cc -o extload extload.c -lservice`:

```c
#include <err.h>
#include <stdio.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx;
	char names[SERVICE_EXTENSION_LIST_MAX][SERVICE_EXTENSION_NAME_MAX];
	size_t n;
	int loaded;

	if (service_acquire(&ctx) == -1)
		err(1, "service_acquire");

	/* What does the allow-list permit? Global, not per label. */
	if (service_extension_list(ctx, names, SERVICE_EXTENSION_LIST_MAX, &n) == -1)
		err(1, "service_extension_list");
	for (size_t i = 0; i < n; i++)
		printf("allowed: %s\n", names[i]);

	/* Is it loaded already? (No load attempted.) */
	if (service_extension_stat(ctx, "vhid", &loaded) == -1)
		err(1, "service_extension_stat");

	/* ENSURE: 0 if loaded now or already; EPERM if not on the allow-list. */
	if (!loaded && service_ensure_extension(ctx, "vhid") == -1)
		warn("vhid not loaded, continuing without HID (retry later)");

	service_release(ctx);
	return (0);
}
```

`service_extension_list` fails with `EMSGSIZE` rather than truncating if
the buffer is too small; a `SERVICE_EXTENSION_LIST_MAX` buffer always
holds the whole list. Calls time out after 30 seconds. The operator tool is
sysextctl(8): `sysextctl list | status module | load module | reload`,
where `status` exits 1 for a permitted but unloaded module and `reload`
needs ADMIN rights on the channel, not root.

## Writing a MAC policy against the new hooks

`sys/security/mac/mac_policy.h` is at `MAC_VERSION` 9. Beyond FreeBSD's
hooks it adds check hooks for process lifecycle (`fork`, `core`, `syscall`,
`mmap_anon`, `mprotect`, `ktrace`, `suspend`), the descriptor layer
(`file_check_receive`, `_inherit`, `_dup`, `_ioctl`, `_mmap`), `vnode_check_close`,
`vnode_check_truncate`, the `uipc_bind` and `uipc_connect` pair,
`socket_check_setsockopt`, `kld_check_unload`, `pts_check_open`,
`system_check_kas_info`, `rctl_check_add_rule` and `_remove_rule`, seven
`vmm_check_*` hooks, eight `zfs_check_*` hooks, three `mount_check_snapshot_*`
hooks and four `vsock_provider_*` hooks; notify hooks for exec completion,
exit, file close and thirteen vnode mutations; and the `execve_relabel`
pair, which refreshes per-exec credential label state without being a
set-id transition. `docs/macf-new-hooks.md` documents each with its XNU
counterpart, call site and lock context; mac(9) has not been updated.

The pattern to copy is `sys/security/mac_test_hooks/mac_test_hooks.c`, a
loadable policy that implements most of the new hooks as counters with a
per-hook deny toggle under `security.mac.test_hooks.{counter,deny}.<hook>`,
and its test `tests/sys/mac/mac_test_hooks_test.c`, which exercises a hook
by doing the operation, checking the counter moved, setting the deny
sysctl to an errno, and checking the operation now fails with it. The
skeleton below uses two hooks that do not exist in FreeBSD and follows that
file's structure: a sysctl node, one function per hook, a
`mac_policy_ops` initializer and `MAC_POLICY_SET`.

```c
#include <sys/param.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

static SYSCTL_NODE(_security_mac, OID_AUTO, book,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "mac_book policy controls");

static int book_close_count;
SYSCTL_INT(_security_mac_book, OID_AUTO, close_count, CTLFLAG_RD,
    &book_close_count, 0, "vnode close hook invocations");

static int book_deny_ioctl;
SYSCTL_INT(_security_mac_book, OID_AUTO, deny_ioctl, CTLFLAG_RW,
    &book_deny_ioctl, 0, "errno to return from every ioctl check");

/* Fires on every vnode close; a check hook may veto with an errno. */
static int
book_vnode_check_close(struct ucred *cred __unused, struct vnode *vp __unused,
    struct label *vplabel __unused)
{
	atomic_add_int(&book_close_count, 1);
	return (0);
}

/* Fires for every ioctl(2) on any file type, with the descriptor. */
static int
book_file_check_ioctl(struct ucred *cred __unused, struct file *fp __unused,
    int fd __unused, u_long cmd __unused)
{
	return (book_deny_ioctl);
}

static struct mac_policy_ops book_ops = {
	.mpo_vnode_check_close = book_vnode_check_close,
	.mpo_file_check_ioctl = book_file_check_ioctl,
};

MAC_POLICY_SET(&book_ops, mac_book, "5BSD Epic example policy",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
```

The Makefile is two lines plus the include; `vnode_if.h` must be in `SRCS`
because `mac_policy.h` pulls in vnode types:

```make
KMOD=	mac_book
SRCS=	vnode_if.h mac_book.c

.include <bsd.kmod.mk>
```

Two things a policy author should know from the framework. `mac_vnode_check_close`
is called from `sys/kern/vfs_vnops.c` with the vnode locked; its only
in-tree consumer is OES, which uses it for `NOTIFY_CLOSE`. And
`file_check_ioctl` and `file_check_mmap` are among the seven hot hooks with
an `FPFLAG` fast path: the framework skips the call entirely when no loaded
policy implements the hook, so a policy that registers one pays for every
ioctl in the system and should return quickly. The `vmm_check_*` and
`zfs_check_*` hooks are enforcement points with no production policy behind
them yet; only `mac_test_hooks` implements them.

## Writing a mac_capability service module

The second shape is a module that provides a service on the capability
plane: a named endpoint that userland connects to through
`/dev/mac_capability` and talks to over a channel, with the kernel
delivering each message with the sender's credential attached. The nine
production services (isolation, system, coalition, capprotect, node, mount,
accounting, identity, channel) are compiled into every kernel as
`standard` in `sys/conf/files`; the two test fixtures
`mac_capability_test_keystore` and `mac_capability_test_kernelstore` are
loadable and are the patterns. The KPI is `sys/dev/mac_capability/mac_capability.h`
and `docs/mac_capability-architecture.md` has the full callback contract.

A service fills a `struct mac_capability_ops`. `co_connect` runs when a
process connects and assigns a badge; `co_handler` runs on the service's
taskqueue for each async message, never concurrently for one instance, and
answers with `mac_capability_reply`; `co_call` is the synchronous
alternative, run in the caller's thread and possibly concurrently;
`co_revoke` fires exactly once when an instance dies. The keystore fixture
is async-only and the kernelstore fixture is the `co_call` example. This
echo service, modelled on `mac_capability_test_keystore.c`, builds as a
module:

```c
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/ucred.h>

#include "mac_capability.h"

MALLOC_DEFINE(M_CAPSVC_BOOK, "capsvc_book", "capsvc_book replies");

#define	BOOK_MAX_PAYLOAD	4096

struct book_reply {
	uint32_t	status;
	uint32_t	uid;
	uint8_t		data[];
};

static struct mac_capability_service *book_svc;
static volatile uint64_t book_next_badge = 1;

/* One connection = one instance; hand it a monotonic badge. */
static int
book_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	return (MAC_CAPABILITY_CONNECT_BADGE(book_next_badge, badge_out));
}

/* Runs on the service taskqueue, never concurrently per instance. */
static int
book_handler(struct mac_capability_instance *s,
    const struct mac_capability_msg *msg, void *arg __unused)
{
	struct book_reply *rep;
	size_t len, replylen;

	len = mac_capability_msg_datalen(msg);
	if (len > BOOK_MAX_PAYLOAD) {
		struct book_reply err = { .status = EMSGSIZE };

		mac_capability_reply(s, mac_capability_msg_token(msg), &err,
		    sizeof(err), NULL, NULL, 0);
		return (0);
	}
	replylen = sizeof(*rep) + len;
	rep = malloc(replylen, M_CAPSVC_BOOK, M_WAITOK | M_ZERO);
	rep->status = 0;
	rep->uid = mac_capability_msg_cred(msg)->cr_uid;
	memcpy(rep->data, mac_capability_msg_data(msg), len);
	mac_capability_reply(s, mac_capability_msg_token(msg), rep, replylen,
	    NULL, NULL, 0);
	free(rep, M_CAPSVC_BOOK);
	return (0);
}

static const struct mac_capability_ops book_ops = {
	.co_connect = book_connect,
	.co_handler = book_handler,
};

static int
capsvc_book_modevent(module_t mod __unused, int type, void *unused __unused)
{
	struct mac_capability_service_params p = {
		.name = "book_echo",
		.ops = &book_ops,
	};

	switch (type) {
	case MOD_LOAD:
		return (mac_capability_service_create(&p, &book_svc));
	case MOD_UNLOAD:
		if (book_svc != NULL)
			mac_capability_service_destroy(book_svc);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t capsvc_book_mod = {
	"capsvc_book", capsvc_book_modevent, NULL,
};

DECLARE_MODULE(capsvc_book, capsvc_book_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(capsvc_book, 1);
MODULE_DEPEND(capsvc_book, mac_capability, 1, 1, 1);
```

```make
KMOD=	capsvc_book
SRCS=	capsvc_book.c
CFLAGS+= -I${SYSDIR}/dev/mac_capability

.include <bsd.kmod.mk>
```

The parts that matter for correctness: the reply token comes from the
message and must be used exactly once; `mac_capability_msg_cred` is the
sender's credential as stamped by the kernel, which is how a service scopes
state by uid or nonce without trusting the payload; `queue_depth`,
`tx_limit` and `instance_limit` in the params (zero means the defaults,
1024 instances) are the resource ceilings; a service that pushes unsolicited
messages sets `MAC_CAPABILITY_SVC_NOTIFY` and uses `mac_capability_notify`;
and `MODULE_DEPEND` on `mac_capability` is required. The kernel-side tests
in `tests/sys/mac_capability` load the fixtures with `kldload` on a
plane-off boot, which is how you would test a new service before there is a
userland provider in front of it (see [Testing](testing.md)).

## KPI changes to know about

Out-of-tree modules written for FreeBSD hit three signature changes.

`vop_spare1` is now `vop_fileclose`. `sys/kern/vnode_if.src` defines
`VOP_FILECLOSE(vp, fp, last, td)` with the vnode exclusively locked: it
tells a filesystem that one open description of the vnode is being flushed
(`last` false, from `vn_file_close_fd()`) or that the last owner is
releasing it (`last` true, from the close path after advisory locks are
dropped, and from the error path of a create that had a handle awaiting
`VOP_OPEN`). It backs the per-open vnode fileops table `vn_openfileops[]`
in `sys/kern/vfs_vnops.c` and exists for FUSE's per-descriptor handles. A
filesystem that used the spare slot must move; one that does not implement
it gets the default.

`fdcopy()` takes a third argument: `fdcopy(fdp, p1, bool isfork)`. The
`CAP_CLOFORK_ONCE` descriptor state survives exactly one fork and then
locks, so the copy has to know whether it is a fork boundary, and a real
fork takes the table's exclusive lock so concurrent forks cannot both
consume the single crossing. `kern_fork.c` passes `true`; the internal copy
that unshares a table passes `false`.

`fget_mmap()` gained an out-parameter: `fget_mmap(td, fd, rightsp, maxprotp, uint8_t *fde_flagsp, fpp)`.
It returns the per-descriptor `fde_flags` so `mmap(2)` can enforce
`UF_MMAP_CAPMODE`, the monotone per-fd flag that says this descriptor may
be mapped only from inside capability mode; `sys/vm/vm_mmap.c` fails such a
map with `ENOTCAPABLE` outside the sandbox and fires the
`capsicum:::mmap-capmode-deny` probe. The same call site is where
`mac_file_check_mmap` runs. Pass `NULL` if you do not care.

Two smaller ones from the same area: `mpo_file_check_receive` has a
different signature from upstream's (it takes the `struct file`), and
`MAC_MAX_SLOTS` is 7. The inventory row for KPI breaks
(`docs/5bsd-inventory.md`, section 13) also lists `vfs_spare`,
`SDHCI_VERSION` 3 and pseudofs ABI 3.

## Shipping it

A module's package is chosen in its Makefile: `PACKAGE=` before the
`bsd.kmod.mk` include routes the `.ko` into that pkgbase package through
`KMODTAGS`, and an unset `PACKAGE` means the kernel package. The test
fixtures set `PACKAGE= mac-capability-tests`; `sys/modules/oes/Makefile`
sets `PACKAGE= oes` so the module travels with liboes and oeslogger. Add
the module name to the broker's `allowed_extensions`, or it will be refused
with `EPERM` however it is packaged. The rest is in
[Packaging and Shipping](packaging.md).
