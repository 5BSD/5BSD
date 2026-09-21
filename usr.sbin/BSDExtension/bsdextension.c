/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdextension(8) — the system-extension broker.
 *
 * Owns kernel-module ("system extension") loading, taking it out of PID 1.
 * bsdextension is a socket-free service_provider: it exposes the well-known name
 * system.SystemExtension and serves each client on its own mac_capability
 * worker channel.  A client asks it to ensure a named extension is loaded; the
 * domain layer restricts system.SystemExtension to SYSTEM-domain clients, so a
 * user service can never reach it and therefore can never load kernel code.
 *
 * bsdextension holds no /dev/mac_capability handle of its own — PID 1 owns that
 * device.  It declares the kldload system-capability gate in its
 * manifest; switchboard mints the matching system token (capsule claims the
 * gate under its nonce) and delivers it as a bootstrap capability.
 * service_provider_authorize_capabilities() authorizes that token, adding
 * bsdextension's process nonce to the gate's authorized set.  Because the pdfork'd
 * workers share bsdextension's fork-family nonce, each worker's kldload(2) passes the
 * gate — no token is minted here, no device is opened, and no socket appears
 * anywhere in the path.
 *
 * bsdextension runs as root and NOT in capability mode.  kldload(2) needs the classic
 * PRIV_KLD_LOAD privilege (checked before the gate) and resolves a bare module
 * name against the global kernel module path, which capsicum forbids; module
 * loading is inherently privileged and unsandboxable.  The mac_capability system
 * gate is what actually authorizes the load — even root is denied without the
 * held token — so root only satisfies the classical privilege underneath it.
 * For ENSURE, modfind(2)/kldstat(2) are avoided: a kldload whose module is
 * already present returns EEXIST, which bsdextension reports as success, so ENSURE
 * needs only the kldload gate.  The STAT operation, in contrast, must query
 * without loading; it uses kldfind(2) (a filename lookup that pairs with
 * kldload's filename argument).  kldfind is a read-only query and is not
 * gated — module enumeration is deliberately open (the DTrace toolchain
 * depends on it) — so bsdextension's manifest declares only the kldload gate.
 *
 * There is deliberately no UNLOAD operation: safe removal needs per-consumer
 * module refcounting/ownership this broker does not track, so one SYSTEM client
 * could otherwise unload code another still depends on.  See sysext_proto.h.
 *
 * Loading is default-deny by module name as well as by domain: bsdextension carries
 * an allow-list of module names it is permitted to load (the built-in set of
 * on-demand modules the base system legitimately requests, overridable by an
 * operator UCL config).  A name that passes the path-traversal check but is not
 * on the allow-list is refused with EPERM and logged.  This closes the gap where
 * any SYSTEM-domain client, once past the domain gate, could load ARBITRARY
 * kernel code; the gate authorizes reaching bsdextension, the allow-list authorizes
 * WHICH kernel code may load.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/procdesc.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <channel.h>
#include <libservice.h>

#include "sysext_proto.h"
#include "bsdextension.h"
#include "bsdextension_reclaim.h"
#include "bsdextension_probes.h"

/*
 * A LIST reply must be able to carry the entire allow-list in one message.
 */
_Static_assert(SYSEXT_MAX_ALLOW <= SYSEXT_LIST_MAX,
    "allow-list capacity must fit in a SYSEXT_OP_LIST reply");

/*
 * The kernel-module allow-list.  Loading is default-deny by name: only a module
 * whose name appears here may be loaded.  The built-in defaults are the exact
 * set of extensions the base system loads on demand today (see
 * sysext_config_defaults); an optional operator config (SYSEXT_DEFAULT_CONF)
 * may replace the set.  A missing config is not an error — the built-in set
 * stands, so the control is fail-closed with no dependency on a file being
 * present early in boot.
 *
 * SYSEXT_MAX_ALLOW, SYSEXT_DEFAULT_CONF and struct sysext_config are defined in
 * bsdextension.h so the unit tests share one definition.
 */

/*
 * Shared before accepting clients; authorized reloads publish to all workers.
 */
static struct sysext_policy *active_policy;
static const char *policy_path = SYSEXT_DEFAULT_CONF;
/*
 * True when the allow-list came from the switchboard-delivered Config directory
 * (production, born-in-capmode) rather than an explicit -c path (tests / pre-
 * capmode).  RELOAD must then re-open via service_config_open, since an absolute
 * open(policy_path) is refused (ECAPMODE) after the daemon enters capability mode.
 */
static bool policy_delivered = true;

struct sysext_client {
	const char *label;
	const char *bundle;	/* installed bundle (stamped container), or "" */
	service_rights_t rights;
};

/* The module -> bundle owner map's directory (reclaim.c), or -1. */
static int sysext_owners_fd = -1;

/*
 * The held "system" gate token covering SYS_GATE_KLDLOAD (+ KLDUNLOAD),
 * dup'd in main() before entering capability mode.  A born-in-capmode broker
 * loads/unloads modules THROUGH this token (service_system_kldload/kldunload),
 * since the raw kldload(2) would fail priv_check(PRIV_KLD_LOAD) as the
 * unprivileged capability user.  -1 when no token is held (a unit test, or
 * fail-soft), in which case load/unload fall back to the direct syscalls.
 */
int sysext_kld_token = -1;
#define	g_kld_token	sysext_kld_token

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * held service instance can never occupy a stdio slot and be clobbered by a
 * later /dev/null redirect.  bsdextension is launched by switchboard without a
 * controlling terminal.
 */
#ifndef BSDEXTENSION_TESTING
static void
reserve_stdio(void)
{
	int fd, nfd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			continue;
		nfd = open("/dev/null", O_RDWR);
		if (nfd == -1)
			continue;
		if (nfd != fd) {
			(void)dup2(nfd, fd);
			(void)close(nfd);
		}
	}
}
#endif /* !BSDEXTENSION_TESTING */

/*
 * A module name must be a single, safe filename component: NUL-terminated
 * within the buffer, non-empty, not "." or "..", and containing no '/' (no path
 * traversal, no absolute path).  Embedded dots ARE permitted — real module
 * names contain them (e.g. "if_foo.ko"-style names) — only the pure "." and
 * ".." directory names are rejected.  This is a syntactic guard; the allow-list
 * (extension_allowed) decides WHICH module may actually load.
 */
SYSEXT_STATIC bool
valid_module_name(const char *name)
{

	if (memchr(name, '\0', SYSEXT_NAME_MAX) == NULL)
		return (false);
	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	return (true);
}

/*
 * The built-in allow-list: the modules the base system legitimately loads on
 * demand through system.SystemExtension today.  Derived from the tree's
 * service_ensure_extension(3) callers and the equivalent early-boot kldload
 * needs:
 *
 *   cryptodev  bsdcrypto (usr.sbin/bsdcrypto): /dev/crypto for OCF.
 *   vhid       blued (usr.sbin/bluetooth/blued):   virtual-HID transport.
 *   zfs        bsdfilesystem (usr.sbin/bsdfilesystem):             storage backing /Capabilities.
 *   linux64    sysextctl:                        Linux application runtime.
 *
 * Deliberately narrow — every entry corresponds to a concrete on-demand
 * consumer.  Do not broaden without a matching consumer.
 */
SYSEXT_STATIC void
sysext_config_defaults(struct sysext_config *cfg)
{
	static const char *const builtin[] = {
		"cryptodev", "vhid", "zfs", "linux64"
	};
	size_t i;

	memset(cfg, 0, sizeof(*cfg));
	for (i = 0; i < nitems(builtin); i++)
		(void)strlcpy(cfg->allow[i], builtin[i], SYSEXT_NAME_MAX);
	cfg->nallow = nitems(builtin);
}

/* True iff name is on the resolved allow-list (exact match). */
SYSEXT_STATIC bool
extension_allowed(const struct sysext_config *cfg, const char *name)
{
	size_t i;

	for (i = 0; i < cfg->nallow; i++) {
		if (strcmp(cfg->allow[i], name) == 0)
			return (true);
	}
	return (false);
}

/*
 * Overlay an operator UCL config on top of the built-in allow-list.  A missing
 * file is not an error (the built-in set stands, fail-closed).  A present file
 * with an "allowed_extensions" string array REPLACES the built-in set; each
 * entry must itself be a valid single-component module name.  Any malformed or
 * over-permissive file is rejected wholesale (EINVAL) and the built-in set is
 * left untouched, so a bad config can never widen what may load.
 */
/*
 * Parse a trusted, already-open config fd into cfg.  The fd is authoritative by
 * PROVENANCE -- either switchboard-delivered from the veriexec-protected bundle
 * Config directory (service_config_open), or an operator-named path -- so there
 * is NO uid/ownership check: possession of the descriptor is the authorization
 * (a born-in-capmode broker is not root and cannot own an operator config).
 * The only checks are cheap integrity: a regular, size-bounded, non-group/other
 * -writable file.  Does not close fd (the caller owns it).
 */
static int
sysext_config_parse_fd(struct sysext_config *cfg, int fd, bool required)
{
	struct sysext_config saved;
	struct ucl_parser *p;
	const ucl_object_t *root, *arr, *ent;
	ucl_object_iter_t it = NULL;
	struct stat sb;
	int error;
	size_t count = 0;

	saved = *cfg;
	if (fstat(fd, &sb) == -1)
		return (-1);
	if (!S_ISREG(sb.st_mode) || sb.st_size > 1024 * 1024 ||
	    (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		return (errno = EPERM, -1);
	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL)
		return (errno = ENOMEM, -1);
	if (!ucl_parser_add_fd(p, fd)) {
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}
	root = ucl_parser_get_object(p);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		if (root != NULL)
			ucl_object_unref(__DECONST(ucl_object_t *, root));
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}

	arr = ucl_object_lookup(root, "allowed_extensions");
	if (arr == NULL && required)
		goto invalid;
	if (arr != NULL) {
		if (ucl_object_type(arr) != UCL_ARRAY)
			goto invalid;
		while ((ent = ucl_object_iterate(arr, &it, true)) != NULL) {
			const char *s;

			if (count >= SYSEXT_MAX_ALLOW ||
			    ucl_object_type(ent) != UCL_STRING ||
			    (s = ucl_object_tostring(ent)) == NULL ||
			    strlcpy(cfg->allow[count], s, SYSEXT_NAME_MAX) >=
			    SYSEXT_NAME_MAX ||
			    !valid_module_name(cfg->allow[count]))
				goto invalid;
			count++;
		}
		cfg->nallow = count;
	}

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (0);

invalid:
	error = EINVAL;
	*cfg = saved;
	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (errno = error, -1);
}

/* Open `path` and parse it (integrity + provenance as in parse_fd). */
static int
sysext_config_read(struct sysext_config *cfg, const char *path, bool required)
{
	int fd, r, error;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd == -1)
		return (errno == ENOENT && !required ? 0 : -1);
	r = sysext_config_parse_fd(cfg, fd, required);
	error = errno;
	(void)close(fd);
	errno = error;
	return (r);
}

SYSEXT_STATIC int
sysext_config_load(struct sysext_config *cfg, const char *path)
{
	return (sysext_config_read(cfg, path, false));
}

/*
 * Load the allow-list from a switchboard-delivered Config descriptor (the
 * born-in-capmode path: no global namespace access).  Holding the fd is the
 * authorization; the fd is not closed here.  External linkage (not
 * SYSEXT_STATIC): policy.c's capmode-safe RELOAD (sysext_policy_reload_fd) calls
 * it, and main()/tests use it too.
 */
int
sysext_config_load_fd(struct sysext_config *cfg, int fd)
{
	return (sysext_config_parse_fd(cfg, fd, false));
}

int
sysext_config_reload(struct sysext_config *cfg, const char *path)
{
	return (sysext_config_read(cfg, path, true));
}

/*
 * Ensure the named kernel extension is loaded.  Returns 0 on success (including
 * "already loaded") or an errno.  kldload(2) is CAPENABLED; a name that is
 * already present returns EEXIST, which is success for an ensure.
 */
static int
ensure_extension(const char *name, bool *loaded_now)
{
	int fileid;

	*loaded_now = false;
	/*
	 * Load THROUGH the held SYS_GATE_KLDLOAD token when born in capability
	 * mode (the raw kldload(2) would fail priv_check as the unprivileged
	 * capability user); fall back to a direct kldload(2) when no token is
	 * held (a unit test).  Both resolve `name` the same way and treat an
	 * already-loaded module (EEXIST) as success.
	 */
	if (g_kld_token >= 0) {
		if (service_system_kldload(g_kld_token, name, &fileid) == 0) {
			*loaded_now = true;
			return (0);
		}
		if (errno == EEXIST)
			return (0);
		return (errno);
	}
	if (kldload(name) != -1) {
		*loaded_now = true;
		return (0);
	}
	if (errno == EEXIST)
		return (0);
	return (errno);
}

/*
 * Query whether the named kernel extension is currently loaded, WITHOUT loading
 * it.  Sets *loaded to 1 if present, 0 if not, and returns 0; on a real error
 * returns the errno (and leaves *loaded 0).  kldfind(2) resolves a bare module
 * name against the loaded-file list exactly as kldload resolves it against the
 * module path (both accept the ".ko"-less name), so STAT and ENSURE agree on
 * what a name refers to.  kldfind is the query ENSURE deliberately avoids; it
 * is read-only and ungated (module enumeration is deliberately open), so STAT
 * needs no system capability at all.
 */
static int
stat_extension(const char *name, int *loaded)
{

	*loaded = 0;
	if (kldfind(name) != -1) {
		*loaded = 1;
		return (0);
	}
	if (errno == ENOENT)
		return (0);
	return (errno);
}

/*
 * Per-client channel request handler.  arg is the connecting client's
 * unforgeable label (for the audit log only; the domain layer already gated
 * reachability).  The reply is a fixed sysext_reply.
 */
static void
sysext_request(struct channel *ch __unused, struct channel_message *m, void *arg)
{
	const struct sysext_client *identity = arg;
	const char *client = identity->label;
	struct sysext_config cfg;
	const struct sysext_request *rq;
	struct sysext_reply rp;
	struct sysext_stat_reply srp;
	struct sysext_list_reply lrp;
	struct channel_outgoing out;
	bool loaded_now;
	int loaded;

	memset(&rp, 0, sizeof(rp));
	memset(&srp, 0, sizeof(srp));

	if (channel_message_length(m) != sizeof(*rq) ||
	    channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if (rq->_reserved != 0 ||
	    (rq->op != SYSEXT_OP_ENSURE && rq->op != SYSEXT_OP_STAT &&
	    rq->op != SYSEXT_OP_LIST && rq->op != SYSEXT_OP_RELOAD)) {
		rp.status = EINVAL;
		goto reply;
	}
	if (rq->op == SYSEXT_OP_LIST || rq->op == SYSEXT_OP_RELOAD) {
		static const char empty[SYSEXT_NAME_MAX];
		if (memcmp(rq->name, empty, sizeof(empty)) != 0) {
			rp.status = EINVAL;
			goto reply;
		}
	}
	if (rq->op == SYSEXT_OP_RELOAD) {
		/*
		 * Reload capmode-safely: in production the operator allow-list is read
		 * through the switchboard-delivered Config descriptor (an absolute
		 * open(policy_path) is refused after cap_enter); an explicit -c path
		 * (tests / pre-capmode) still reloads by path.
		 */
		if (policy_delivered) {
			int rfd;

			if (service_config_open(SYSEXT_CONFIG_NAME, &rfd) == 0) {
				if (sysext_policy_reload_fd(active_policy, rfd,
				    identity->rights) == -1)
					rp.status = errno;
				(void)close(rfd);
			} else {
				rp.status = errno;
			}
		} else if (sysext_policy_reload(active_policy, policy_path,
		    identity->rights) == -1) {
			rp.status = errno;
		}
		syslog(LOG_NOTICE, "RELOAD (client %s) -> %s", client,
		    rp.status == 0 ? "policy installed" : strerror(rp.status));
		goto reply;
	}
	if (sysext_policy_snapshot(active_policy, &cfg) == -1) {
		rp.status = errno;
		goto reply;
	}
	/*
	 * LIST enumerates the module names the allow-list permits, so a consumer
	 * can discover what it may ENSURE without STAT-probing names blindly.  It
	 * carries no module name and is not itself gated by the allow-list (it
	 * only reveals which names may load, never any loaded/not-loaded state);
	 * reaching bsdextension at all already required the SYSTEM-domain gate.  The
	 * allow-list is global, not per-label, so every caller sees the same set.
	 */
	if (rq->op == SYSEXT_OP_LIST) {
		size_t i;

		memset(&lrp, 0, sizeof(lrp));
		lrp.status = 0;
		lrp.count = (uint32_t)cfg.nallow;
		for (i = 0; i < cfg.nallow && i < SYSEXT_LIST_MAX; i++)
			(void)strlcpy(lrp.names[i], cfg.allow[i],
			    SYSEXT_NAME_MAX);
		BSDEXTENSION_PROBE_LIST(client, lrp.count, 0);
		syslog(LOG_INFO, "LIST (client %s) -> %u module(s)", client,
		    lrp.count);
		goto list_reply;
	}
	if (!valid_module_name(rq->name)) {
		rp.status = EINVAL;
		goto reply;
	}
	/*
	 * Default-deny by name, for BOTH operations: even a syntactically valid
	 * module is refused unless it is on the allow-list.  This is the boundary
	 * between "may reach bsdextension" (the domain gate) and "may act on THIS
	 * kernel code".  A client may STAT only a module it could ENSURE, so a
	 * non-allow-listed name is EPERM rather than a loaded/not-loaded answer —
	 * denial leaks no information about the module set.
	 */
	if (!extension_allowed(&cfg, rq->name)) {
		rp.status = EPERM;
		syslog(LOG_WARNING,
		    "%s %s (client %s) -> DENIED (not on allow-list)",
		    rq->op == SYSEXT_OP_STAT ? "STAT" : "ENSURE", rq->name,
		    client);
		goto reply;
	}

	if (rq->op == SYSEXT_OP_STAT) {
		srp.status = stat_extension(rq->name, &loaded);
		srp.loaded = loaded;
		if (srp.status == 0)
			syslog(LOG_INFO, "STAT %s (client %s) -> %s", rq->name,
			    client, srp.loaded ? "loaded" : "not loaded");
		else
			syslog(LOG_NOTICE, "STAT %s (client %s) -> %s", rq->name,
			    client, strerror(srp.status));
		goto stat_reply;
	}

	rp.status = ensure_extension(rq->name, &loaded_now);
	if (rp.status == 0) {
		syslog(LOG_INFO, "ENSURE %s (client %s) -> loaded", rq->name,
		    client);
		/*
		 * Attribute the module to the client's bundle (from the
		 * stamped container, never the wire) so the reconcile can
		 * unload it once the bundle is gone.  Units without a bundle
		 * (sessions, rc units) are not noted.
		 */
		if (sysext_owners_fd >= 0 && identity->bundle[0] != '\0' &&
		    sysext_owner_note(sysext_owners_fd, rq->name,
		    identity->bundle, loaded_now) == -1)
			syslog(LOG_WARNING, "reclaim: cannot note %s for bundle "
			    "%s: %m", rq->name, identity->bundle);
	} else
		syslog(LOG_NOTICE, "ENSURE %s (client %s) -> %s", rq->name,
		    client, strerror(rp.status));

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	(void)channel_send_reply(m, &out);
	channel_message_free(m);
	return;

stat_reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &srp;
	out.length = sizeof(srp);
	(void)channel_send_reply(m, &out);
	channel_message_free(m);
	return;

list_reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &lrp;
	out.length = sizeof(lrp);
	(void)channel_send_reply(m, &out);
	channel_message_free(m);
}

/*
 * Serve one client on its own worker channel until it closes.  Runs in a
 * pdfork'd worker; it shares bsdextension's fork-family nonce, so its kldload passes
 * the gate under the authorization granted at startup.
 */
static int
sysext_worker(int fd, const char *client, const char *container,
    service_rights_t rights)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	char label[SYSEXT_NAME_MAX], bundle[64] = "";
	struct sysext_client identity = { .label = label, .bundle = bundle,
	    .rights = rights };
	int ready, wants_write;

	(void)strlcpy(label, client, sizeof(label));
	/* The stamped container names the bundle; "" for units without one. */
	if (sysext_bundle_of(container, bundle, sizeof(bundle)) == -1)
		bundle[0] = '\0';

	/*
	 * channel_create() consumes (closes) fd on success and leaves it on
	 * failure -- so close it here only on failure, and NEVER after return.
	 * The caller (sysext_client_thread) must not close it again: doing so
	 * closes an fd number channel_create already handed back to the pool, which
	 * a concurrent accept on another thread may have re-used (double-close race
	 * that silently drops a co-connecting client).
	 */
	if (channel_create(fd, &options, &channel) == -1) {
		(void)close(fd);
		return (1);
	}
	if (channel_set_request_handler(channel, sysext_request, &identity) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 ||
		    (ready = channel_wait(channel, wants_write, -1)) == -1 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1))
			break;
	}
	channel_destroy(channel);
	return (0);
}

#ifdef BSDEXTENSION_TESTING
/*
 * Test-only serve entry point.  Installs cfg as the resolved allow-list (which
 * every pdfork'd worker would otherwise inherit through the fork image) and
 * runs the real per-client worker on fd, so a test drives the identical
 * sysext_request path a production worker would.  ENSURE cases a test drives
 * (deny, malformed) are refused before ensure_extension is reached, so no
 * kldload(2) runs; STAT cases for an allow-listed name do reach kldfind(2), a
 * read-only query that loads nothing and is not gated, so it succeeds in any
 * environment.
 */
int
sysext_test_serve(int fd, const char *client, const struct sysext_config *cfg)
{
	int result;

	active_policy = sysext_policy_create(cfg);
	if (active_policy == NULL)
		return (1);
	result = sysext_worker(fd, client, "", SERVICE_RIGHTS_NONE);
	sysext_policy_destroy(active_policy);
	return (result);
}
#endif /* BSDEXTENSION_TESTING */

#ifndef BSDEXTENSION_TESTING
/*
 * Per-client thread argument (heap-allocated; the thread owns and frees it).
 */
struct sysext_conn {
	int			fd;
	service_rights_t	rights;
	char			label[64];	/* service_identity.client_label */
	char			container[64];	/* service_identity.container */
};

/*
 * Per-client worker thread: run the channel session to completion, then close
 * the client fd and release the argument.  Threads (unlike pdfork workers)
 * share the daemon's SYS_GATE_KLDLOAD token, so each can perform gated loads.
 */
static void *
sysext_client_thread(void *arg)
{
	struct sysext_conn *c = arg;

	/* sysext_worker() owns c->fd (channel_create consumes it, or it closes it
	 * on failure) -- do NOT close it again here (double-close race). */
	(void)sysext_worker(c->fd, c->label, c->container, c->rights);
	free(c);
	return (NULL);
}

/*
 * Expose system.SystemExtension and serve each accepted client.
 * service_provider_authorize_capabilities() authorizes the delivered
 * SYS_GATE_KLDLOAD/KLDUNLOAD token, which is then dup'd (survives the bootstrap
 * authority drop) so it outlives into capability mode.
 *
 * bsdextension is BORN IN CAPABILITY MODE.  kldload(2)/kldunload(2) are
 * capmode-enabled but run priv_check(PRIV_KLD_LOAD/UNLOAD), which the
 * unprivileged capability user fails; the load/unload instead go THROUGH the
 * held gate (service_system_kldload/kldunload -> kern_kldload_gated), whose
 * claim replaces that privilege.  The kernel performs the module-path lookup in
 * kernel context (a UIO_SYSSPACE namei, exempt from the capmode userspace-path
 * restriction), so a born-in-capmode broker resolves modules that the raw
 * syscall could not.  The delivered token is close-on-fork, so clients are
 * served INLINE (no per-client worker could inherit it).  Returns -1 only on
 * setup failure.
 */
static int
sysext_serve(void)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, SYSEXT_SERVICE_NAME,
	    &listener) == -1)
		return (-1);
	/*
	 * Anti-tamper the process before it holds the SYS_GATE_KLDLOAD token -- the
	 * highest-value token in the fleet (module load == kernel code execution).
	 * SERVICE_PROTECT_EXTERNAL blocks ptrace/ktrace/debug of this daemon by
	 * another same-uid process, which could otherwise drive it to load a module
	 * or read the held token fd.  Every other token/privilege-holding provider
	 * (BSDTime, BSDSysctl, ...) does this; this daemon holds a strictly more
	 * dangerous token, so it must too.
	 */
	if (service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1)
		return (-1);
	/*
	 * Dup the delivered kldload/kldunload token before entering capmode;
	 * fail-soft if none was delivered (loads then attempt the raw syscall).
	 */
	if (service_system_token_dup(&sysext_kld_token) == -1) {
		syslog(LOG_WARNING, "no kldload capability; module load/unload "
		    "will attempt the raw syscall: %m");
		sysext_kld_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	/*
	 * Container model: reconcile the modules loaded on bundles' behalf
	 * against the installed-or-running bundles (reclaim.c).  Soft: without
	 * the delivered roots there is no reclaim, and loads proceed as before.
	 */
	sysext_reclaim_start(sysext_owners_fd);

	for (;;) {
		struct sysext_conn *c;
		pthread_t tid;
		int error;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		/*
		 * Serve each client on its own THREAD, not a pdfork worker: the
		 * delivered SYS_GATE_KLDLOAD token is close-on-fork, but threads
		 * share it, so a born-in-capmode broker can serve concurrent,
		 * long-lived consumer connections (service_ensure_extension caches
		 * a persistent session) without head-of-line blocking.  The shared
		 * allow-list policy is already concurrency-safe (a robust mutex +
		 * double-buffered slots); the per-label check in sysext_request
		 * stays the access boundary.
		 */
		c = malloc(sizeof(*c));
		if (c == NULL) {
			syslog(LOG_WARNING, "client alloc: %m");
			(void)close(fd);
			continue;
		}
		c->fd = fd;
		(void)strlcpy(c->label, id.client_label, sizeof(c->label));
		(void)strlcpy(c->container, id.container, sizeof(c->container));
		c->rights = id.rights;
		error = pthread_create(&tid, NULL, sysext_client_thread, c);
		if (error != 0) {
			syslog(LOG_ERR, "pthread_create: %s", strerror(error));
			(void)close(fd);
			free(c);
			continue;
		}
		(void)pthread_detach(tid);
	}
}

int
main(int argc, char **argv)
{
	struct sysext_config sysext_conf;
	const char *conf = SYSEXT_DEFAULT_CONF;
	bool conf_from_arg = false;
	int ch;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			conf = optarg;
			conf_from_arg = true;
			break;
		default:
			(void)fprintf(stderr, "usage: bsdextension [-c config]\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: bsdextension [-c config]\n");
		return (1);
	}

	/*
	 * LOG_PERROR unconditionally: switchboard captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("bsdextension", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	setproctitle("-SystemExtension");
	syslog(LOG_NOTICE, "bsdextension system-extension broker");

	/*
	 * Resolve the module allow-list before serving so every pdfork'd worker
	 * shares it.  Missing or malformed startup configuration retains the
	 * built-in allow-list; failed reloads retain the last active policy.
	 */
	sysext_config_defaults(&sysext_conf);
	if (conf_from_arg) {
		/* Explicit -c path (tests / non-plane, pre-capmode). */
		if (sysext_config_load(&sysext_conf, conf) == -1)
			syslog(LOG_WARNING, "allow-list config %s unparseable "
			    "(%m); using built-in allow-list", conf);
	} else {
		/*
		 * Plane: the allow-list config is delivered by descriptor.  A
		 * born-in-capmode broker has no global namespace, so the operator
		 * config is opened THROUGH the switchboard-delivered Config
		 * directory (service_config_open); holding that fd is the
		 * authorization.  Absent config => built-in allow-list (ENOENT).
		 */
		int cfgfd;

		if (service_config_open(SYSEXT_CONFIG_NAME, &cfgfd) == 0) {
			if (sysext_config_load_fd(&sysext_conf, cfgfd) == -1)
				syslog(LOG_WARNING, "allow-list config "
				    "unparseable (%m); built-in allow-list");
			(void)close(cfgfd);
		} else if (errno != ENOENT) {
			syslog(LOG_WARNING, "allow-list config unavailable "
			    "(%m); built-in allow-list");
		}
	}
	policy_path = conf;
	policy_delivered = !conf_from_arg;
	active_policy = sysext_policy_create(&sysext_conf);
	if (active_policy == NULL)
		err(1, "initialize shared extension policy");

	/*
	 * The module -> bundle owner map (reclaim.c), opened before serving so
	 * every pdfork'd worker inherits it.  Soft: without it loads are not
	 * attributed and never reclaimed, logged once.
	 */
	sysext_owners_fd = sysext_reclaim_open();
	if (sysext_owners_fd == -1)
		syslog(LOG_WARNING, "reclaim: cannot open %s (%m); module "
		    "reclaim disabled", SYSEXT_RECLAIM_DIR);

	/*
	 * Serve as a socket-free service_provider: authorize the delivered
	 * kldload system token, expose system.SystemExtension, remain privileged,
	 * and dispatch each client on its own worker channel.
	 * sysext_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (sysext_serve() == -1)
		errx(1, "system-extension provider failed");

	return (0);
}
#endif /* !BSDEXTENSION_TESTING */
