/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * sysextd(8) — the system-extension broker.
 *
 * Owns kernel-module ("system extension") loading, taking it out of PID 1.
 * sysextd is a socket-free service_provider: it exposes the well-known name
 * system.SystemExtension and serves each client on its own mac_capability
 * worker channel.  A client asks it to ensure a named extension is loaded; the
 * domain layer restricts system.SystemExtension to SYSTEM-domain clients, so a
 * user service can never reach it and therefore can never load kernel code.
 *
 * sysextd holds no /dev/mac_capability handle of its own — PID 1 owns that
 * device.  It declares the kldload/kldstat system-capability gates in its
 * manifest; serviced mints the matching system token (authorityd claims the
 * gates under its nonce) and delivers it as a bootstrap capability.
 * service_provider_authorize_capabilities() authorizes that token, adding
 * sysextd's process nonce to the gate's authorized set.  Because the pdfork'd
 * workers share sysextd's fork-family nonce, each worker's kldload(2) passes the
 * gate — no token is minted here, no device is opened, and no socket appears
 * anywhere in the path.
 *
 * sysextd runs as root and NOT in capability mode.  kldload(2) needs the classic
 * PRIV_KLD_LOAD privilege (checked before the gate) and resolves a bare module
 * name against the global kernel module path, which capsicum forbids; module
 * loading is inherently privileged and unsandboxable.  The mac_capability system
 * gate is what actually authorizes the load — even root is denied without the
 * held token — so root only satisfies the classical privilege underneath it.
 * For ENSURE, modfind(2)/kldstat(2) are avoided: a kldload whose module is
 * already present returns EEXIST, which sysextd reports as success, so ENSURE
 * needs only the kldload gate.  The STAT operation, in contrast, must query
 * without loading; it uses kldfind(2) (a filename lookup that pairs with
 * kldload's filename argument), which is what exercises the SYS_GATE_KLDSTAT
 * gate the manifest declares alongside kldload.
 *
 * There is deliberately no UNLOAD operation: safe removal needs per-consumer
 * module refcounting/ownership this broker does not track, so one SYSTEM client
 * could otherwise unload code another still depends on.  See sysext_proto.h.
 *
 * Loading is default-deny by module name as well as by domain: sysextd carries
 * an allow-list of module names it is permitted to load (the built-in set of
 * on-demand modules the base system legitimately requests, overridable by an
 * operator UCL config).  A name that passes the path-traversal check but is not
 * on the allow-list is refused with EPERM and logged.  This closes the gap where
 * any SYSTEM-domain client, once past the domain gate, could load ARBITRARY
 * kernel code; the gate authorizes reaching sysextd, the allow-list authorizes
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
#include "sysextd.h"

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
 * sysextd.h so the unit tests share one definition.
 */

/*
 * Populated once in main() before the accept loop, so every pdfork'd worker
 * inherits the resolved allow-list through the fork image.
 */
static struct sysext_config sysext_conf;

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * held service instance can never occupy a stdio slot and be clobbered by a
 * later /dev/null redirect.  sysextd is launched by serviced without a
 * controlling terminal.
 */
#ifndef SYSEXTD_TESTING
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
#endif /* !SYSEXTD_TESTING */

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
 *   cryptodev  localcrypto (usr.sbin/localcrypto): /dev/crypto for OCF.
 *   vhid       blued (usr.sbin/bluetooth/blued):   virtual-HID transport.
 *   zfs        tzfsd (usr.sbin/tzfsd):             storage backing /Capabilities.
 *
 * Deliberately narrow — every entry corresponds to a concrete on-demand
 * consumer.  Do not broaden without a matching consumer.
 */
SYSEXT_STATIC void
sysext_config_defaults(struct sysext_config *cfg)
{
	static const char *const builtin[] = { "cryptodev", "vhid", "zfs" };
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
SYSEXT_STATIC int
sysext_config_load(struct sysext_config *cfg, const char *path)
{
	struct sysext_config saved;
	struct ucl_parser *p;
	const ucl_object_t *root, *arr, *ent;
	ucl_object_iter_t it = NULL;
	struct stat sb;
	int error, fd;
	size_t count = 0;

	saved = *cfg;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (errno == ENOENT ? 0 : -1);
	if (fstat(fd, &sb) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	/* Regular, owner-owned, not group/other writable, size-bounded. */
	if (!S_ISREG(sb.st_mode) || sb.st_size > 1024 * 1024 ||
	    sb.st_uid != geteuid() || (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		(void)close(fd);
		return (errno = EPERM, -1);
	}
	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL) {
		(void)close(fd);
		return (errno = ENOMEM, -1);
	}
	if (!ucl_parser_add_fd(p, fd)) {
		(void)close(fd);
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}
	(void)close(fd);
	root = ucl_parser_get_object(p);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		if (root != NULL)
			ucl_object_unref(__DECONST(ucl_object_t *, root));
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}

	arr = ucl_object_lookup(root, "allowed_extensions");
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
	error = errno != 0 ? errno : EINVAL;
	*cfg = saved;
	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (errno = error, -1);
}

/*
 * Ensure the named kernel extension is loaded.  Returns 0 on success (including
 * "already loaded") or an errno.  kldload(2) is CAPENABLED; a name that is
 * already present returns EEXIST, which is success for an ensure.
 */
static int
ensure_extension(const char *name)
{

	if (kldload(name) != -1)
		return (0);
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
 * what a name refers to.  kldfind is the query ENSURE deliberately avoids; it is
 * what exercises the SYS_GATE_KLDSTAT gate the manifest declares.
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
	const char *client = arg;
	const struct sysext_request *rq;
	struct sysext_reply rp;
	struct sysext_stat_reply srp;
	struct channel_outgoing out;
	int loaded;

	memset(&rp, 0, sizeof(rp));
	memset(&srp, 0, sizeof(srp));

	if (channel_message_length(m) != sizeof(*rq) ||
	    channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if ((rq->op != SYSEXT_OP_ENSURE && rq->op != SYSEXT_OP_STAT) ||
	    !valid_module_name(rq->name)) {
		rp.status = EINVAL;
		goto reply;
	}
	/*
	 * Default-deny by name, for BOTH operations: even a syntactically valid
	 * module is refused unless it is on the allow-list.  This is the boundary
	 * between "may reach sysextd" (the domain gate) and "may act on THIS
	 * kernel code".  A client may STAT only a module it could ENSURE, so a
	 * non-allow-listed name is EPERM rather than a loaded/not-loaded answer —
	 * denial leaks no information about the module set.
	 */
	if (!extension_allowed(&sysext_conf, rq->name)) {
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

	rp.status = ensure_extension(rq->name);
	if (rp.status == 0)
		syslog(LOG_INFO, "ENSURE %s (client %s) -> loaded", rq->name,
		    client);
	else
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
}

/*
 * Serve one client on its own worker channel until it closes.  Runs in a
 * pdfork'd worker; it shares sysextd's fork-family nonce, so its kldload passes
 * the gate under the authorization granted at startup.
 */
static int
sysext_worker(int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	char label[SYSEXT_NAME_MAX];
	int ready, wants_write;

	(void)strlcpy(label, client, sizeof(label));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, sysext_request, label) == -1) {
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

#ifdef SYSEXTD_TESTING
/*
 * Test-only serve entry point.  Installs cfg as the resolved allow-list (which
 * every pdfork'd worker would otherwise inherit through the fork image) and
 * runs the real per-client worker on fd, so a test drives the identical
 * sysext_request path a production worker would.  ENSURE cases a test drives
 * (deny, malformed) are refused before ensure_extension is reached, so no
 * kldload(2) runs; STAT cases for an allow-listed name do reach kldfind(2), a
 * read-only query that loads nothing (and, where the KLDSTAT gate is claimed by
 * another nonce, is itself denied — a plane test skips that environment).
 */
int
sysext_test_serve(int fd, const char *client, const struct sysext_config *cfg)
{

	sysext_conf = *cfg;
	return (sysext_worker(fd, client));
}
#endif /* SYSEXTD_TESTING */

#ifndef SYSEXTD_TESTING
/*
 * Expose system.SystemExtension and dispatch each accepted client on its own
 * pdfork'd worker.  service_provider_authorize_capabilities() authorizes the
 * delivered kldload/kldstat system token before serving.
 *
 * Unlike other capability-plane providers, sysextd does NOT enter capability
 * mode: kldload(2) resolves a bare module name against the global kernel module
 * path (a namei over kern.module_path), which capsicum forbids — in capability
 * mode the load fails ENOENT before the gate is ever consulted.  Module loading
 * is inherently privileged and unsandboxable, so sysextd stays a root,
 * non-capability-mode broker (exactly as PID 1 was before this split), gated
 * only by the held system capability.  Returns -1 only on setup failure.
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
	    &listener) == -1 ||
	    service_provider_enter_privileged(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	for (;;) {
		pid_t pid;
		int pd;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0)
			_exit(sysext_worker(fd, id.client_label));
		(void)close(fd);
		(void)close(pd);
	}
}

int
main(int argc, char **argv)
{
	const char *conf = SYSEXT_DEFAULT_CONF;
	int ch;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			conf = optarg;
			break;
		default:
			(void)fprintf(stderr, "usage: sysextd [-c config]\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: sysextd [-c config]\n");
		return (1);
	}

	/*
	 * LOG_PERROR unconditionally: serviced captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("sysextd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	setproctitle("-SystemExtension");
	syslog(LOG_NOTICE, "sysextd system-extension broker");

	/*
	 * Resolve the module allow-list before serving so every pdfork'd worker
	 * inherits it.  A missing config keeps the built-in default set (fail-
	 * closed); a malformed config is fatal rather than served with an
	 * unknown policy.
	 */
	sysext_config_defaults(&sysext_conf);
	if (sysext_config_load(&sysext_conf, conf) == -1)
		syslog(LOG_WARNING, "allow-list config %s unparseable (%m), "
		    "using built-in allow-list", conf);
	syslog(LOG_NOTICE, "allow-list: %zu module(s) permitted",
	    sysext_conf.nallow);

	/*
	 * Serve as a socket-free service_provider: authorize the delivered
	 * kldload/kldstat system token, expose system.SystemExtension, enter
	 * capability mode, and dispatch each client on its own worker channel.
	 * sysext_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (sysext_serve() == -1)
		errx(1, "system-extension provider failed");

	return (0);
}
#endif /* !SYSEXTD_TESTING */
