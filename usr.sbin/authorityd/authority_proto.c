/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityd channel protocol handler.
 *
 * Receives requests from serviced over the restricted channel,
 * validates them against the authority's claimed resource set, and
 * dispatches to mac_capability to mint tokens or create channels/coalitions.
 * Replies are sent back over the same channel with attached fds.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/wait.h>

#include <sys/zfshandle.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <fcntl.h>

#include <arpa/inet.h>

#include <errno.h>
#include <jail.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "authorityd.h"
#include "authority_init.h"
#include "authorityd_svc_proto.h"
#include "authorityd_ctl.h"		/* struct ctl_reply for cmd_reload() */
#include "serviced_ctl.h"		/* SERVICED_CTL_SUMMARY_MAX */
#include "commands.h"			/* cmd_reload() */
#include "tzfsd.h"		/* libtzfsd client: forward storage to tzfsd(8) */
#include "mac_capability_priv.h"
#include "probes.h"
#include "authority_proto_claims.h"
#include "req_validate.h"


static int	proto_channel_fd = -1;
static bool	serviced_ready;
static uint64_t	serviced_nonce;		/* set on first message */
static bool	nonce_set;

/* Per-dispatch tracking for the ipc-dispatch-done probe. */
static uint32_t dispatch_op;
static int dispatch_status;

static bool
all_zero(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t i;

	for (i = 0; i < len; i++)
		if (p[i] != 0)
			return (false);
	return (true);
}

/*
 * Return an owned descriptor for an existing persistent jail only when its
 * immutable launch identity matches the requested definition.  Reusing a
 * name with different roots, hostnames, or an explicitly requested address
 * is a policy conflict, never an implicit update.
 */
static int
existing_jail_descriptor(const struct authority_create_jail_req *req)
{
	char desc[32], hostname[64], ip4_addr[256], path[PATH_MAX];
	const char *wanted_hostname;
	char *end;
	long fd;
	int jid;

	memset(desc, 0, sizeof(desc));
	memset(hostname, 0, sizeof(hostname));
	memset(ip4_addr, 0, sizeof(ip4_addr));
	memset(path, 0, sizeof(path));
	jid = jail_getv(JAIL_GET_DESC | JAIL_OWN_DESC,
	    "name", __DECONST(char *, req->name),
	    "path", path,
	    "host.hostname", hostname,
	    "ip4.addr", ip4_addr,
	    "desc", desc,
	    NULL);
	if (jid < 0)
		return (-1);
	wanted_hostname = req->hostname[0] != '\0' ?
	    req->hostname : req->name;
	if (strcmp(path, req->path) != 0 ||
	    strcmp(hostname, wanted_hostname) != 0 ||
	    (req->ip4_addr[0] != '\0' &&
	    strcmp(ip4_addr, req->ip4_addr) != 0)) {
		errno = EEXIST;
		goto fail;
	}
	errno = 0;
	fd = strtol(desc, &end, 10);
	if (errno != 0 || end == desc || *end != '\0' ||
	    fd < 0 || fd > INT_MAX) {
		errno = EPROTO;
		goto fail;
	}
	return ((int)fd);

fail:
	if (desc[0] != '\0') {
		fd = strtol(desc, NULL, 10);
		if (fd >= 0 && fd <= INT_MAX)
			close((int)fd);
	}
	return (-1);
}

/*
 * Send a reply with optional attached fds.
 */
int
proto_reply(int status, uint64_t reply_token, int *fds, int nfds)
{
	struct mac_capability_sendmsg_args sa;
	struct authority_reply rpl;
	int i;

	/*
	 * Every delegated descriptor crosses exactly this one message edge.
	 * CAP_XFER_ONCE is consumed atomically by SENDMSG and the receiving
	 * descriptor is installed as CAP_XFER_NONE.
	 */
	if (status == 0 && nfds > 0) {
		for (i = 0; i < nfds; i++) {
			if (cap_xfer_limit(fds[i], CAP_XFER_ONCE) == -1) {
				syslog(LOG_ERR,
				    "authority_proto: confine reply fd: %m");
				status = EIO;
				fds = NULL;
				nfds = 0;
				break;
			}
		}
	}

	rpl.status = status;

	memset(&sa, 0, sizeof(sa));
	sa.payload = &rpl;
	sa.payload_len = sizeof(rpl);
	sa.reply_token = reply_token;
	if (nfds > 0) {
		sa.fds = fds;
		sa.nfds = (uint32_t)nfds;
	}

	if (ioctl(proto_channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "authority_proto: reply: %m");
		return (-1);
	}
	dispatch_status = status;
	AUTHORITYD_PROBE_IPC_REPLY(dispatch_op, status);
	return (0);
}

/*
 * Validate that a path is within the authority's claimed set.
 */
#include "claim_check.h"

/* Convenience wrappers using the global config. */
#define	path_is_claimed(p)	claim_path_covered(&od.cfg, (p))
#define	net_is_claimed(r)	claim_net_covered(&od.cfg, (r))
#define	jail_is_claimed(r)	claim_jail_covered(&od.cfg, (r))

/*
 * Verify that the requested jail path is allowed by the matching
 * claim.  If the claim specifies a path prefix, req_path must start
 * with it followed by '/' or end exactly at the prefix.  An empty
 * claim path means any absolute path is allowed.
 */
static bool
jail_path_allowed(const char *jail_name, const char *req_path)
{
	unsigned i;
	size_t plen;

	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		const struct authorityd_jail_claim *c = &od.cfg.claim_jail[i];

		if (c->name[0] == '\0' || strcmp(c->name, jail_name) != 0)
			continue;
		if (c->path[0] == '\0')
			return (true);
		plen = strlen(c->path);
		if (strncmp(req_path, c->path, plen) == 0 &&
		    (req_path[plen] == '\0' || req_path[plen] == '/'))
			return (true);
		return (false);
	}
	/* No matching claim found — shouldn't happen after jail_is_claimed. */
	return (false);
}

static void
handle_mint_path(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_path_req *req;
	int err, token_fd;

	if (!validate_path_req(payload, len, &req, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_path(req->path, &err) != 0) {
		AUTHORITYD_PROBE_MINT_PATH(req->path, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_path_token(req->path);
	if (token_fd == -1) {
		release_auto_claim_path(req->path);
		AUTHORITYD_PROBE_MINT_PATH(req->path, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_PATH(req->path, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_file(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_mint_file_req *req;
	int token_fd;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (req->_pad != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (strnlen(req->path, PATH_MAX) >= PATH_MAX) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}
	if (req->path[0] != '/') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (req->actions == 0 || (req->actions & ~FI_FS_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	{
		int err;

		if (auto_claim_path(req->path, &err) != 0) {
			AUTHORITYD_PROBE_MINT_FILE(req->path, req->actions, err);
			proto_reply(err, reply_token, NULL, 0);
			return;
		}
	}

	token_fd = mac_capability_mint_file_token(req->path, req->actions);
	if (token_fd == -1) {
		release_auto_claim_path(req->path);
		AUTHORITYD_PROBE_MINT_FILE(req->path, req->actions, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_FILE(req->path, req->actions, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_net(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_net_claim nc;
	int err, token_fd;

	if (!validate_net_req(payload, len, &nc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_net(&nc, &err) != 0 &&
	    !net_is_claimed(&nc)) {
		AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max,
		    nc.protocol, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_net_token(&nc);
	if (token_fd == -1) {
		release_auto_claim_net(&nc);
		AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol,
		    EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct authorityd_jail_claim jc;
	int err, token_fd;

	if (!validate_jail_req(payload, len, &jc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_jail(&jc, &err) != 0 &&
	    !jail_is_claimed(&jc)) {
		AUTHORITYD_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions,
		    err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_jail_token(&jc);
	if (token_fd == -1) {
		release_auto_claim_jail(&jc);
		AUTHORITYD_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_vsock(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_vsock_claim vc;
	int err, token_fd;
	if (!validate_vsock_req(payload, len, &vc, &err)) {
		AUTHORITYD_PROBE_MINT_VSOCK(0, 0, 0, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	if (auto_claim_vsock(&vc, &err) != 0) {
		AUTHORITYD_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	token_fd = mac_capability_mint_vsock_token(&vc);
	if (token_fd == -1) {
		release_auto_claim_vsock(&vc);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}
	AUTHORITYD_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

/*
 * Storage capabilities are owned by tzfsd(8), the [TZFS] storage daemon,
 * which holds the pool, the /Capabilities layout, and the flavor templates.
 * authorityd forwards mint/release requests to tzfsd and relays the
 * rights-limited handle back; it no longer opens /dev/zfs itself.
 *
 * The channel to tzfsd is cached.  tzfsd is a serviced-supervised unit (P4a,
 * docs/capability-authority-model.md) — serviced launches and restarts it, not
 * authorityd — so this just connects, retrying briefly to cover a startup or
 * restart race.
 */
static int authority_tzfsd_channel = -1;
static char authority_storage_session[TZFSD_SESSION_MAX];
static bool authority_storage_session_ready;

static void
tzfsd_channel_reset(void)
{

	if (authority_tzfsd_channel != -1) {
		close(authority_tzfsd_channel);
		authority_tzfsd_channel = -1;
	}
	authority_storage_session_ready = false;
}

static int
tzfsd_channel_get(void)
{
	int i;

	if (authority_tzfsd_channel != -1)
		goto begin_session;

	authority_tzfsd_channel = tzfsd_connect();
	if (authority_tzfsd_channel != -1)
		goto begin_session;

	/*
	 * Not up yet.  tzfsd is a serviced-supervised unit now (P4a,
	 * docs/capability-authority-model.md): serviced launches and restarts it,
	 * so authorityd no longer spawns it.  A storage request can still race
	 * tzfsd's startup (or a restart), so retry the connect briefly while
	 * serviced brings it up.
	 */
	for (i = 0; i < 100 && authority_tzfsd_channel == -1; i++) {
		struct timespec ts = { 0, 50 * 1000 * 1000 }; /* 50ms */

		(void)nanosleep(&ts, NULL);
		authority_tzfsd_channel = tzfsd_connect();
	}
	if (authority_tzfsd_channel == -1)
		return (-1);
begin_session:
	if (!authority_storage_session_ready) {
		if (authority_storage_session[0] == '\0' ||
		    tzfsd_begin_session(authority_tzfsd_channel,
		    authority_storage_session) == -1) {
			int saved = errno;

			tzfsd_channel_reset();
			errno = saved;
			return (-1);
		}
		authority_storage_session_ready = true;
	}
	return (authority_tzfsd_channel);
}

/*
 * Forward a storage mint to tzfsd and relay the rights-limited handle back to
 * the service.  flavor[0] == '\0' is a bare dataset claim; a named flavor
 * clones that template.  authorityd holds no ZFS privilege of its own.
 */
static void
handle_mint_storage(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_storage_req *req;
	struct tzfsd_req treq;
	struct tzfsd_grant grant;
	int chan, e;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (memchr(req->dataset, '\0', sizeof(req->dataset)) == NULL ||
	    req->dataset[0] == '\0' ||
	    memchr(req->flavor, '\0', sizeof(req->flavor)) == NULL ||
	    !all_zero(req->_reserved, sizeof(req->_reserved)) ||
	    (req->rights & ~ZH_ALL_RIGHTS) != 0 ||
	    (req->flags & ~ZHF_SUBTREE) != 0 ||
	    req->lifetime > ORT_STORAGE_LEASE) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	chan = tzfsd_channel_get();
	if (chan == -1) {
		proto_reply(errno != 0 ? errno : ECONNREFUSED, reply_token,
		    NULL, 0);
		return;
	}

	memset(&treq, 0, sizeof(treq));
	(void)strlcpy(treq.flavor, req->flavor, sizeof(treq.flavor));
	(void)strlcpy(treq.dataset, req->dataset, sizeof(treq.dataset));
	treq.rights = req->rights;
	treq.flags = req->flags;
	treq.lifetime = req->lifetime;
	treq.owner_uid = req->owner_uid;
	treq.owner_gid = req->owner_gid;
	if (tzfsd_request(chan, &treq, &grant) == -1) {
		e = errno;
		if (e == EPIPE || e == ECONNRESET || e == EBADF)
			tzfsd_channel_reset();
		proto_reply(e, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, &grant.handle_fd, 1);
	close(grant.handle_fd);
}

/*
 * Forward a last-holder lease storage teardown to tzfsd.  A missing
 * claim is success so stop paths stay idempotent.
 */
static void
handle_destroy_storage(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_storage_req *req;
	int chan, e;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (memchr(req->dataset, '\0', sizeof(req->dataset)) == NULL ||
	    req->dataset[0] == '\0' || req->flags != 0 || req->rights != 0 ||
	    req->lifetime != 0 || req->flavor[0] != '\0' ||
	    !all_zero(req->_reserved, sizeof(req->_reserved))) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	chan = tzfsd_channel_get();
	if (chan == -1) {
		proto_reply(errno != 0 ? errno : ECONNREFUSED, reply_token,
		    NULL, 0);
		return;
	}
	if (tzfsd_release(chan, req->dataset) == -1) {
		e = errno;
		if (e == EPIPE || e == ECONNRESET || e == EBADF)
			tzfsd_channel_reset();
		proto_reply(e, reply_token, NULL, 0);
		return;
	}
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_create_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_create_jail_req *req;
	struct authorityd_jail_claim jc;
	struct iovec iov[10];
	struct in_addr ip4;
	int err, jd, persist, niov;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (req->_pad != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	/* Validate strings are NUL-terminated. */
	if (memchr(req->name, '\0', sizeof(req->name)) == NULL ||
	    memchr(req->path, '\0', sizeof(req->path)) == NULL ||
	    memchr(req->hostname, '\0', sizeof(req->hostname)) == NULL ||
	    memchr(req->ip4_addr, '\0', sizeof(req->ip4_addr)) == NULL) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}
	if (req->name[0] == '\0' || req->path[0] != '/') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	/* Validate ip4_addr if specified. */
	if (req->ip4_addr[0] != '\0') {
		if (inet_pton(AF_INET, req->ip4_addr, &ip4) != 1) {
			syslog(LOG_NOTICE,
			    "authority_proto: create_jail: bad ip4_addr: %s",
			    req->ip4_addr);
			proto_reply(EINVAL, reply_token, NULL, 0);
			return;
		}
	}

	/* Verify the jail name is covered by our claimed set. */
	memset(&jc, 0, sizeof(jc));
	jc.actions = FI_JAIL_CREATE | FI_JAIL_GET;
	strlcpy(jc.name, req->name, sizeof(jc.name));
	strlcpy(jc.path, req->path, sizeof(jc.path));
	if (auto_claim_jail(&jc, &err) != 0 &&
	    !jail_is_claimed(&jc)) {
		syslog(LOG_NOTICE, "authority_proto: create_jail denied: %s",
		    req->name);
		proto_reply(err != 0 ? err : EACCES,
		    reply_token, NULL, 0);
		return;
	}

	/* Verify the jail path is under the claim's allowed root. */
	if (!jail_path_allowed(req->name, req->path)) {
		syslog(LOG_NOTICE,
		    "authority_proto: create_jail path denied: %s path=%s",
		    req->name, req->path);
		proto_reply(EACCES, reply_token, NULL, 0);
		release_auto_claim_jail(&jc);
		return;
	}

	/*
	 * Named execution jails are persistent serviced resources.  Relaunches
	 * attach to the existing jail if its immutable definition matches.
	 */
	jd = existing_jail_descriptor(req);
	if (jd >= 0) {
		syslog(LOG_INFO,
		    "authority_proto: reused persistent jail %s jd=%d",
		    req->name, jd);
		AUTHORITYD_PROBE_CREATE_JAIL(req->name, 0);
		proto_reply(0, reply_token, &jd, 1);
		close(jd);
		release_auto_claim_jail(&jc);
		return;
	}
	if (errno != ENOENT) {
		int error;

		error = errno;
		syslog(LOG_NOTICE,
		    "authority_proto: persistent jail %s conflicts with request: %s",
		    req->name, strerror(error));
		AUTHORITYD_PROBE_CREATE_JAIL(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		release_auto_claim_jail(&jc);
		return;
	}

	/* Build jail iovec. */
	persist = 1;
	niov = 0;
	iov[niov].iov_base = __DECONST(char *, "name");
	iov[niov].iov_len = sizeof("name");
	niov++;
	iov[niov].iov_base = __DECONST(char *, req->name);
	iov[niov].iov_len = strlen(req->name) + 1;
	niov++;
	iov[niov].iov_base = __DECONST(char *, "path");
	iov[niov].iov_len = sizeof("path");
	niov++;
	iov[niov].iov_base = __DECONST(char *, req->path);
	iov[niov].iov_len = strlen(req->path) + 1;
	niov++;
	iov[niov].iov_base = __DECONST(char *, "persist");
	iov[niov].iov_len = sizeof("persist");
	niov++;
	iov[niov].iov_base = &persist;
	iov[niov].iov_len = sizeof(persist);
	niov++;
	iov[niov].iov_base = __DECONST(char *, "host.hostname");
	iov[niov].iov_len = sizeof("host.hostname");
	niov++;
	iov[niov].iov_base = __DECONST(char *,
	    req->hostname[0] != '\0' ? req->hostname : req->name);
	iov[niov].iov_len = strlen(req->hostname[0] != '\0' ?
	    req->hostname : req->name) + 1;
	niov++;
	if (req->ip4_addr[0] != '\0') {
		iov[niov].iov_base = __DECONST(char *, "ip4.addr");
		iov[niov].iov_len = sizeof("ip4.addr");
		niov++;
		iov[niov].iov_base = &ip4;
		iov[niov].iov_len = sizeof(ip4);
		niov++;
	}

	jd = jail_set(iov, niov,
	    JAIL_CREATE | JAIL_GET_DESC | JAIL_OWN_DESC);
	if (jd < 0) {
		int error;

		error = errno;
		syslog(LOG_ERR, "authority_proto: jail_set(%s): %m", req->name);
		AUTHORITYD_PROBE_CREATE_JAIL(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		release_auto_claim_jail(&jc);
		return;
	}

	syslog(LOG_INFO, "authority_proto: created jail %s jd=%d", req->name, jd);
	AUTHORITYD_PROBE_CREATE_JAIL(req->name, 0);
	proto_reply(0, reply_token, &jd, 1);
	close(jd);
	release_auto_claim_jail(&jc);
}

static void
handle_mint_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_system_req *req;
	int token_fd;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (req->gates == 0 || (req->gates & ~SYS_GATE_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	{
		int err;

		if (auto_claim_system(req->gates, &err) != 0) {
			AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, err);
			proto_reply(err, reply_token, NULL, 0);
			return;
		}
	}

	token_fd = mac_capability_mint_system_token(req->gates);
	if (token_fd == -1) {
		release_auto_claim_system(req->gates);
		AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_channel(uint64_t reply_token)
{
	int fds[2];

	if (mac_capability_create_channel(&fds[0], &fds[1]) == -1) {
		AUTHORITYD_PROBE_CHANNEL_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_CHANNEL_CREATE(0);
	proto_reply(0, reply_token, fds, 2);
	close(fds[0]);
	close(fds[1]);
}

static void
handle_create_coalition(uint64_t reply_token)
{
	int cfd;

	cfd = mac_capability_create_coalition();
	if (cfd == -1) {
		AUTHORITYD_PROBE_COALITION_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_COALITION_CREATE(0);
	proto_reply(0, reply_token, &cfd, 1);
	close(cfd);
}

static void
handle_ready(uint64_t reply_token)
{

	if (!serviced_ready) {
		serviced_ready = true;
		syslog(LOG_INFO, "authority_proto: serviced ready");
	}
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ping(uint64_t reply_token)
{

	proto_reply(0, reply_token, NULL, 0);
}

/*
 * AUTHORITY_OP_SET_AMBIENT_LOOKUP (§21): serviced forwarded a dup of its SYSTEM
 * ambient lookup channel client end so authority-init can carry it into
 * interactive logins.  Takes ownership of fd (installs or closes it).
 *
 * Best-effort: a malformed request or a failed install is reported in the
 * status reply and never disturbs the event loop.  The reply carries no fds.
 */
/*
 * Apply a system lifecycle transition serviced relayed from its ADMIN-gated
 * system.lifecycle capability (docs/lifecycle-capability-design.md, P4b).  The
 * ack is queued before the transition runs — authority_init_lifecycle() only
 * *sets* the requested transition, which the state-machine loop applies after
 * this dispatch returns, so the caller's reply precedes the death sweep (same
 * ordering as the legacy control-socket path).
 */
static void
handle_lifecycle(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_lifecycle_req *req;
	int error;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	error = authority_init_lifecycle((int)req->lifecycle_op);
	if (error == 0)
		syslog(LOG_NOTICE,
		    "authority_proto: capability lifecycle op %u accepted",
		    req->lifecycle_op);
	proto_reply(error, reply_token, NULL, 0);
}

/*
 * Reload the authority config claims, relayed from authorityctl(8) over
 * serviced's ADMIN-gated system.lifecycle capability (P4b) in place of the
 * getpeereid control socket.  serviced has already authorized the caller, so
 * cmd_reload() runs with euid 0 to satisfy its transitional uid check; the
 * summary it produces is informational and dropped (the reply is status-only).
 */
static void
handle_reload(const void *payload __unused, uint32_t len, uint64_t reply_token)
{
	struct ctl_reply reply;
	char summary[SERVICED_CTL_SUMMARY_MAX];

	if (len != sizeof(struct authority_req_hdr)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	memset(&reply, 0, sizeof(reply));
	summary[0] = '\0';
	cmd_reload(0, &reply, summary, sizeof(summary));
	proto_reply((int)reply.status, reply_token, NULL, 0);
}

static void
handle_set_ambient_lookup(uint32_t len, int fd, uint64_t reply_token)
{

	if (len != sizeof(struct authority_req_hdr) || fd < 0) {
		if (fd >= 0)
			(void)close(fd);
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (authority_init_set_ambient_lookup(fd) == -1) {
		/* set_ambient_lookup already closed fd on failure. */
		syslog(LOG_NOTICE,
		    "authority_proto: ambient lookup install failed: %m");
		proto_reply(errno, reply_token, NULL, 0);
		return;
	}
	syslog(LOG_INFO, "authority_proto: ambient lookup channel installed for "
	    "interactive logins");
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ensure_kmod(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_kmod_req *req;
	const uint32_t gates = SYS_GATE_KLDLOAD | SYS_GATE_KLDSTAT;
	int error, id;

	if (!validate_kmod_req(payload, len, &req, &error)) {
		AUTHORITYD_PROBE_KMOD_ENSURE("", error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	if (auto_claim_system(gates, &error) != 0) {
		AUTHORITYD_PROBE_KMOD_ENSURE(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}

	id = modfind(req->name);
	if (id == -1) {
		id = kldload(req->name);
		if (id == -1)
			error = errno;
		else
			error = 0;
	} else {
		error = 0;
	}
	release_auto_claim_system(gates);

	if (error == 0)
		syslog(LOG_INFO, "authority_proto: ensured kernel module %s",
		    req->name);
	else
		syslog(LOG_ERR, "authority_proto: ensure kernel module %s: %s",
		    req->name, strerror(error));
	AUTHORITYD_PROBE_KMOD_ENSURE(req->name, error);
	proto_reply(error, reply_token, NULL, 0);
}

static void
handle_delegate_service(const void *payload, uint32_t len,
    uint64_t reply_token)
{
	const struct authority_service_req *req;
	int error, fd;

	if (!validate_service_req(payload, len, &req, &error)) {
		AUTHORITYD_PROBE_SERVICE_DELEGATE("", error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	fd = mac_capability_connect_for_delegate(req->name);
	if (fd == -1) {
		error = errno;
		AUTHORITYD_PROBE_SERVICE_DELEGATE(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	AUTHORITYD_PROBE_SERVICE_DELEGATE(req->name, 0);
	proto_reply(0, reply_token, &fd, 1);
	close(fd);
}

/* Claim/release handlers and sweep are in authority_proto_claims.c. */

/*
 * Dispatch a single request from the channel.
 * Returns 0 if message processed, -1 on receive error (peer closed).
 */
static int
proto_dispatch_one(void)
{
	struct mac_capability_recvmsg_args ra;
	union {
		struct authority_create_jail_req create_jail;
		struct authority_mint_file_req file;
		struct authority_path_req path;
		struct authority_net_req net;
		struct authority_jail_req jail;
		struct authority_vsock_req vsock;
		struct authority_system_req system;
		struct authority_kmod_req kmod;
		struct authority_service_req service;
		struct authority_req_hdr hdr;
	} buf;
	uint32_t op;
	int recv_fd = -1;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &buf;
	ra.payload_len = sizeof(buf);
	/*
	 * Accept at most one attached descriptor.  Only
	 * AUTHORITY_OP_SET_AMBIENT_LOOKUP (§21) sends one; any stray fd on another
	 * op is closed below rather than leaked.
	 */
	ra.fds = &recv_fd;
	ra.nfds = 1;

	if (ioctl(proto_channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN)
			return (0);
		syslog(LOG_WARNING, "authority_proto: recvmsg: %m");
		return (-1);
	}

	if (ra.payload_len < sizeof(uint32_t)) {
		syslog(LOG_WARNING, "authority_proto: short message (%u bytes)",
		    ra.payload_len);
		if (recv_fd >= 0)
			(void)close(recv_fd);
		return (0);
	}

	/* Nonce verification — lock to first sender. */
	if (!nonce_set) {
		serviced_nonce = ra.trailer.nonce;
		nonce_set = true;
	} else if (ra.trailer.nonce != serviced_nonce) {
		syslog(LOG_WARNING,
		    "authority_proto: nonce mismatch (got 0x%jx, expected 0x%jx)",
		    (uintmax_t)ra.trailer.nonce,
		    (uintmax_t)serviced_nonce);
		proto_reply(EACCES, ra.reply_token, NULL, 0);
		if (recv_fd >= 0)
			(void)close(recv_fd);
		return (0);
	}

	memcpy(&op, &buf, sizeof(op));
	dispatch_op = op;
	dispatch_status = 0;
	AUTHORITYD_PROBE_IPC_RECV(op);

	{
	struct timespec ts_start, ts_end;
	uint64_t dur;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	switch (op) {
	case AUTHORITY_OP_MINT_PATH:
		handle_mint_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_FILE:
		handle_mint_file(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_NET:
		handle_mint_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_JAIL:
		handle_mint_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_VSOCK:
		handle_mint_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_STORAGE:
		handle_mint_storage(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_DESTROY_STORAGE:
		handle_destroy_storage(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_SYSTEM:
		handle_mint_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CREATE_JAIL:
		handle_create_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CREATE_CHANNEL:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_channel(ra.reply_token);
		break;
	case AUTHORITY_OP_CREATE_COALITION:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_coalition(ra.reply_token);
		break;
	case AUTHORITY_OP_READY:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ready(ra.reply_token);
		break;
	case AUTHORITY_OP_PING:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ping(ra.reply_token);
		break;
	case AUTHORITY_OP_SET_AMBIENT_LOOKUP:
		/* Consumes recv_fd (installs or closes it). */
		handle_set_ambient_lookup(ra.payload_len, recv_fd,
		    ra.reply_token);
		recv_fd = -1;
		break;
	case AUTHORITY_OP_ENSURE_KMOD:
		handle_ensure_kmod(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_DELEGATE_SERVICE:
		handle_delegate_service(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_PATH:
		handle_claim_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_NET:
		handle_claim_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_JAIL:
		handle_claim_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_SYSTEM:
		handle_claim_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_VSOCK:
		handle_claim_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_PATH:
		handle_release_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_NET:
		handle_release_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_JAIL:
		handle_release_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_SYSTEM:
		handle_release_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_VSOCK:
		handle_release_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_LIFECYCLE:
		handle_lifecycle(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELOAD:
		handle_reload(&buf, ra.payload_len, ra.reply_token);
		break;
	default:
		syslog(LOG_WARNING, "authority_proto: unknown op %u", op);
		proto_reply(ENOTSUP, ra.reply_token, NULL, 0);
		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	dur = (uint64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
	    (uint64_t)(ts_end.tv_nsec - ts_start.tv_nsec);
	AUTHORITYD_PROBE_IPC_DISPATCH_DONE(op, dispatch_status, dur);
	}

	/* Close any descriptor an op did not consume (only §21 sends one). */
	if (recv_fd >= 0)
		(void)close(recv_fd);

	return (0);
}

/*
 * Called from the event loop when EVFILT_READ fires on the channel fd.
 * Processes one message per call; kqueue re-fires if more are queued.
 */
int
authority_proto_dispatch(void)
{

	return (proto_dispatch_one());
}

/*
 * Initialize the protocol handler.
 * channel_fd is authorityd's end of the channel to serviced.
 */
void
authority_proto_init(int channel_fd)
{
	unsigned char random[16];
	unsigned i;

	proto_channel_fd = channel_fd;
	serviced_ready = false;
	nonce_set = false;
	arc4random_buf(random, sizeof(random));
	for (i = 0; i < nitems(random); i++)
		(void)snprintf(authority_storage_session + i * 2, 3, "%02x",
		    random[i]);
	authority_storage_session[32] = '\0';
	authority_storage_session_ready = false;
}

/*
 * Reset state when serviced exits (before restart).
 */
void
authority_proto_reset(void)
{

	/* The caller already closed the fd; prevent stale ioctl use. */
	proto_channel_fd = -1;
	sweep_dynamic_claims();
	serviced_ready = false;
	nonce_set = false;
	authority_storage_session_ready = false;
}

bool
authority_proto_is_ready(void)
{

	return (serviced_ready);
}

int
authority_proto_fd(void)
{

	return (proto_channel_fd);
}
