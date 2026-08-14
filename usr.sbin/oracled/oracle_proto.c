/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled channel protocol handler.
 *
 * Receives requests from serviced over the restricted channel,
 * validates them against the oracle's claimed resource set, and
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

#include "oracled.h"
#include "oracled_svc_proto.h"
#include "mac_capability_priv.h"
#include "probes.h"
#include "oracle_proto_claims.h"
#include "req_validate.h"

static int	proto_channel_fd = -1;
static bool	serviced_ready;
static uint64_t	serviced_nonce;		/* set on first message */
static bool	nonce_set;

/* Per-dispatch tracking for the ipc-dispatch-done probe. */
static uint32_t dispatch_op;
static int dispatch_status;

/*
 * Return an owned descriptor for an existing persistent jail only when its
 * immutable launch identity matches the requested definition.  Reusing a
 * name with different roots, hostnames, or an explicitly requested address
 * is a policy conflict, never an implicit update.
 */
static int
existing_jail_descriptor(const struct oracle_create_jail_req *req)
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
	struct oracle_reply rpl;
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
				    "oracle_proto: confine reply fd: %m");
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
		syslog(LOG_WARNING, "oracle_proto: reply: %m");
		return (-1);
	}
	dispatch_status = status;
	ORACLED_PROBE_IPC_REPLY(dispatch_op, status);
	return (0);
}

/*
 * Validate that a path is within the oracle's claimed set.
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
		const struct oracled_jail_claim *c = &od.cfg.claim_jail[i];

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
	const struct oracle_path_req *req;
	int err, token_fd;

	if (!validate_path_req(payload, len, &req, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_path(req->path, &err) != 0) {
		ORACLED_PROBE_MINT_PATH(req->path, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_path_token(req->path);
	if (token_fd == -1) {
		release_auto_claim_path(req->path);
		ORACLED_PROBE_MINT_PATH(req->path, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_PATH(req->path, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_file(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_file_req *req;
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
			ORACLED_PROBE_MINT_FILE(req->path, req->actions, err);
			proto_reply(err, reply_token, NULL, 0);
			return;
		}
	}

	token_fd = mac_capability_mint_file_token(req->path, req->actions);
	if (token_fd == -1) {
		release_auto_claim_path(req->path);
		ORACLED_PROBE_MINT_FILE(req->path, req->actions, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_FILE(req->path, req->actions, 0);
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
		ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max,
		    nc.protocol, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_net_token(&nc);
	if (token_fd == -1) {
		release_auto_claim_net(&nc);
		ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol,
		    EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct oracled_jail_claim jc;
	int err, token_fd;

	if (!validate_jail_req(payload, len, &jc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_jail(&jc, &err) != 0 &&
	    !jail_is_claimed(&jc)) {
		ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions,
		    err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_jail_token(&jc);
	if (token_fd == -1) {
		release_auto_claim_jail(&jc);
		ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_vsock(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_vsock_claim vc;
	int err, token_fd;
	if (!validate_vsock_req(payload, len, &vc, &err)) {
		ORACLED_PROBE_MINT_VSOCK(0, 0, 0, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	if (auto_claim_vsock(&vc, &err) != 0) {
		ORACLED_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	token_fd = mac_capability_mint_vsock_token(&vc);
	if (token_fd == -1) {
		release_auto_claim_vsock(&vc);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}
	ORACLED_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

/*
 * Mint a TrustedZFS dataset handle for the requested dataset and rights
 * and pass the handle fd back to the service.  oracled holds the /dev/zfs
 * privilege (it runs unsandboxed as the capability engine); the service
 * receives only the rights-limited descriptor.  The dataset must already
 * exist — serviced materializes ephemeral datasets before requesting.
 */
static void
handle_mint_storage(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_storage_req *req;
	struct zfs_dataset_open_args args;
	int devfd, handle_fd, serrno;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (memchr(req->dataset, '\0', sizeof(req->dataset)) == NULL ||
	    req->dataset[0] == '\0' ||
	    (req->rights & ~ZH_ALL_RIGHTS) != 0 ||
	    (req->flags & ~ZHF_SUBTREE) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	devfd = open("/dev/zfs", O_RDWR | O_CLOEXEC);
	if (devfd == -1) {
		proto_reply(errno, reply_token, NULL, 0);
		return;
	}
	memset(&args, 0, sizeof(args));
	strlcpy(args.zdo_name, req->dataset, sizeof(args.zdo_name));
	args.zdo_rights = req->rights;
	args.zdo_flags = req->flags;
	args.zdo_fd = -1;
	if (ioctl(devfd, ZFS_IOC_DATASET_OPEN, &args) == -1) {
		serrno = errno;
		close(devfd);
		proto_reply(serrno, reply_token, NULL, 0);
		return;
	}
	close(devfd);

	handle_fd = args.zdo_fd;
	proto_reply(0, reply_token, &handle_fd, 1);
	close(handle_fd);
}

static void
handle_create_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_create_jail_req *req;
	struct oracled_jail_claim jc;
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
			    "oracle_proto: create_jail: bad ip4_addr: %s",
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
		syslog(LOG_NOTICE, "oracle_proto: create_jail denied: %s",
		    req->name);
		proto_reply(err != 0 ? err : EACCES,
		    reply_token, NULL, 0);
		return;
	}

	/* Verify the jail path is under the claim's allowed root. */
	if (!jail_path_allowed(req->name, req->path)) {
		syslog(LOG_NOTICE,
		    "oracle_proto: create_jail path denied: %s path=%s",
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
		    "oracle_proto: reused persistent jail %s jd=%d",
		    req->name, jd);
		ORACLED_PROBE_CREATE_JAIL(req->name, 0);
		proto_reply(0, reply_token, &jd, 1);
		close(jd);
		release_auto_claim_jail(&jc);
		return;
	}
	if (errno != ENOENT) {
		int error;

		error = errno;
		syslog(LOG_NOTICE,
		    "oracle_proto: persistent jail %s conflicts with request: %s",
		    req->name, strerror(error));
		ORACLED_PROBE_CREATE_JAIL(req->name, error);
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
		syslog(LOG_ERR, "oracle_proto: jail_set(%s): %m", req->name);
		ORACLED_PROBE_CREATE_JAIL(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		release_auto_claim_jail(&jc);
		return;
	}

	syslog(LOG_INFO, "oracle_proto: created jail %s jd=%d", req->name, jd);
	ORACLED_PROBE_CREATE_JAIL(req->name, 0);
	proto_reply(0, reply_token, &jd, 1);
	close(jd);
	release_auto_claim_jail(&jc);
}

static void
handle_mint_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_system_req *req;
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
			ORACLED_PROBE_MINT_SYSTEM(req->gates, err);
			proto_reply(err, reply_token, NULL, 0);
			return;
		}
	}

	token_fd = mac_capability_mint_system_token(req->gates);
	if (token_fd == -1) {
		release_auto_claim_system(req->gates);
		ORACLED_PROBE_MINT_SYSTEM(req->gates, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_SYSTEM(req->gates, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_channel(uint64_t reply_token)
{
	int fds[2];

	if (mac_capability_create_channel(&fds[0], &fds[1]) == -1) {
		ORACLED_PROBE_CHANNEL_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_CHANNEL_CREATE(0);
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
		ORACLED_PROBE_COALITION_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_COALITION_CREATE(0);
	proto_reply(0, reply_token, &cfd, 1);
	close(cfd);
}

static void
handle_ready(uint64_t reply_token)
{

	if (!serviced_ready) {
		serviced_ready = true;
		syslog(LOG_INFO, "oracle_proto: serviced ready");
	}
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ping(uint64_t reply_token)
{

	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ensure_kmod(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_kmod_req *req;
	const uint32_t gates = SYS_GATE_KLDLOAD | SYS_GATE_KLDSTAT;
	int error, id;

	if (!validate_kmod_req(payload, len, &req, &error)) {
		ORACLED_PROBE_KMOD_ENSURE("", error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	if (auto_claim_system(gates, &error) != 0) {
		ORACLED_PROBE_KMOD_ENSURE(req->name, error);
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
		syslog(LOG_INFO, "oracle_proto: ensured kernel module %s",
		    req->name);
	else
		syslog(LOG_ERR, "oracle_proto: ensure kernel module %s: %s",
		    req->name, strerror(error));
	ORACLED_PROBE_KMOD_ENSURE(req->name, error);
	proto_reply(error, reply_token, NULL, 0);
}

static void
handle_delegate_service(const void *payload, uint32_t len,
    uint64_t reply_token)
{
	const struct oracle_service_req *req;
	int error, fd;

	if (!validate_service_req(payload, len, &req, &error)) {
		ORACLED_PROBE_SERVICE_DELEGATE("", error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	fd = mac_capability_connect_for_delegate(req->name);
	if (fd == -1) {
		error = errno;
		ORACLED_PROBE_SERVICE_DELEGATE(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	ORACLED_PROBE_SERVICE_DELEGATE(req->name, 0);
	proto_reply(0, reply_token, &fd, 1);
	close(fd);
}

/* Claim/release handlers and sweep are in oracle_proto_claims.c. */

/*
 * Dispatch a single request from the channel.
 * Returns 0 if message processed, -1 on receive error (peer closed).
 */
static int
proto_dispatch_one(void)
{
	struct mac_capability_recvmsg_args ra;
	union {
		struct oracle_create_jail_req create_jail;
		struct oracle_mint_file_req file;
		struct oracle_path_req path;
		struct oracle_net_req net;
		struct oracle_jail_req jail;
		struct oracle_vsock_req vsock;
		struct oracle_system_req system;
		struct oracle_kmod_req kmod;
		struct oracle_service_req service;
		struct oracle_req_hdr hdr;
	} buf;
	uint32_t op;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &buf;
	ra.payload_len = sizeof(buf);

	if (ioctl(proto_channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN)
			return (0);
		syslog(LOG_WARNING, "oracle_proto: recvmsg: %m");
		return (-1);
	}

	if (ra.payload_len < sizeof(uint32_t)) {
		syslog(LOG_WARNING, "oracle_proto: short message (%u bytes)",
		    ra.payload_len);
		return (0);
	}

	/* Nonce verification — lock to first sender. */
	if (!nonce_set) {
		serviced_nonce = ra.trailer.nonce;
		nonce_set = true;
	} else if (ra.trailer.nonce != serviced_nonce) {
		syslog(LOG_WARNING,
		    "oracle_proto: nonce mismatch (got 0x%jx, expected 0x%jx)",
		    (uintmax_t)ra.trailer.nonce,
		    (uintmax_t)serviced_nonce);
		proto_reply(EACCES, ra.reply_token, NULL, 0);
		return (0);
	}

	memcpy(&op, &buf, sizeof(op));
	dispatch_op = op;
	dispatch_status = 0;
	ORACLED_PROBE_IPC_RECV(op);

	{
	struct timespec ts_start, ts_end;
	uint64_t dur;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	switch (op) {
	case ORACLE_OP_MINT_PATH:
		handle_mint_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_FILE:
		handle_mint_file(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_NET:
		handle_mint_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_JAIL:
		handle_mint_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_VSOCK:
		handle_mint_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_STORAGE:
		handle_mint_storage(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_SYSTEM:
		handle_mint_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CREATE_JAIL:
		handle_create_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CREATE_CHANNEL:
		if (ra.payload_len != sizeof(struct oracle_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_channel(ra.reply_token);
		break;
	case ORACLE_OP_CREATE_COALITION:
		if (ra.payload_len != sizeof(struct oracle_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_coalition(ra.reply_token);
		break;
	case ORACLE_OP_READY:
		if (ra.payload_len != sizeof(struct oracle_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ready(ra.reply_token);
		break;
	case ORACLE_OP_PING:
		if (ra.payload_len != sizeof(struct oracle_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ping(ra.reply_token);
		break;
	case ORACLE_OP_ENSURE_KMOD:
		handle_ensure_kmod(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_DELEGATE_SERVICE:
		handle_delegate_service(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CLAIM_PATH:
		handle_claim_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CLAIM_NET:
		handle_claim_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CLAIM_JAIL:
		handle_claim_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CLAIM_SYSTEM:
		handle_claim_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CLAIM_VSOCK:
		handle_claim_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_RELEASE_PATH:
		handle_release_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_RELEASE_NET:
		handle_release_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_RELEASE_JAIL:
		handle_release_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_RELEASE_SYSTEM:
		handle_release_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_RELEASE_VSOCK:
		handle_release_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	default:
		syslog(LOG_WARNING, "oracle_proto: unknown op %u", op);
		proto_reply(ENOTSUP, ra.reply_token, NULL, 0);
		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	dur = (uint64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
	    (uint64_t)(ts_end.tv_nsec - ts_start.tv_nsec);
	ORACLED_PROBE_IPC_DISPATCH_DONE(op, dispatch_status, dur);
	}

	return (0);
}

/*
 * Called from the event loop when EVFILT_READ fires on the channel fd.
 * Processes one message per call; kqueue re-fires if more are queued.
 */
int
oracle_proto_dispatch(void)
{

	return (proto_dispatch_one());
}

/*
 * Initialize the protocol handler.
 * channel_fd is oracled's end of the channel to serviced.
 */
void
oracle_proto_init(int channel_fd)
{

	proto_channel_fd = channel_fd;
	serviced_ready = false;
	nonce_set = false;
}

/*
 * Reset state when serviced exits (before restart).
 */
void
oracle_proto_reset(void)
{

	/* The caller already closed the fd; prevent stale ioctl use. */
	proto_channel_fd = -1;
	sweep_dynamic_claims();
	serviced_ready = false;
	nonce_set = false;
}

bool
oracle_proto_is_ready(void)
{

	return (serviced_ready);
}

int
oracle_proto_fd(void)
{

	return (proto_channel_fd);
}
