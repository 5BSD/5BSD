/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * NS0: SwitchBoard and libservice pins on dev, written before the
 * nested-supervisor slices (nested-supervisors.md rev 1.3, section 9) give
 * a program subsets of its own.  Each case pins real behaviour of dev and
 * passes there:
 *
 *   NR2 lookup_channel_refuses_claim  outside a unit, the provider API
 *	fails before any wire operation (service_provider_create EBADF),
 *	and SVC_OP_NAME_CLAIM on a lookup channel answers ENOTSUP
 *	(domain.c lookup_channel_request), leaving the channel usable.
 *   NR5 provider_drops_flagged_new_client  a libservice provider drops a
 *	SVC_OP_NEW_CLIENT notice whose flags are not 0, closing its
 *	descriptor, and accepts the next one (libservice.c
 *	service_control_event).  A stand-in SwitchBoard drives it.
 *   NR7 relay_as_self_zero_hops  the end a lookup returns for a name its
 *	provider did not mark sendable arrives CAP_XFER_NONE: the caller
 *	cannot pass it on at all.  This is the anonymous half; the half
 *	where the requester is a unit holding software authority, whose end
 *	is also bound to that authority, is subset_stack_test.
 *   NR9 route_grants_nothing  a parent with no software authority installs
 *	a SwitchBoard route it obtained in its child: the child reaches the
 *	public names, and an endpoint with `requires` (and SwitchBoard's own
 *	control name) answers ENOENT, while approved software using the same
 *	route reaches its gated endpoint.
 *
 * NR2's lookup half, NR7 and NR9 need SwitchBoard's system route (Capsule
 * as PID 1) and skip elsewhere with DEFERRED_PLANEON_TIER; NR5 runs on
 * every tier.  Every wait is on an event: a child's exit, a pipe's end of
 * file, or a message on a channel (MAC_CAPABILITY_RECV_F_WAIT).
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <libservice.h>
#include <libservice_session.h>
#include <service_bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <switchboard_svc_proto.h>

#define	NA	(-9999)		/* a step that was not reached */
#define	ERRNO_OF(rv)	((rv) == -1 ? errno : 0)

#define	ROW(what, got, want) do {					\
	int got_ = (int)(got), want_ = (int)(want);			\
	ATF_CHECK_EQ_MSG(want_, got_, "%s: got %d (%s), pinned %d (%s)",	\
	    (what), got_, got_ > 0 ? strerror(got_) : "-", want_,	\
	    want_ > 0 ? strerror(want_) : "-");				\
} while (0)

/*
 * Run fn in a child and copy its result back over a pipe.  The parent's
 * read ends at the child's write or its exit, whichever comes first.
 */
static void
run_child(void (*fn)(const void *, void *), const void *arg, void *result,
    size_t size)
{
	ssize_t n;
	size_t got;
	pid_t pid;
	int p[2], status;

	ATF_REQUIRE(pipe2(p, O_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		(void)close(p[0]);
		fn(arg, result);
		_exit(write(p[1], result, size) == (ssize_t)size ? 0 : 70);
	}
	(void)close(p[1]);
	for (got = 0; got < size; got += (size_t)n) {
		n = read(p[0], (char *)result + got, size - got);
		if (n <= 0)
			break;
	}
	(void)close(p[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x", status);
	ATF_REQUIRE_EQ_MSG(size, got, "child reported %zu of %zu bytes", got,
	    size);
}

/*
 * The cases that talk to the system SwitchBoard need Capsule as PID 1 and
 * the route it gave this test.  Elsewhere (plane off, the stack tier) they
 * skip as DEFERRED_PLANEON_TIER, as tests/sys/dq does.
 */
static void
require_plane(void)
{
	char plane[KENV_MVALLEN + 1];
	struct mac_cap_process_info info;
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 1 };

	len = sizeof(kp);
	ATF_REQUIRE_MSG(sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == 0,
	    "kern.proc.pid.1: %s", strerror(errno));
	if (strcmp(kp.ki_comm, "capsule") != 0) {
		if (kenv(KENV_GET, "capability_plane", plane,
		    sizeof(plane)) > 0 && (strcasecmp(plane, "NO") == 0 ||
		    strcmp(plane, "0") == 0))
			atf_tc_skip("DEFERRED_PLANEON_TIER: needs Capsule as "
			    "PID 1 and SwitchBoard's route; this boot has "
			    "capability_plane=%s (PID 1 is %s)", plane,
			    kp.ki_comm);
		atf_tc_fail("the capability plane is off: PID 1 is %s, not "
		    "capsule", kp.ki_comm);
	}
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_MSG(cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info) == 0,
	    "MAC_CAP_PROCESS_INFO: %s", strerror(errno));
	ATF_REQUIRE_MSG(info.present == 1, "the test program was started "
	    "without SwitchBoard's route although the plane is on");
}

/* Receive one message on `fd`, waiting for it with no limit. */
static int
recv_wait(int fd, void *buf, size_t len, int *fds, uint32_t nfds,
    struct mac_capability_recvmsg_args *out)
{
	struct mac_capability_recvmsg_args ra;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = len;
	ra.fds = fds;
	ra.nfds = nfds;
	ra.flags = MAC_CAPABILITY_RECV_F_WAIT;
	ra._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1)
		return (errno);
	/* A peer that closed is reported as an empty message. */
	if (ra.payload_len == 0 && ra.nfds == 0)
		return (ECONNRESET);
	if (out != NULL)
		*out = ra;
	return (0);
}

static int
send_msg(int fd, const void *buf, size_t len, const int *fds, uint32_t nfds,
    uint64_t token)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = buf;
	sa.payload_len = len;
	sa.fds = fds;
	sa.nfds = nfds;
	sa.reply_token = token;
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa)));
}

/* One request on a private lookup channel and the status it answers. */
#define	NR2_TOKEN	0x4e5232u

static int
lookup_channel_call(int chan, const void *req, size_t len, int *status)
{
	struct mac_capability_recvmsg_args ra;
	struct svc_reply reply;
	int error, fd;

	error = send_msg(chan, req, len, NULL, 0, NR2_TOKEN);
	if (error != 0)
		return (error);
	fd = -1;
	memset(&reply, 0, sizeof(reply));
	error = recv_wait(chan, &reply, sizeof(reply), &fd, 1, &ra);
	if (fd >= 0)
		(void)close(fd);
	if (error != 0)
		return (error);
	if (ra.reply_token != NR2_TOKEN || ra.payload_len != sizeof(reply))
		return (EBADMSG);
	*status = reply.status;
	return (0);
}

struct nr2_res {
	int	create, create_out_null, expose_null;
};

static void
nr2_provider_rows(const void *arg __unused, void *resp)
{
	struct service_listener *listener;
	struct service_provider *provider;
	struct nr2_res *r = resp;

	/* A program SwitchBoard did not launch: no bootstrap at all. */
	(void)unsetenv(SERVICE_BOOTSTRAP_ENV);
	(void)close(SERVICE_BOOTSTRAP_FD);
	provider = NULL;
	r->create = ERRNO_OF(service_provider_create(&provider));
	r->create_out_null = provider == NULL;
	listener = NULL;
	r->expose_null = ERRNO_OF(service_provider_expose(provider,
	    "org.test.nr2.claim", &listener));
}

ATF_TC(lookup_channel_refuses_claim);
ATF_TC_HEAD(lookup_channel_refuses_claim, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR2: a program that is not a unit "
	    "cannot serve a name on dev.  libservice's provider API fails "
	    "before it sends anything (service_provider_create: EBADF, no "
	    "bootstrap; service_provider_expose then has no provider: "
	    "EINVAL), and SVC_OP_NAME_CLAIM sent on a lookup channel, plain "
	    "or sendable, answers ENOTSUP while the channel keeps serving "
	    "lookups.  NS3's line claim must not change this outside a "
	    "subset");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lookup_channel_refuses_claim, tc)
{
	struct svc_name_claim_req claim;
	struct svc_lookup_req lookup;
	struct nr2_res r;
	int chan, status;

	memset(&r, 0, sizeof(r));
	run_child(nr2_provider_rows, NULL, &r, sizeof(r));
	ROW("service_provider_create outside a unit", r.create, EBADF);
	ROW("no provider returned", r.create_out_null, 1);
	ROW("service_provider_expose without a provider", r.expose_null,
	    EINVAL);

	require_plane();
	chan = service_ambient_lookup_channel();
	ATF_REQUIRE_MSG(chan >= 0, "private lookup channel: %s",
	    strerror(errno));

	memset(&claim, 0, sizeof(claim));
	claim.op = SVC_OP_NAME_CLAIM;
	strlcpy(claim.name, "org.test.nr2.claim", sizeof(claim.name));
	status = NA;
	ROW("NAME_CLAIM exchange", lookup_channel_call(chan, &claim,
	    sizeof(claim), &status), 0);
	ROW("NAME_CLAIM on a lookup channel", status, ENOTSUP);

	claim.flags = SVC_NAME_CLAIM_SENDABLE;
	status = NA;
	ROW("sendable NAME_CLAIM exchange", lookup_channel_call(chan, &claim,
	    sizeof(claim), &status), 0);
	ROW("sendable NAME_CLAIM on a lookup channel", status, ENOTSUP);

	/* The refusal leaves the channel serving lookups. */
	memset(&lookup, 0, sizeof(lookup));
	lookup.op = SVC_OP_LOOKUP;
	strlcpy(lookup.name, "system.Notify", sizeof(lookup.name));
	status = NA;
	ROW("LOOKUP exchange after the refusals", lookup_channel_call(chan,
	    &lookup, sizeof(lookup), &status), 0);
	ROW("LOOKUP system.Notify after the refusals", status, 0);
	(void)close(chan);
}

/*
 * NR5.  A stand-in SwitchBoard on the provider's descriptor 3.  It answers
 * the claim, activates the name, then sends two NEW_CLIENT notices that
 * differ only in `flags`: 1, then 0.
 */
#define	NR5_NAME		"org.test.nr5.provider"
#define	NR5_FLAGGED		"org.test.nr5.flagged"
#define	NR5_VALID		"org.test.nr5.valid"

struct nr5_report {
	int	create, expose, accept;
	char	service_name[SWITCHBOARD_NAME_MAX + 1];
	char	client_label[64];
};

static int
install_bootstrap(void)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(sizeof(struct service_bootstrap));
	struct service_bootstrap bootstrap;
	cap_rights_t rights;
	int fd;

	memset(&bootstrap, 0, sizeof(bootstrap));
	bootstrap.magic = SERVICE_BOOTSTRAP_MAGIC;
	bootstrap.header_size = offsetof(struct service_bootstrap, label);
	bootstrap.total_size = sizeof(bootstrap);
	bootstrap.channel_fd = 3;
	bootstrap.capprotect_fd = -1;
	strlcpy(bootstrap.label, "org.test.nr5", sizeof(bootstrap.label));
	options.eco_flags = ENVFD_WRITE_ONCE;
	fd = envfd_create(SERVICE_BOOTSTRAP_ENVFD_NAME, &options);
	if (fd == -1 ||
	    write(fd, &bootstrap, sizeof(bootstrap)) != sizeof(bootstrap))
		return (-1);
	if (fd != SERVICE_BOOTSTRAP_FD) {
		if (dup2(fd, SERVICE_BOOTSTRAP_FD) != SERVICE_BOOTSTRAP_FD)
			return (-1);
		(void)close(fd);
	}
	/* SwitchBoard's immutable bootstrap descriptor contract. */
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(SERVICE_BOOTSTRAP_FD, &rights) == -1 ||
	    cap_ioctls_limit(SERVICE_BOOTSTRAP_FD,
	    (const unsigned long[]){ ENVFD_GETINFO }, 1) == -1)
		return (-1);
	return (setenv(SERVICE_BOOTSTRAP_ENV, "5", 1));
}

/*
 * The provider: expose the name and accept one client.  It reports what
 * it accepted, then stays alive until the test closes `done`, so that the
 * ends it holds are closed by libservice's choice, not by its exit.
 */
static void __dead2
nr5_provider(int control, int report_fd, int done)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct nr5_report rep;
	char byte;
	int session;

	memset(&rep, 0, sizeof(rep));
	rep.expose = rep.accept = NA;
	/* Keep the test's descriptors clear of 3 and 5, the unit's slots. */
	report_fd = fcntl(report_fd, F_DUPFD_CLOEXEC, 10);
	done = fcntl(done, F_DUPFD_CLOEXEC, 10);
	control = fcntl(control, F_DUPFD_CLOEXEC, 10);
	if (report_fd == -1 || done == -1 || control == -1 ||
	    dup2(control, 3) != 3 || install_bootstrap() == -1)
		_exit(71);
	rep.create = ERRNO_OF(service_provider_create(&provider));
	if (rep.create == 0)
		rep.expose = ERRNO_OF(service_provider_expose(provider,
		    NR5_NAME, &listener));
	if (rep.expose == 0) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		rep.accept = ERRNO_OF(service_listener_accept(listener,
		    &identity, &session));
		strlcpy(rep.service_name, identity.service_name,
		    sizeof(rep.service_name));
		strlcpy(rep.client_label, identity.client_label,
		    sizeof(rep.client_label));
	}
	if (write(report_fd, &rep, sizeof(rep)) != sizeof(rep))
		_exit(72);
	(void)read(done, &byte, sizeof(byte));
	_exit(0);
}

static void
new_client_msg(struct svc_new_client_msg *n, uint32_t flags,
    const char *label)
{

	memset(n, 0, sizeof(*n));
	n->op = SVC_OP_NEW_CLIENT;
	n->flags = flags;
	strlcpy(n->service_name, NR5_NAME, sizeof(n->service_name));
	strlcpy(n->client_label, label, sizeof(n->client_label));
	n->rights = UINT64_MAX;
	strlcpy(n->resource_owner, "org.test.nr5.owner",
	    sizeof(n->resource_owner));
	n->generation[0] = 1;
}

ATF_TC(provider_drops_flagged_new_client);
ATF_TC_HEAD(provider_drops_flagged_new_client, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR5: a libservice provider drops a "
	    "SVC_OP_NEW_CLIENT notice whose flags are not 0 (the fixed "
	    "760-byte layout has no extension field a subset could use): "
	    "of two notices that differ only in flags, 1 then 0, it accepts "
	    "the second, and the session end the first carried is closed, "
	    "not queued");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(provider_drops_flagged_new_client, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct svc_name_claim_req claim;
	struct svc_name_result_req result;
	struct svc_activate_name_msg activate;
	struct svc_new_client_msg notice;
	struct svc_reply ok;
	struct nr5_report rep;
	char byte;
	ssize_t n;
	pid_t pid;
	int ctl[2], report[2], done[2], flagged[2], valid[2], status;

	ATF_REQUIRE_MSG(mac_capability_channel_create(ctl) == 0,
	    "mac_capability_channel_create: %s", strerror(errno));
	ATF_REQUIRE(pipe2(report, O_CLOEXEC) == 0);
	ATF_REQUIRE(pipe2(done, O_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		(void)close(ctl[1]);
		(void)close(report[0]);
		(void)close(done[1]);
		nr5_provider(ctl[0], report[1], done[0]);
	}
	(void)close(ctl[0]);
	(void)close(report[1]);
	(void)close(done[0]);

	/* The provider claims the name. */
	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(0, recv_wait(ctl[1], &claim, sizeof(claim), NULL, 0,
	    &ra));
	ROW("first request is NAME_CLAIM", claim.op, SVC_OP_NAME_CLAIM);
	ATF_CHECK_STREQ(NR5_NAME, claim.name);
	memset(&ok, 0, sizeof(ok));
	ATF_REQUIRE_EQ(0, send_msg(ctl[1], &ok, sizeof(ok), NULL, 0,
	    ra.reply_token));

	/* Activate it; the provider reports the name's result. */
	memset(&activate, 0, sizeof(activate));
	activate.op = SVC_OP_ACTIVATE_NAME;
	strlcpy(activate.name, NR5_NAME, sizeof(activate.name));
	ATF_REQUIRE_EQ(0, send_msg(ctl[1], &activate, sizeof(activate), NULL,
	    0, 0));
	memset(&result, 0, sizeof(result));
	ATF_REQUIRE_EQ(0, recv_wait(ctl[1], &result, sizeof(result), NULL, 0,
	    &ra));
	ROW("second request is NAME_RESULT", result.op, SVC_OP_NAME_RESULT);
	ROW("activation result", result.status, 0);
	ATF_REQUIRE_EQ(0, send_msg(ctl[1], &ok, sizeof(ok), NULL, 0,
	    ra.reply_token));

	/* Two notices, the flagged one first. */
	ATF_REQUIRE(mac_capability_channel_create(flagged) == 0);
	ATF_REQUIRE(mac_capability_channel_create(valid) == 0);
	new_client_msg(&notice, 1, NR5_FLAGGED);
	ROW("send the flagged NEW_CLIENT", send_msg(ctl[1], &notice,
	    sizeof(notice), &flagged[0], 1, 0), 0);
	new_client_msg(&notice, 0, NR5_VALID);
	ROW("send the valid NEW_CLIENT", send_msg(ctl[1], &notice,
	    sizeof(notice), &valid[0], 1, 0), 0);
	(void)close(flagged[0]);
	(void)close(valid[0]);

	memset(&rep, 0, sizeof(rep));
	n = read(report[0], &rep, sizeof(rep));
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(rep), n, "provider report: %zd",
	    n);
	printf("provider: create %d expose %d accept %d: %s from %s\n",
	    rep.create, rep.expose, rep.accept, rep.service_name,
	    rep.client_label);
	ROW("service_provider_create", rep.create, 0);
	ROW("service_provider_expose", rep.expose, 0);
	ROW("service_listener_accept", rep.accept, 0);
	ATF_CHECK_STREQ(NR5_NAME, rep.service_name);
	ATF_CHECK_STREQ_MSG(NR5_VALID, rep.client_label, "the provider "
	    "accepted %s", rep.client_label);
	/*
	 * libservice handles notices in order on one dispatch thread, so the
	 * flagged notice was dealt with before the valid one was queued: its
	 * end is already closed while the provider still runs.
	 */
	ROW("the flagged notice's end was closed by the provider",
	    recv_wait(flagged[1], &byte, sizeof(byte), NULL, 0, NULL),
	    ECONNRESET);

	(void)close(done[1]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "provider status %#x", status);
	(void)close(flagged[1]);
	(void)close(valid[1]);
	(void)close(report[0]);
	(void)close(ctl[1]);
}

/*
 * NR7, anonymous half.  The test program looks up a public name over its
 * route.  No base provider marks a name sendable, so SwitchBoard limits the
 * end to CAP_XFER_ONCE and its own delivery spends that (fdxfer_source_locked
 * in kern_descrip.c): the end arrives CAP_XFER_NONE.
 */
struct nr7_res {
	int	open, xfer_once, xfer_none, scm_send, chan_send;
	int	auth_valid, child_getinfo;
};

static int
scm_send(int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))], byte = 'x';
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int error, sp[2];

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == -1)
		return (errno);
	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	error = ERRNO_OF(sendmsg(sp[0], &msg, 0));
	(void)close(sp[0]);
	(void)close(sp[1]);
	return (error);
}

static int
getinfo(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	return (ERRNO_OF(ioctl(fd, MAC_CAPABILITY_GETINFO, &info)));
}

static void
nr7_rows(const void *arg __unused, void *resp)
{
	struct cap_authority_info auth;
	struct nr7_res *r = resp;
	pid_t pid;
	int fd, pair[2], p[2], v;

	r->xfer_once = r->xfer_none = r->scm_send = r->chan_send = NA;
	r->child_getinfo = NA;
	/* An anonymous requester, whatever the test inherited. */
	(void)cap_process(CAP_AUTH_CLEAR, -1, 0, NULL);
	memset(&auth, 0, sizeof(auth));
	r->auth_valid = cap_process(CAP_AUTH_INFO, -1, 0, &auth) == 0 ?
	    (int)auth.valid : -1;
	fd = -1;
	r->open = ERRNO_OF(service_open("system.Notify", &fd));
	if (fd < 0)
		return;
	/* NONE only tightens to NONE; ONCE could still be set to ONCE. */
	r->xfer_once = ERRNO_OF(cap_xfer_limit(fd, CAP_XFER_ONCE));
	r->xfer_none = ERRNO_OF(cap_xfer_limit(fd, CAP_XFER_NONE));
	r->scm_send = scm_send(fd);
	if (mac_capability_channel_create(pair) == 0) {
		r->chan_send = send_msg(pair[0], "x", 1, &fd, 1, 0);
		(void)close(pair[0]);
		(void)close(pair[1]);
	}
	/* Not bound: a process without software authority may use it. */
	if (pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		(void)cap_process(CAP_AUTH_CLEAR, -1, 0, NULL);
		v = getinfo(fd);
		_exit(write(p[1], &v, sizeof(v)) == sizeof(v) ? 0 : 70);
	}
	(void)close(p[1]);
	if (pid > 0 && read(p[0], &v, sizeof(v)) == sizeof(v))
		r->child_getinfo = v;
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, NULL, 0);
	(void)close(fd);
}

ATF_TC(relay_as_self_zero_hops);
ATF_TC_HEAD(relay_as_self_zero_hops, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR7, anonymous requester: the end "
	    "service_open returns for a name its provider did not mark "
	    "sendable (system.Notify) is CAP_XFER_NONE in the requester: "
	    "cap_xfer_limit can only keep it NONE, and passing it on by "
	    "SCM_RIGHTS or on a channel fails ENOTCAPABLE.  A requester "
	    "without software authority gets an end bound to nothing.  "
	    "Relaying as oneself therefore fails at zero hops; the unit "
	    "half is subset_stack_test:relay_as_self_zero_hops_unit");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(relay_as_self_zero_hops, tc)
{
	struct nr7_res r;

	require_plane();
	memset(&r, 0, sizeof(r));
	run_child(nr7_rows, NULL, &r, sizeof(r));
	printf("authority valid %d; open %d; xfer ONCE %d NONE %d; "
	    "SCM_RIGHTS %d channel %d; child without authority GETINFO %d\n",
	    r.auth_valid, r.open, r.xfer_once, r.xfer_none, r.scm_send,
	    r.chan_send, r.child_getinfo);
	ROW("requester holds no software authority", r.auth_valid, 0);
	ROW("service_open(system.Notify)", r.open, 0);
	ROW("cap_xfer_limit(ONCE) on the received end", r.xfer_once,
	    ENOTCAPABLE);
	ROW("cap_xfer_limit(NONE) on the received end", r.xfer_none, 0);
	ROW("SCM_RIGHTS send of the received end", r.scm_send, ENOTCAPABLE);
	ROW("channel send of the received end", r.chan_send, ENOTCAPABLE);
	ROW("GETINFO from a child without authority", r.child_getinfo, 0);
}

/*
 * NR9.  The parent clears whatever software authority it inherited and
 * shows it holds none, takes the route it holds (GET) and installs that
 * very descriptor as the route of a child that first cleared its own.
 */
#define	NR9_NAMES	4
static const char *const nr9_names[NR9_NAMES] = {
	"system.Notify",	/* public */
	"system.Sysctl",	/* public */
	"system.Network.Admin",	/* requires system.network.admin */
	"system.switchboard",	/* SwitchBoard's own control name */
};
static const int nr9_want[NR9_NAMES] = { 0, 0, ENOENT, ENOENT };

struct nr9_res {
	int		parent_clear, parent_valid, parent_get;
	int		child_clear, child_set, child_present, child_valid;
	uint64_t	parent_generation, child_generation;
	int		open[NR9_NAMES];
	int		approved_status;
};

static void
nr9_rows(const void *arg __unused, void *resp)
{
	struct cap_authority_info auth;
	struct mac_cap_process_info info;
	struct nr9_res *r = resp;
	pid_t pid;
	int fd, i, p[2], route, s;

	memset(r, 0, sizeof(*r));
	r->parent_get = r->child_clear = r->child_set = NA;
	r->child_present = r->child_valid = NA;
	r->approved_status = -1;
	for (i = 0; i < NR9_NAMES; i++)
		r->open[i] = NA;
	r->parent_clear = ERRNO_OF(cap_process(CAP_AUTH_CLEAR, -1, 0, NULL));
	memset(&auth, 0, sizeof(auth));
	r->parent_valid = cap_process(CAP_AUTH_INFO, -1, 0, &auth) == 0 ?
	    (int)auth.valid : -1;
	memset(&info, 0, sizeof(info));
	(void)cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info);
	r->parent_generation = info.generation;
	route = cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL);
	r->parent_get = ERRNO_OF(route);
	if (route < 0 || pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		struct nr9_res c;

		memcpy(&c, r, sizeof(c));
		c.child_clear = ERRNO_OF(cap_process(MAC_CAP_PROCESS_CLEAR,
		    -1, 0, NULL));
		c.child_set = ERRNO_OF(cap_process(MAC_CAP_PROCESS_SET, route,
		    getuid(), NULL));
		(void)close(route);
		memset(&info, 0, sizeof(info));
		(void)cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info);
		c.child_present = (int)info.present;
		c.child_generation = info.generation;
		memset(&auth, 0, sizeof(auth));
		c.child_valid = cap_process(CAP_AUTH_INFO, -1, 0, &auth) == 0 ?
		    (int)auth.valid : -1;
		for (i = 0; i < NR9_NAMES; i++) {
			fd = -1;
			c.open[i] = ERRNO_OF(service_open(nr9_names[i], &fd));
			if (fd >= 0)
				(void)close(fd);
		}
		/* Approved software through the same installed route. */
		pid = fork();
		if (pid == 0) {
			fd = open("/dev/null", O_WRONLY);
			if (fd >= 0) {
				(void)dup2(fd, STDOUT_FILENO);
				(void)dup2(fd, STDERR_FILENO);
			}
			execl("/usr/sbin/networkcmpctl", "networkcmpctl",
			    "info", (char *)NULL);
			_exit(127);
		}
		if (pid > 0 && waitpid(pid, &s, 0) == pid)
			c.approved_status = s;
		_exit(write(p[1], &c, sizeof(c)) == sizeof(c) ? 0 : 70);
	}
	(void)close(p[1]);
	(void)close(route);
	if (pid > 0 && read(p[0], r, sizeof(*r)) != sizeof(*r))
		r->child_set = NA;
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, NULL, 0);
}

ATF_TC(route_grants_nothing);
ATF_TC_HEAD(route_grants_nothing, tc)
{
	atf_tc_set_md_var(tc, "descr", "NR9: a parent that holds no "
	    "software authority (CAP_AUTH_INFO valid 0) installs the "
	    "SwitchBoard route it holds in its child.  The child, an "
	    "anonymous caller (authority.c svc_authority_resolve), reaches "
	    "the public system.Notify and system.Sysctl, and gets ENOENT "
	    "for system.Network.Admin, whose endpoint requires "
	    "system.network.admin, and for system.switchboard; "
	    "networkcmpctl, approved software, reaches its gated endpoint "
	    "through the same route.  The route grants nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "/usr/sbin/networkcmpctl");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(route_grants_nothing, tc)
{
	struct nr9_res r;
	int i;

	require_plane();
	run_child(nr9_rows, NULL, &r, sizeof(r));
	printf("parent: clear %d valid %d GET %d gen %ju; child: CLEAR %d "
	    "SET %d present %d gen %ju valid %d; networkcmpctl %#x\n",
	    r.parent_clear, r.parent_valid, r.parent_get,
	    (uintmax_t)r.parent_generation, r.child_clear, r.child_set,
	    r.child_present, (uintmax_t)r.child_generation, r.child_valid,
	    r.approved_status);
	ROW("parent CAP_AUTH_CLEAR", r.parent_clear, 0);
	ROW("parent holds no software authority", r.parent_valid, 0);
	ROW("parent GET of its SwitchBoard route", r.parent_get, 0);
	ROW("child CLEAR", r.child_clear, 0);
	ROW("child SET of the parent's route", r.child_set, 0);
	ROW("child route present", r.child_present, 1);
	ROW("child holds no software authority", r.child_valid, 0);
	for (i = 0; i < NR9_NAMES; i++) {
		printf("  %s: %d\n", nr9_names[i], r.open[i]);
		ATF_CHECK_EQ_MSG(nr9_want[i], r.open[i], "service_open(%s): "
		    "got %d (%s), pinned %d", nr9_names[i], r.open[i],
		    r.open[i] > 0 ? strerror(r.open[i]) : "-", nr9_want[i]);
	}
	ATF_CHECK_MSG(WIFEXITED(r.approved_status) &&
	    WEXITSTATUS(r.approved_status) == 0, "networkcmpctl info through "
	    "the installed route: status %#x", r.approved_status);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, lookup_channel_refuses_claim);
	ATF_TP_ADD_TC(tp, provider_drops_flagged_new_client);
	ATF_TP_ADD_TC(tp, relay_as_self_zero_hops);
	ATF_TP_ADD_TC(tp, route_grants_nothing);
	return (atf_no_error());
}
