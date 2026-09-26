/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * IPC anointments, v1 (docs/book/src/plane/anointments.md): the set
 * representation, the endpoint match, the session-set plumbing on minted
 * channels, the on-demand pre-check, the refusal audit record, and the nonce
 * and ABI identity in the NEW_CLIENT grant.  Rows of the design's acceptance
 * matrix (S*, U*, P*) are cited where a case is that row.
 *
 * The pure-logic cases run anywhere: mac_cap_create_channel() is stubbed to a
 * socketpair when no channel device is wanted, and the provider under test is
 * registered sendable so the resolve path never touches cap_xfer_limit().  The
 * end-to-end cases that mint a real session channel and drive a lookup over it
 * with libservice need root and the mac_capability channel device, and skip
 * cleanly without it.
 *
 * The implementation is included directly (anoint.c, domain.c, naming.c), the
 * same trick as domain_test.c, so private state (the lookup-channel registry)
 * can be inspected and the collaborators stubbed.  USE_BSM_AUDIT is defined
 * for this unit so the refusal path calls switchboard_audit(), stubbed below
 * to capture the record.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "service_bootstrap.h"
#include "switchboard_ctl.h"

#include "../anoint.c"
#include "../domain.c"
#include "../naming.c"

struct switchboard_state sd;
int switchboard_kq = -1;

/* ------------------------------------------------------------------ */
/* Stubs for collaborators owned by other translation units.           */
/* ------------------------------------------------------------------ */

int
svc_lifecycle_client(struct svc_runtime *svc __unused,
    struct svc_runtime *provider __unused,
    struct svc_new_client_msg *msg __unused)
{
	return (0);
}

int
switchboard_fd_budget_check(size_t count, const char *what)
{

	(void)count;
	(void)what;
	return (0);
}

int
sctl_adopt_channel(int provider_fd, uint64_t rights, uid_t uid,
    bool capsule_relay)
{

	(void)rights;
	(void)uid;
	(void)capsule_relay;
	if (provider_fd >= 0)
		(void)close(provider_fd);
	return (0);
}

int
bundle_registry_ensure_user_dir(uid_t uid)
{

	(void)uid;
	return (0);
}

int
on_demand_launch_ambient(const char *name, struct svc_lookup_channel *lc,
    const struct svc_domain *domain, struct channel_message *request, int kq)
{

	(void)name;
	(void)lc;
	(void)domain;
	(void)request;
	(void)kq;
	errno = ENOENT;
	return (-1);
}

void
on_demand_lookup_channel_gone(struct svc_lookup_channel *lc, int kq)
{

	(void)lc;
	(void)kq;
}

void
cancel_idle_timer(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
}

/*
 * The grant push: capture the svc_new_client_msg naming_lookup() hands the
 * provider so the identity (label, nonce, abi) and rights can be asserted.
 */
static struct svc_new_client_msg last_grant;
static unsigned grant_count;

int
svc_channel_send_event(struct svc_runtime *svc, const void *data, size_t length,
    const int *fds, size_t nfds, int kq)
{

	(void)svc;
	(void)fds;
	(void)nfds;
	(void)kq;
	if (length == sizeof(last_grant)) {
		memcpy(&last_grant, data, sizeof(last_grant));
		grant_count++;
	}
	return (0);
}

/* The audit record: capture the last one so refusals can be asserted. */
static char last_audit[512];
static int last_audit_event;
static int last_audit_error;
static uid_t last_audit_uid;
static unsigned audit_count;

void
switchboard_audit(int event, uid_t auid, int error, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(last_audit, sizeof(last_audit), fmt, ap);
	va_end(ap);
	last_audit_event = event;
	last_audit_uid = auid;
	last_audit_error = error;
	audit_count++;
}

static void
audit_reset(void)
{

	last_audit[0] = '\0';
	last_audit_event = 0;
	last_audit_error = 0;
	last_audit_uid = (uid_t)-1;
	audit_count = 0;
	grant_count = 0;
	memset(&last_grant, 0, sizeof(last_grant));
}

/* ------------------------------------------------------------------ */
/* Bundle-registry fixture: the design's acceptance-matrix endpoints.  */
/* ------------------------------------------------------------------ */

#define	OPEN_USER_NAME		"system.Notify"		/* open, user-visible */
#define	GATED_NAME		"system.Notify.System"	/* requires notify.system */
#define	GATED_ANOINT		"system.notify.system"
#define	STORAGE_NAME		"system.Storage.Admin"	/* requires storage.admin */
#define	STORAGE_ANOINT		"system.storage.admin"
#define	BOTH_NAME		"system.X.Both"		/* requires a.one AND a.two */
#define	TRACE_NAME		"system.Trace"		/* requires trace.client */
#define	TRACE_ANOINT		"system.trace.client"
#define	SYSTEM_ONLY_NAME	"system.Filesystem"	/* open, system-only */
#define	UNKNOWN_NAME		"org.example.Nobody"	/* not in the registry */

struct fixture_endpoint {
	const char	*name;
	bool		 user_resolvable;
	unsigned	 nrequires;
	const char	*requires[SWITCHBOARD_MAX_REQUIRES];
};

static const struct fixture_endpoint fixture[] = {
	{ OPEN_USER_NAME,	true,	0, { NULL } },
	{ GATED_NAME,		false,	1, { GATED_ANOINT } },
	{ STORAGE_NAME,		false,	1, { STORAGE_ANOINT } },
	{ BOTH_NAME,		false,	2, { "a.one", "a.two" } },
	{ TRACE_NAME,		false,	1, { TRACE_ANOINT } },
	{ SYSTEM_ONLY_NAME,	false,	0, { NULL } },
};

int
bundle_registry_lookup(const char *name, unsigned *bundle_idx,
    unsigned *service_idx)
{
	unsigned i;

	for (i = 0; i < nitems(fixture); i++) {
		if (strcmp(fixture[i].name, name) == 0) {
			*bundle_idx = i;
			*service_idx = 0;
			return (0);
		}
	}
	return (-1);
}

struct capbundle *
bundle_registry_get(unsigned idx)
{

	if (idx >= nitems(fixture))
		return (NULL);
	return ((struct capbundle *)(uintptr_t)&fixture[idx]);
}

struct capbundle_service *
capbundle_service(const struct capbundle *b, unsigned i)
{

	(void)i;
	return ((struct capbundle_service *)(uintptr_t)b);
}

static const struct fixture_endpoint *
fx(const struct capbundle_service *s)
{

	return ((const struct fixture_endpoint *)s);
}

bool
capbundle_svc_user_resolvable(const struct capbundle_service *s)
{

	return (fx(s)->user_resolvable);
}

int
capbundle_svc_provides_index(const struct capbundle_service *s,
    const char *name)
{

	return (strcmp(fx(s)->name, name) == 0 ? 0 : -1);
}

unsigned
capbundle_svc_nrequires(const struct capbundle_service *s,
    unsigned provides_idx)
{

	return (provides_idx == 0 ? fx(s)->nrequires : 0);
}

const char *
capbundle_svc_requires(const struct capbundle_service *s,
    unsigned provides_idx, unsigned j)
{

	if (provides_idx != 0 || j >= fx(s)->nrequires)
		return (NULL);
	return (fx(s)->requires[j]);
}

/*
 * mac_cap_create_channel: a genuine mac_capability channel pair when a test
 * asked for one (the end-to-end cases; ENODEV without the device so they can
 * skip), otherwise a socketpair so the pure resolve path can be driven
 * in-session — the provider under test is registered sendable, so
 * naming_lookup() never applies a transfer limit to the fake endpoint.
 */
static bool want_real_channel;

static int
real_channel_pair(int *our_end, int *child_end)
{
	struct mac_capability_connect_args connect;
	struct mac_capability_sendmsg_args send;
	struct mac_capability_recvmsg_args receive;
	uint32_t op;
	int control, first, second, error;

	control = open("/dev/mac_capability", O_RDWR);
	if (control == -1) {
		errno = ENODEV;
		return (-1);
	}
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, "channel", sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	first = connect.fd;

	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	if (ioctl(first, MAC_CAPABILITY_SENDMSG, &send) == -1) {
		error = errno;
		close(first);
		errno = error;
		return (-1);
	}
	second = -1;
	memset(&receive, 0, sizeof(receive));
	receive.fds = &second;
	receive.nfds = 1;
	if (ioctl(first, MAC_CAPABILITY_RECVMSG, &receive) == -1 ||
	    receive.nfds != 1 || second < 0) {
		error = errno != 0 ? errno : EIO;
		close(first);
		errno = error;
		return (-1);
	}
	(void)fcntl(first, F_SETFD, FD_CLOEXEC);
	(void)fcntl(second, F_SETFD, FD_CLOEXEC);
	*our_end = first;
	*child_end = second;
	return (0);
}

int
mac_cap_create_channel(int *our_end, int *child_end)
{
	int sv[2];

	if (want_real_channel)
		return (real_channel_pair(our_end, child_end));
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (-1);
	*our_end = sv[0];
	*child_end = sv[1];
	return (0);
}

/* ------------------------------------------------------------------ */
/* Helpers.                                                             */
/* ------------------------------------------------------------------ */

static void
set_with(struct svc_anoint_set *set, const char *const *names, unsigned n)
{
	unsigned i;

	memset(set, 0, sizeof(*set));
	for (i = 0; i < n && i < SVC_ANOINT_MAX; i++)
		strlcpy(set->names[i], names[i], sizeof(set->names[i]));
	set->n = n;
}

static void
set_one(struct svc_anoint_set *set, const char *name)
{

	set_with(set, &name, 1);
}

static void
requires_fill(char (*requires)[SWITCHBOARD_LABEL_MAX],
    const char *const *names, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		strlcpy(requires[i], names[i], SWITCHBOARD_LABEL_MAX);
}

#define	CREQ(r)	((const char (*)[SWITCHBOARD_LABEL_MAX])(r))

/*
 * Register a provider under `label` publishing `name` with the given
 * requires in ITS OWN manifest — the policy the unit was launched with is
 * what the resolve path consults first.  Registered sendable so the fake
 * endpoint is never transfer-limited.  channel_fd is only compared against
 * -1 by the resolve path; the grant push is stubbed.
 */
static void
provider_register(struct svc_runtime *svc, const char *label,
    const char *name, const char *const *requires, unsigned nrequires)
{

	memset(svc, 0, sizeof(*svc));
	strlcpy(svc->manifest.label, label, sizeof(svc->manifest.label));
	strlcpy(svc->manifest.provides[0], name,
	    sizeof(svc->manifest.provides[0]));
	svc->manifest.nprovides = 1;
	svc->manifest.nrequires[0] = nrequires;
	requires_fill(svc->manifest.requires[0], requires, nrequires);
	svc->protocol_ready = true;
	svc->state = SVC_STATE_RUNNING;
	svc->channel_fd = 99;
	ATF_REQUIRE_EQ(0, naming_register(name, svc, true));
	ATF_REQUIRE(naming_exists(name));
}

/* A unit requester: its set comes from its manifest, exactly as execute.c. */
static void
unit_init(struct svc_runtime *unit, const char *label,
    const char *const *anointments, unsigned n)
{
	unsigned i;

	memset(unit, 0, sizeof(*unit));
	strlcpy(unit->manifest.label, label, sizeof(unit->manifest.label));
	for (i = 0; i < n; i++)
		strlcpy(unit->manifest.anointments[i], anointments[i],
		    sizeof(unit->manifest.anointments[i]));
	unit->manifest.nanointments = n;
	unit->domain.kind = SVC_DOMAIN_SYSTEM;
	svc_anoint_set_from_manifest(&unit->domain.anoint, &unit->manifest);
}

static const char *const NOTIFY_ONE[] = { GATED_ANOINT };
static const char *const A_ONE[] = { "a.one" };
static const char *const A_BOTH[] = { "a.one", "a.two" };
static const char *const ADMIN_ONE[] = { SVC_ANOINT_SWITCHBOARD_ADMIN };

/* ------------------------------------------------------------------ */
/* svc_anoint_covers / holds: the match table.                          */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(covers_table);
ATF_TC_BODY(covers_table, tc)
{
	struct svc_anoint_set empty, one, both, all;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];

	memset(&empty, 0, sizeof(empty));
	set_one(&one, "a.one");
	set_with(&both, A_BOTH, 2);
	memset(&all, 0, sizeof(all));
	all.all = true;

	/* An open endpoint (no requires) is covered by everyone, even NULL. */
	ATF_CHECK(svc_anoint_covers(NULL, NULL, 0));
	ATF_CHECK(svc_anoint_covers(&empty, NULL, 0));
	ATF_CHECK(svc_anoint_covers(&empty, CREQ(req), 0));

	/* One required name. */
	requires_fill(req, A_ONE, 1);
	ATF_CHECK(!svc_anoint_covers(NULL, CREQ(req), 1));
	ATF_CHECK(!svc_anoint_covers(&empty, CREQ(req), 1));
	ATF_CHECK(svc_anoint_covers(&one, CREQ(req), 1));
	ATF_CHECK(svc_anoint_covers(&both, CREQ(req), 1));
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));

	/* Several: all-of.  Holding one of two is a miss (U6); both is a hit (U7). */
	requires_fill(req, A_BOTH, 2);
	ATF_CHECK(!svc_anoint_covers(&empty, CREQ(req), 2));
	ATF_CHECK(!svc_anoint_covers(&one, CREQ(req), 2));
	ATF_CHECK(svc_anoint_covers(&both, CREQ(req), 2));
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 2));

	/* The all flag short-circuits regardless of the name list. */
	ATF_CHECK_EQ(0U, all.n);
	requires_fill(req, (const char *const[]){ "nobody.declares" }, 1);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));

	/* Exact, case-sensitive, whole-string comparison. */
	requires_fill(req, (const char *const[]){ "A.One" }, 1);
	ATF_CHECK(!svc_anoint_covers(&one, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "a.one.more" }, 1);
	ATF_CHECK(!svc_anoint_covers(&one, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "a.on" }, 1);
	ATF_CHECK(!svc_anoint_covers(&one, CREQ(req), 1));

	/* Holds: same rules for a single name; "*" is never a held name. */
	ATF_CHECK(svc_anoint_holds(&one, "a.one"));
	ATF_CHECK(!svc_anoint_holds(&one, "a.two"));
	ATF_CHECK(!svc_anoint_holds(&one, "*"));
	ATF_CHECK(svc_anoint_holds(&all, "anything.at.all"));
	ATF_CHECK(!svc_anoint_holds(NULL, "a.one"));
	ATF_CHECK(!svc_anoint_holds(&one, NULL));

	/* A NULL requires list with a nonzero count is a miss, never a crash. */
	ATF_CHECK(!svc_anoint_covers(&one, NULL, 1));
	ATF_CHECK(svc_anoint_covers(&all, NULL, 1));
}

ATF_TC_WITHOUT_HEAD(set_from_manifest);
ATF_TC_BODY(set_from_manifest, tc)
{
	struct svc_manifest m;
	struct svc_anoint_set set;
	unsigned i;

	memset(&m, 0, sizeof(m));
	strlcpy(m.anointments[0], "a.one", sizeof(m.anointments[0]));
	strlcpy(m.anointments[1], "a.two", sizeof(m.anointments[1]));
	m.nanointments = 2;

	memset(&set, 0xff, sizeof(set));	/* stale garbage is cleared */
	svc_anoint_set_from_manifest(&set, &m);
	ATF_CHECK_EQ(2U, set.n);
	ATF_CHECK_STREQ("a.one", set.names[0]);
	ATF_CHECK_STREQ("a.two", set.names[1]);
	/* A unit never holds "*" and never carries the admin bypass. */
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);
	ATF_CHECK_EQ('\0', set.names[2][0]);

	/* An absent list is the empty set. */
	memset(&m, 0, sizeof(m));
	svc_anoint_set_from_manifest(&set, &m);
	ATF_CHECK_EQ(0U, set.n);
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);

	/* A NULL manifest is the empty set. */
	memset(&set, 0xff, sizeof(set));
	svc_anoint_set_from_manifest(&set, NULL);
	ATF_CHECK_EQ(0U, set.n);
	ATF_CHECK(!set.all);

	/* An empty slot is skipped, and the count is clamped to the bound. */
	memset(&m, 0, sizeof(m));
	for (i = 0; i < SWITCHBOARD_MAX_ANOINTMENTS; i++)
		snprintf(m.anointments[i], sizeof(m.anointments[i]),
		    "name.%u", i);
	m.anointments[3][0] = '\0';
	m.nanointments = SWITCHBOARD_MAX_ANOINTMENTS + 5;	/* corrupt */
	svc_anoint_set_from_manifest(&set, &m);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_ANOINTMENTS - 1, set.n);
	ATF_CHECK(svc_anoint_holds(&set, "name.0"));
	ATF_CHECK(!svc_anoint_holds(&set, "name.3"));
	ATF_CHECK(svc_anoint_holds(&set, "name.31"));
}

/* ------------------------------------------------------------------ */
/* svc_anoint_set_from_mint: the SVC_OP_MINT_DOMAIN payload contract.   */
/* ------------------------------------------------------------------ */

static void
mint_req_init(struct svc_mint_domain_req *req, uint32_t flags,
    const char *const *names, unsigned n)
{
	unsigned i;

	memset(req, 0, sizeof(*req));
	req->op = SVC_OP_MINT_DOMAIN;
	req->flags = flags;
	req->uid = 1001;
	req->domain = SVC_MINT_DOMAIN_USER;
	for (i = 0; i < n && i < SVC_ANOINT_MAX; i++)
		strlcpy(req->anointments[i], names[i],
		    sizeof(req->anointments[i]));
	req->nanointments = n;
}

ATF_TC_WITHOUT_HEAD(set_from_mint_valid);
ATF_TC_BODY(set_from_mint_valid, tc)
{
	struct svc_mint_domain_req req;
	struct svc_anoint_set set;

	/* An empty set: the shipped default for an ordinary user (S3/S4). */
	mint_req_init(&req, 0, NULL, 0);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK_EQ(0U, set.n);
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);

	/* A literal list (P1 operators). */
	mint_req_init(&req, 0, (const char *const[]){ TRACE_ANOINT,
	    GATED_ANOINT }, 2);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK_EQ(2U, set.n);
	ATF_CHECK_STREQ(TRACE_ANOINT, set.names[0]);
	ATF_CHECK_STREQ(GATED_ANOINT, set.names[1]);
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);

	/* "*" travels as the ANOINT_ALL flag; ADMIN_RIGHTS is its own knob. */
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL | SVC_MINT_FLAG_ADMIN_RIGHTS,
	    NULL, 0);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(set.all);
	ATF_CHECK(set.admin_rights);

	/* The two knobs are independent (P6: some names, no bypass). */
	mint_req_init(&req, 0, ADMIN_ONE, 1);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);
	ATF_CHECK(svc_anoint_holds(&set, SVC_ANOINT_SWITCHBOARD_ADMIN));
	mint_req_init(&req, SVC_MINT_FLAG_ADMIN_RIGHTS, NULL, 0);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
	ATF_CHECK(set.admin_rights);

	/* RESEND is still accepted, alone and combined. */
	mint_req_init(&req, SVC_MINT_FLAG_RESEND, NULL, 0);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	mint_req_init(&req, SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ANOINT_ALL |
	    SVC_MINT_FLAG_ADMIN_RIGHTS, NULL, 0);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(set.all && set.admin_rights);

	/* Exactly the bound is fine. */
	{
		const char *names[SVC_ANOINT_MAX];
		char store[SVC_ANOINT_MAX][16];
		unsigned i;

		for (i = 0; i < SVC_ANOINT_MAX; i++) {
			snprintf(store[i], sizeof(store[i]), "n.%u", i);
			names[i] = store[i];
		}
		mint_req_init(&req, 0, names, SVC_ANOINT_MAX);
		ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
		ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, set.n);
		ATF_CHECK(svc_anoint_holds(&set, "n.31"));
	}

	/* Entries past nanointments are ignored, garbage or not. */
	mint_req_init(&req, 0, A_ONE, 1);
	memset(req.anointments[1], 'x', sizeof(req.anointments[1]));
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK_EQ(1U, set.n);
	ATF_CHECK(!svc_anoint_holds(&set, "x"));
}

ATF_TC_WITHOUT_HEAD(set_from_mint_rejects);
ATF_TC_BODY(set_from_mint_rejects, tc)
{
	struct svc_mint_domain_req req;
	struct svc_anoint_set set;

	/* Oversize count. */
	mint_req_init(&req, 0, NULL, 0);
	req.nanointments = SVC_ANOINT_MAX + 1;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	req.nanointments = 0xffffffffU;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* An unterminated name (all 64 bytes non-NUL). */
	mint_req_init(&req, 0, A_ONE, 1);
	memset(req.anointments[0], 'a', sizeof(req.anointments[0]));
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* An empty name inside the counted range. */
	mint_req_init(&req, 0, A_BOTH, 2);
	req.anointments[0][0] = '\0';
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* "*" as a name: the wildcard is the ANOINT_ALL flag, never a name. */
	mint_req_init(&req, 0, (const char *const[]){ "*" }, 1);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	mint_req_init(&req, 0, (const char *const[]){ "a.one", "*" }, 2);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* Unknown flag bits. */
	mint_req_init(&req, 0x8U, NULL, 0);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL | 0x80000000U, NULL, 0);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* The reserved word must be zero. */
	mint_req_init(&req, 0, NULL, 0);
	req.reserved = 1;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* A refused request leaves an empty, harmless set behind. */
	ATF_CHECK_EQ(0U, set.n);
	ATF_CHECK(!set.all);
	ATF_CHECK(!set.admin_rights);

	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(NULL, &set));
}

/* ------------------------------------------------------------------ */
/* Registry-derived requires, gating, and the missing-name rendering.  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(endpoint_requires_from_registry);
ATF_TC_BODY(endpoint_requires_from_registry, tc)
{
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	unsigned n;

	n = 99;
	ATF_CHECK_EQ(0, svc_anoint_endpoint_requires(GATED_NAME, req, &n));
	ATF_CHECK_EQ(1U, n);
	ATF_CHECK_STREQ(GATED_ANOINT, req[0]);

	ATF_CHECK_EQ(0, svc_anoint_endpoint_requires(BOTH_NAME, req, &n));
	ATF_CHECK_EQ(2U, n);
	ATF_CHECK_STREQ("a.one", req[0]);
	ATF_CHECK_STREQ("a.two", req[1]);

	/* Open endpoints: known, zero requires. */
	n = 99;
	ATF_CHECK_EQ(0, svc_anoint_endpoint_requires(OPEN_USER_NAME, req, &n));
	ATF_CHECK_EQ(0U, n);
	ATF_CHECK_EQ(0, svc_anoint_endpoint_requires(SYSTEM_ONLY_NAME, req, &n));
	ATF_CHECK_EQ(0U, n);

	/* Unknown to the registry: -1, and n is zero (treated as open). */
	n = 99;
	ATF_CHECK_EQ(-1, svc_anoint_endpoint_requires(UNKNOWN_NAME, req, &n));
	ATF_CHECK_EQ(0U, n);
	ATF_CHECK_EQ(-1, svc_anoint_endpoint_requires(NULL, req, &n));

	ATF_CHECK(svc_anoint_name_gated(GATED_NAME));
	ATF_CHECK(svc_anoint_name_gated(BOTH_NAME));
	ATF_CHECK(!svc_anoint_name_gated(OPEN_USER_NAME));
	ATF_CHECK(!svc_anoint_name_gated(SYSTEM_ONLY_NAME));
	ATF_CHECK(!svc_anoint_name_gated(UNKNOWN_NAME));
	ATF_CHECK(!svc_anoint_name_gated(NULL));
}

ATF_TC_WITHOUT_HEAD(unit_requires_from_manifest);
ATF_TC_BODY(unit_requires_from_manifest, tc)
{
	struct svc_manifest m;
	const char (*req)[SWITCHBOARD_LABEL_MAX];
	unsigned n;

	memset(&m, 0, sizeof(m));
	strlcpy(m.provides[0], OPEN_USER_NAME, sizeof(m.provides[0]));
	strlcpy(m.provides[1], GATED_NAME, sizeof(m.provides[1]));
	m.nprovides = 2;
	m.nrequires[1] = 1;
	strlcpy(m.requires[1][0], GATED_ANOINT, sizeof(m.requires[1][0]));

	ATF_CHECK_EQ(0, svc_anoint_unit_requires(&m, OPEN_USER_NAME, &req, &n));
	ATF_CHECK_EQ(0U, n);
	ATF_CHECK_EQ(0, svc_anoint_unit_requires(&m, GATED_NAME, &req, &n));
	ATF_CHECK_EQ(1U, n);
	ATF_CHECK(req != NULL);
	ATF_CHECK_STREQ(GATED_ANOINT, req[0]);
	/* Not published by this manifest (a helper name, say). */
	ATF_CHECK_EQ(-1, svc_anoint_unit_requires(&m, "helper.x.y", &req, &n));
	ATF_CHECK_EQ(0U, n);
	ATF_CHECK(req == NULL);
	ATF_CHECK_EQ(-1, svc_anoint_unit_requires(NULL, GATED_NAME, &req, &n));
	/* A corrupt count is clamped. */
	m.nrequires[1] = SWITCHBOARD_MAX_REQUIRES + 3;
	ATF_CHECK_EQ(0, svc_anoint_unit_requires(&m, GATED_NAME, &req, &n));
	ATF_CHECK_EQ((unsigned)SWITCHBOARD_MAX_REQUIRES, n);
}

ATF_TC_WITHOUT_HEAD(missing_rendering);
ATF_TC_BODY(missing_rendering, tc)
{
	struct svc_anoint_set empty, one, all;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	char buf[256];

	memset(&empty, 0, sizeof(empty));
	set_one(&one, "a.one");
	memset(&all, 0, sizeof(all));
	all.all = true;
	requires_fill(req, A_BOTH, 2);

	ATF_CHECK_EQ(2, svc_anoint_missing(&empty, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("a.one,a.two", buf);
	ATF_CHECK_EQ(1, svc_anoint_missing(&one, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("a.two", buf);
	ATF_CHECK_EQ(0, svc_anoint_missing(&all, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("", buf);
	ATF_CHECK_EQ(2, svc_anoint_missing(NULL, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("a.one,a.two", buf);

	/* A short buffer truncates safely and still counts every miss. */
	ATF_CHECK_EQ(2, svc_anoint_missing(&empty, CREQ(req), 2, buf, 4));
	ATF_CHECK_STREQ("a.o", buf);
	ATF_CHECK_EQ(2, svc_anoint_missing(&empty, CREQ(req), 2, buf, 1));
	ATF_CHECK_STREQ("", buf);
	ATF_CHECK_EQ(2, svc_anoint_missing(&empty, CREQ(req), 2, buf, 0));
	ATF_CHECK_EQ(0, svc_anoint_missing(&empty, NULL, 2, buf, sizeof(buf)));
}

/* ------------------------------------------------------------------ */
/* Visibility: a gated endpoint is visible in USER kind to the match.  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(user_visibility_of_gated_names);
ATF_TC_BODY(user_visibility_of_gated_names, tc)
{
	struct svc_domain user, system;

	memset(&user, 0, sizeof(user));
	user.kind = SVC_DOMAIN_USER;
	user.uid = 1001;
	memset(&system, 0, sizeof(system));

	/* resolvable_by = ["user"] names stay visible; system-only open ones
	 * stay hidden — nothing changes for open endpoints. */
	ATF_CHECK(svc_domain_resolves(&user, OPEN_USER_NAME));
	ATF_CHECK(!svc_domain_resolves(&user, SYSTEM_ONLY_NAME));
	ATF_CHECK(!svc_domain_resolves(&user, UNKNOWN_NAME));

	/* A gated endpoint is visible in USER kind regardless of resolvable_by:
	 * the anointment match, not the domain kind, decides (P1/P2). */
	ATF_CHECK(svc_domain_resolves(&user, GATED_NAME));
	ATF_CHECK(svc_domain_resolves(&user, STORAGE_NAME));
	ATF_CHECK(svc_domain_resolves(&user, BOTH_NAME));
	ATF_CHECK(svc_domain_permits(&user, SVC_DOMAIN_SYSTEM, GATED_NAME));

	/* SYSTEM is unchanged: everything. */
	ATF_CHECK(svc_domain_resolves(&system, GATED_NAME));
	ATF_CHECK(svc_domain_resolves(&system, SYSTEM_ONLY_NAME));
	ATF_CHECK(svc_domain_resolves(NULL, GATED_NAME));

	/* Visibility is not reach: the set is not consulted here. */
	user.anoint.all = true;
	ATF_CHECK(!svc_domain_resolves(&user, SYSTEM_ONLY_NAME));
}

/* ------------------------------------------------------------------ */
/* naming_lookup: units.                                               */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(unit_covered_connects_with_identity);
ATF_TC_BODY(unit_covered_connects_with_identity, tc)
{
	struct svc_runtime provider, unit;
	struct channel_sender sender;
	bool sendable;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	unit_init(&unit, "com.example.pub/pub", NOTIFY_ONE, 1);	/* U1 */

	memset(&sender, 0, sizeof(sender));
	sender.nonce = 0x1122334455667788ULL;
	sender.uid = 1234;
	sender.abi = SVC_CLIENT_ABI_NATIVE;

	error = -1;
	sendable = false;
	fd = naming_lookup(GATED_NAME, &unit, &unit.domain, &sender, &error,
	    &sendable);
	ATF_REQUIRE_MSG(fd >= 0, "expected a connection, error %d", error);
	ATF_CHECK_EQ(0, error);
	ATF_CHECK(sendable);
	close(fd);

	/* The grant carries the unit's label, the sender nonce and ABI. */
	ATF_CHECK_EQ(1U, grant_count);
	ATF_CHECK_EQ((uint32_t)SVC_OP_NEW_CLIENT, last_grant.op);
	ATF_CHECK_STREQ(GATED_NAME, last_grant.service_name);
	ATF_CHECK_STREQ("com.example.pub/pub", last_grant.client_label);
	ATF_CHECK_EQ(0x1122334455667788ULL, last_grant.client_nonce);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_NATIVE, last_grant.client_abi);
	/* A unit never gets the admin bypass (U1: rights without ADMIN). */
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN, last_grant.rights);
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(1U, provider.connection_count);

	/* U10: a restarted instance has a different nonce, same label. */
	sender.nonce = 0x99ULL;
	fd = naming_lookup(GATED_NAME, &unit, &unit.domain, &sender, &error,
	    &sendable);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_STREQ("com.example.pub/pub", last_grant.client_label);
	ATF_CHECK_EQ(0x99ULL, last_grant.client_nonce);

	/* S10: a Linux-ABI sender is reported as such; reach is unchanged. */
	sender.abi = SVC_CLIENT_ABI_LINUX;
	fd = naming_lookup(GATED_NAME, &unit, &unit.domain, &sender, &error,
	    &sendable);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_LINUX, last_grant.client_abi);

	/* No stamp at all: nonce 0, ABI unknown, still connects. */
	fd = naming_lookup(GATED_NAME, &unit, &unit.domain, NULL, &error,
	    &sendable);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0ULL, last_grant.client_nonce);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_UNKNOWN, last_grant.client_abi);
	ATF_CHECK_EQ(0U, audit_count);

	naming_remove_owner(&provider);
}

ATF_TC_WITHOUT_HEAD(unit_uncovered_refused_and_audited);
ATF_TC_BODY(unit_uncovered_refused_and_audited, tc)
{
	struct svc_runtime provider, app, base;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	unit_init(&app, "com.example.app/app", NULL, 0);		/* U2 */

	memset(&sender, 0, sizeof(sender));
	sender.uid = 4242;
	sender.nonce = 7;

	error = 0;
	fd = naming_lookup(GATED_NAME, &app, &app.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);	/* the wire masks this to ENOENT */
	ATF_CHECK_EQ(0U, grant_count);	/* nothing was pushed to the provider */
	ATF_CHECK_EQ(0U, provider.connection_count);

	/* The audit record: event, uid from the stamp, label -> endpoint,
	 * missing names. */
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_EQ(EACCES, last_audit_error);
	ATF_CHECK_EQ(4242, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: com.example.app/app -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* Without a stamp the record is attributed to the daemon's own uid. */
	audit_reset();
	fd = naming_lookup(GATED_NAME, &app, &app.domain, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(getuid(), last_audit_uid);

	/* U9: a base unit with no anointments gets no free pass either, and
	 * its domain kind (SYSTEM) does not help. */
	audit_reset();
	unit_init(&base, "system.Base/thing", NULL, 0);
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, base.domain.kind);
	fd = naming_lookup(GATED_NAME, &base, &base.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);

	/* U3: the same unit reaches an open endpoint. */
	naming_remove_owner(&provider);
	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", OPEN_USER_NAME,
	    NULL, 0);
	fd = naming_lookup(OPEN_USER_NAME, &app, &app.domain, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_STREQ("com.example.app/app", last_grant.client_label);
	ATF_CHECK_EQ(7ULL, last_grant.client_nonce);
	naming_remove_owner(&provider);
}

ATF_TC_WITHOUT_HEAD(unit_all_of_several);
ATF_TC_BODY(unit_all_of_several, tc)
{
	struct svc_runtime provider, one, both;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.X/x", BOTH_NAME, A_BOTH, 2);
	unit_init(&one, "com.example.one/u", A_ONE, 1);		/* U6 */
	unit_init(&both, "com.example.both/u", A_BOTH, 2);	/* U7 */

	fd = naming_lookup(BOTH_NAME, &one, &one.domain, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: com.example.one/u -> " BOTH_NAME
	    " missing a.two", last_audit);

	fd = naming_lookup(BOTH_NAME, &both, &both.domain, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(1U, audit_count);

	naming_remove_owner(&provider);
}

/*
 * The resolve path consults the bundle REGISTRY first (the on-disk policy,
 * refreshed by reload) and falls back to the running provider's manifest copy
 * only for a name the registry does not know.  The reverse order let a stale
 * runtime copy keep an endpoint open after its policy file gained a
 * requirement (found on the VM: gate system.Trace, reload, plain user still
 * connected).
 */
ATF_TC_WITHOUT_HEAD(registry_wins_over_stale_unit_manifest);
ATF_TC_BODY(registry_wins_over_stale_unit_manifest, tc)
{
	struct svc_runtime provider, app;
	int fd, error;

	audit_reset();
	unit_init(&app, "com.example.app/app", NULL, 0);

	/* Registry gates GATED_NAME; the live (stale) manifest shows it open:
	 * the registry wins and the non-holder is refused. */
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NULL, 0);
	fd = naming_lookup(GATED_NAME, &app, &app.domain, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	naming_remove_owner(&provider);

	/* Registry says open (SYSTEM_ONLY_NAME); a live manifest that gates it
	 * does not override the on-disk policy. */
	audit_reset();
	provider_register(&provider, "system.Filesystem/fs", SYSTEM_ONLY_NAME,
	    NOTIFY_ONE, 1);
	fd = naming_lookup(SYSTEM_ONLY_NAME, &app, &app.domain, NULL, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	naming_remove_owner(&provider);

	/* A name the registry does not know falls back to the live manifest:
	 * gated there, so a non-holder is refused. */
	audit_reset();
	provider_register(&provider, "org.example.dyn/dyn", UNKNOWN_NAME,
	    NOTIFY_ONE, 1);
	fd = naming_lookup(UNKNOWN_NAME, &app, &app.domain, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	naming_remove_owner(&provider);
}

/* ------------------------------------------------------------------ */
/* naming_lookup: sessions (requester == NULL, set on the channel).     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(session_sets);
ATF_TC_BODY(session_sets, tc)
{
	struct svc_runtime provider, open_provider;
	struct svc_domain session;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	provider_register(&open_provider, "system.Notify/bsdnotify2",
	    OPEN_USER_NAME, NULL, 0);
	memset(&sender, 0, sizeof(sender));
	sender.uid = 1001;
	sender.nonce = 5;

	/* S4: a default user session (USER kind, empty set) is refused on the
	 * gated name, audited under the session label... */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	fd = naming_lookup(GATED_NAME, NULL, &session, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(1001, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* S3: ...and connects to the open tier, identified as a session. */
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_STREQ("org.5bsd.user-session", last_grant.client_label);
	ATF_CHECK_EQ(5ULL, last_grant.client_nonce);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);
	ATF_CHECK_EQ(1U, audit_count);

	/* S1/S2: the shipped-default wheel session holds "*". */
	audit_reset();
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.all = true;
	session.anoint.admin_rights = true;
	fd = naming_lookup(GATED_NAME, NULL, &session, &sender, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_STREQ("org.5bsd.user-session", last_grant.client_label);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL, last_grant.rights);
	ATF_CHECK_EQ(0U, audit_count);

	/* P1: an operator session holding exactly the name, in USER kind
	 * (the name is not user-resolvable — the gate makes it visible). */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1002;
	set_one(&session.anoint, GATED_ANOINT);
	fd = naming_lookup(GATED_NAME, NULL, &session, &sender, &error, NULL);
	ATF_REQUIRE_MSG(fd >= 0, "P1: expected a connection, error %d", error);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);

	/* P2: the same operator does not reach a differently gated name. */
	provider_register(&open_provider, "system.Storage/bsdfilesystem", STORAGE_NAME,
	    (const char *const[]){ STORAGE_ANOINT }, 1);
	fd = naming_lookup(STORAGE_NAME, NULL, &session, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    STORAGE_NAME " missing " STORAGE_ANOINT, last_audit);

	/* P6: root holding some, not all, in SYSTEM kind is still refused. */
	audit_reset();
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	set_one(&session.anoint, SVC_ANOINT_SWITCHBOARD_ADMIN);
	fd = naming_lookup(STORAGE_NAME, NULL, &session, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);

	/* A NULL domain holds nothing and gets no bypass. */
	audit_reset();
	fd = naming_lookup(STORAGE_NAME, NULL, NULL, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);

	naming_remove_owner(&provider);
	naming_remove_owner(&open_provider);
}

/*
 * Rights: the ADMIN bit follows admin_rights alone — not the domain kind,
 * not whether there is a requester.
 */
ATF_TC_WITHOUT_HEAD(rights_follow_admin_rights_knob);
ATF_TC_BODY(rights_follow_admin_rights_knob, tc)
{
	struct svc_runtime provider;
	struct svc_domain session;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", OPEN_USER_NAME,
	    NULL, 0);

	/* P8: SYSTEM kind, "*", but admin_rights = false: no bypass. */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.all = true;
	session.anoint.admin_rights = false;
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN, last_grant.rights);

	/* admin_rights = true carries it, even on a USER-kind channel and
	 * with an otherwise empty set (reach and bypass are independent). */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	session.anoint.admin_rights = true;
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL, last_grant.rights);
	ATF_CHECK(last_grant.rights & SVC_RIGHTS_ADMIN);

	/* The boot carry's shape (all + admin) is the old SYSTEM behaviour. */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.all = true;
	session.anoint.admin_rights = true;
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL, last_grant.rights);

	naming_remove_owner(&provider);
}

/* ------------------------------------------------------------------ */
/* The self-served control names require system.switchboard.admin.     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(self_control_requires_switchboard_admin);
ATF_TC_BODY(self_control_requires_switchboard_admin, tc)
{
	struct svc_domain session;
	struct svc_runtime unit;
	struct channel_sender sender;
	int fd, error;

	memset(&sender, 0, sizeof(sender));
	sender.uid = 0;

	/* A session on a SYSTEM-kind channel WITHOUT the anointment (P9-style
	 * strict admin) is refused and audited; the kind does not help. */
	audit_reset();
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.admin_rights = true;
	error = 0;
	fd = naming_lookup(SWITCHBOARD_CONTROL_NAME, NULL, &session, &sender,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    SWITCHBOARD_CONTROL_NAME " missing " SVC_ANOINT_SWITCHBOARD_ADMIN,
	    last_audit);

	/* The lifecycle plane is gated identically. */
	fd = naming_lookup(SWITCHBOARD_LIFECYCLE_NAME, NULL, &session, &sender,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);

	/* A NULL domain is refused too. */
	fd = naming_lookup(SWITCHBOARD_CONTROL_NAME, NULL, NULL, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);

	/*
	 * Holding the anointment passes the gate — in USER kind too (P6/P7: a
	 * root shell with admin_rights = false but the admin anointment).  The
	 * stubbed adopt path then runs against a fake channel, so the outcome
	 * past the gate is either a connection or a transport error; what
	 * matters is that it is not the anointment refusal and nothing is
	 * audited.
	 */
	audit_reset();
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 0;
	set_one(&session.anoint, SVC_ANOINT_SWITCHBOARD_ADMIN);
	fd = naming_lookup(SWITCHBOARD_CONTROL_NAME, NULL, &session, &sender,
	    &error, NULL);
	if (fd >= 0)
		close(fd);
	else
		ATF_CHECK_MSG(error != EACCES && error != ENOENT,
		    "gate passed but error is %d", error);
	ATF_CHECK_EQ(0U, audit_count);

	/* "*" (the boot carry, the shipped-default wheel session) passes. */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.all = true;
	fd = naming_lookup(SWITCHBOARD_CONTROL_NAME, NULL, &session, &sender,
	    &error, NULL);
	if (fd >= 0)
		close(fd);
	else
		ATF_CHECK_MSG(error != EACCES && error != ENOENT,
		    "gate passed but error is %d", error);
	ATF_CHECK_EQ(0U, audit_count);

	/* A unit never opens control, whatever it declares (U8-style). */
	unit_init(&unit, "com.example.admin/u", ADMIN_ONE, 1);
	unit.domain.anoint.all = true;
	fd = naming_lookup(SWITCHBOARD_CONTROL_NAME, &unit, &unit.domain,
	    &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
}

/* ------------------------------------------------------------------ */
/* On-demand pre-check: a non-holder cannot start the provider.         */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(on_demand_precheck);
ATF_TC_BODY(on_demand_precheck, tc)
{
	struct svc_anoint_set empty, holder, all;

	memset(&empty, 0, sizeof(empty));
	set_one(&holder, GATED_ANOINT);
	memset(&all, 0, sizeof(all));
	all.all = true;

	/* S5/U4: a non-holder is refused (EACCES, audited) before any launch. */
	audit_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, od_anoint_precheck(GATED_NAME, &empty,
	    "com.example.app/app", 1001));
	ATF_CHECK_EQ(EACCES, errno);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_EQ(1001, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: com.example.app/app -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* A NULL set (no requester, no ambient domain) holds nothing. */
	audit_reset();
	ATF_CHECK_EQ(-1, od_anoint_precheck(GATED_NAME, NULL, NULL, 0));
	ATF_CHECK_EQ(EACCES, errno);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* U5: a holder may activate it. */
	audit_reset();
	ATF_CHECK_EQ(0, od_anoint_precheck(GATED_NAME, &holder,
	    "com.example.pub/pub", 1001));
	ATF_CHECK_EQ(0, od_anoint_precheck(GATED_NAME, &all,
	    "org.5bsd.user-session", 0));
	ATF_CHECK_EQ(0U, audit_count);

	/* Open endpoints and names the registry does not gate always pass. */
	ATF_CHECK_EQ(0, od_anoint_precheck(OPEN_USER_NAME, &empty,
	    "com.example.app/app", 1001));
	ATF_CHECK_EQ(0, od_anoint_precheck(SYSTEM_ONLY_NAME, NULL, NULL, 0));
	ATF_CHECK_EQ(0, od_anoint_precheck(UNKNOWN_NAME, &empty, NULL, 0));
	ATF_CHECK_EQ(0U, audit_count);

	/* All-of: partial coverage is still a miss, with the rest named. */
	audit_reset();
	set_one(&holder, "a.one");
	ATF_CHECK_EQ(-1, od_anoint_precheck(BOTH_NAME, &holder,
	    "com.example.one/u", 1001));
	ATF_CHECK_STREQ("anointment refused: com.example.one/u -> " BOTH_NAME
	    " missing a.two", last_audit);
	set_with(&holder, A_BOTH, 2);
	ATF_CHECK_EQ(0, od_anoint_precheck(BOTH_NAME, &holder,
	    "com.example.both/u", 1001));
}

/*
 * The unregistered-name path of naming_lookup(): a gated, non-user-resolvable
 * name whose provider is stopped is on-demand ELIGIBLE (ENOENT) for a USER
 * session — visibility no longer hides it — and the pre-check then decides
 * whether the launch may happen.  Together these are S5.
 */
ATF_TC_WITHOUT_HEAD(unregistered_gated_name_is_ondemand_eligible);
ATF_TC_BODY(unregistered_gated_name_is_ondemand_eligible, tc)
{
	struct svc_domain user;
	int fd, error;

	ATF_REQUIRE(!naming_exists(STORAGE_NAME));
	memset(&user, 0, sizeof(user));
	user.kind = SVC_DOMAIN_USER;
	user.uid = 1001;

	error = 0;
	fd = naming_lookup(STORAGE_NAME, NULL, &user, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(ENOENT, error);		/* eligible: the pre-check gates */

	/* A system-only OPEN name stays out of scope for USER (unchanged). */
	fd = naming_lookup(SYSTEM_ONLY_NAME, NULL, &user, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);

	/* ...and the pre-check refuses the non-holder, permits the holder. */
	audit_reset();
	ATF_CHECK_EQ(-1, od_anoint_precheck(STORAGE_NAME, &user.anoint,
	    "org.5bsd.user-session", 1001));
	ATF_CHECK_EQ(1U, audit_count);
	set_one(&user.anoint, STORAGE_ANOINT);
	ATF_CHECK_EQ(0, od_anoint_precheck(STORAGE_NAME, &user.anoint,
	    "org.5bsd.user-session", 1001));
	ATF_CHECK_EQ(1U, audit_count);
}

/* ------------------------------------------------------------------ */
/* Minted channels carry the set (root + channel device; else skip).   */
/* ------------------------------------------------------------------ */

static void
require_real_channel(int rv)
{

	if (rv == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("mint: %s", strerror(errno));
	}
}

ATF_TC(minted_channel_carries_set);
ATF_TC_HEAD(minted_channel_carries_set, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a session channel minted with an anointment set records that set "
	    "(names, all, admin_rights) on switchboard's end; the boot carry "
	    "holds all + admin and a legacy user mint holds nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(minted_channel_carries_set, tc)
{
	struct svc_anoint_set set;
	struct svc_lookup_channel *lc;
	int fd, kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	want_real_channel = true;

	/* An operator session: two names, no "*", no bypass. */
	set_with(&set, (const char *const[]){ TRACE_ANOINT, GATED_ANOINT }, 2);
	fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 1002,
	    &set, &fd, kq));
	ATF_REQUIRE(fd >= 0);
	lc = lookup_channels;
	ATF_REQUIRE(lc != NULL);
	ATF_CHECK_EQ(SVC_DOMAIN_USER, lc->domain.kind);
	ATF_CHECK_EQ(1002, lc->domain.uid);
	ATF_CHECK_EQ(2U, lc->domain.anoint.n);
	ATF_CHECK_STREQ(TRACE_ANOINT, lc->domain.anoint.names[0]);
	ATF_CHECK_STREQ(GATED_ANOINT, lc->domain.anoint.names[1]);
	ATF_CHECK(!lc->domain.anoint.all);
	ATF_CHECK(!lc->domain.anoint.admin_rights);
	close(fd);

	/* P6: a SYSTEM-kind session with some names and no bypass. */
	set_one(&set, SVC_ANOINT_SWITCHBOARD_ADMIN);
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_SYSTEM, 0,
	    &set, &fd, kq));
	lc = lookup_channels;
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, lc->domain.kind);
	ATF_CHECK_EQ(1U, lc->domain.anoint.n);
	ATF_CHECK(!lc->domain.anoint.all);
	ATF_CHECK(!lc->domain.anoint.admin_rights);
	close(fd);

	/* The shipped-default wheel session: "*" + admin. */
	memset(&set, 0, sizeof(set));
	set.all = true;
	set.admin_rights = true;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_SYSTEM, 0,
	    &set, &fd, kq));
	lc = lookup_channels;
	ATF_CHECK(lc->domain.anoint.all);
	ATF_CHECK(lc->domain.anoint.admin_rights);
	ATF_CHECK_EQ(0U, lc->domain.anoint.n);
	close(fd);

	/* The boot carry holds all + admin (today's behaviour preserved). */
	require_real_channel(domain_mint_system_channel(&fd, kq));
	lc = lookup_channels;
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, lc->domain.kind);
	ATF_CHECK(lc->domain.anoint.all);
	ATF_CHECK(lc->domain.anoint.admin_rights);
	ATF_CHECK(svc_anoint_holds(&lc->domain.anoint,
	    SVC_ANOINT_SWITCHBOARD_ADMIN));
	close(fd);

	/* A legacy user mint holds nothing. */
	require_real_channel(domain_mint_user_channel(4321, &fd, kq));
	lc = lookup_channels;
	ATF_CHECK_EQ(SVC_DOMAIN_USER, lc->domain.kind);
	ATF_CHECK_EQ(0U, lc->domain.anoint.n);
	ATF_CHECK(!lc->domain.anoint.all);
	ATF_CHECK(!lc->domain.anoint.admin_rights);
	close(fd);

	/* A NULL set mints an empty one. */
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 7,
	    NULL, &fd, kq));
	lc = lookup_channels;
	ATF_CHECK_EQ(0U, lc->domain.anoint.n);
	ATF_CHECK(!lc->domain.anoint.all && !lc->domain.anoint.admin_rights);
	close(fd);

	domain_channel_teardown();
	close(kq);
	want_real_channel = false;
}

/* ------------------------------------------------------------------ */
/* End to end over a minted channel (root + channel device; else skip). */
/* ------------------------------------------------------------------ */

struct pump_ctx {
	int		kq;
	volatile int	stop;
};

static void *
domain_pump_thread(void *argument)
{
	struct pump_ctx *ctx = argument;
	struct kevent ev;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };

	while (!ctx->stop) {
		int n = kevent(ctx->kq, NULL, 0, &ev, 1, &ts);

		if (n == 1)
			domain_channel_event(&ev, ctx->kq);
	}
	return (NULL);
}

/*
 * Drive one SVC_OP_LOOKUP of `name` over the minted channel `minted_fd` with
 * libservice and return the wire status (0 with an endpoint attached, or the
 * masked error).
 */
static int
lookup_over_channel(int minted_fd, int kq, const char *name)
{
	struct svc_lookup_req req;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
	};
	int reply_fd = -1;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
		.fds = &reply_fd,
		.fd_capacity = 1,
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct pump_ctx ctx;
	pthread_t pump;
	int dupfd, status;

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	dupfd = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(dupfd >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(dupfd, &session));

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, name, sizeof(req.name));
	memset(&reply_data, 0, sizeof(reply_data));
	options.timeout_ms = 2000;

	ATF_REQUIRE_EQ(0, service_session_call(session, &message, &reply,
	    &options));
	ATF_REQUIRE_EQ(sizeof(reply_data), reply.length);
	status = reply_data.status;
	if (status == 0)
		ATF_CHECK_EQ(1, reply.nfds);
	else
		ATF_CHECK_EQ(0, reply.nfds);
	if (reply_fd >= 0)
		close(reply_fd);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	service_session_close(session);
	return (status);
}

ATF_TC(session_reach_over_minted_channel);
ATF_TC_HEAD(session_reach_over_minted_channel, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "over real minted session channels: a holder reaches the gated "
	    "endpoint, a non-holder gets ENOENT on the wire (audited) and still "
	    "reaches the open one, and the grant carries the session's real "
	    "nonce and native ABI");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(session_reach_over_minted_channel, tc)
{
	struct svc_runtime gated, open_provider;
	struct svc_anoint_set set;
	int holder_fd, plain_fd, kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	want_real_channel = true;

	set_one(&set, GATED_ANOINT);
	holder_fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 1002,
	    &set, &holder_fd, kq));
	memset(&set, 0, sizeof(set));
	plain_fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 1001,
	    &set, &plain_fd, kq));

	provider_register(&gated, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	provider_register(&open_provider, "system.Notify/bsdnotify2",
	    OPEN_USER_NAME, NULL, 0);

	/* P1 / S9-shape: the holder connects to the gated endpoint. */
	audit_reset();
	ATF_CHECK_EQ(0, lookup_over_channel(holder_fd, kq, GATED_NAME));
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_STREQ("org.5bsd.user-session", last_grant.client_label);
	ATF_CHECK_STREQ(GATED_NAME, last_grant.service_name);
	/* The kernel stamped this process's nonce and native ABI. */
	ATF_CHECK(last_grant.client_nonce != 0);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_NATIVE, last_grant.client_abi);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);

	/* S4: the non-holder sees ENOENT on the wire; the refusal is audited
	 * under this process's uid. */
	audit_reset();
	ATF_CHECK_EQ(ENOENT, lookup_over_channel(plain_fd, kq, GATED_NAME));
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_EQ(getuid(), last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* S3: and reaches the open tier. */
	audit_reset();
	ATF_CHECK_EQ(0, lookup_over_channel(plain_fd, kq, OPEN_USER_NAME));
	ATF_CHECK_EQ(0U, audit_count);

	naming_remove_owner(&gated);
	naming_remove_owner(&open_provider);
	domain_channel_teardown();
	close(holder_fd);
	close(plain_fd);
	close(kq);
	want_real_channel = false;
}

ATF_TC(registered_private_channel_keeps_set);
ATF_TC_HEAD(registered_private_channel_keeps_set, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a private per-process lookup channel registered over a session "
	    "channel (SVC_OP_REGISTER_LOOKUP) inherits that channel's "
	    "anointment set — never a wider one");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(registered_private_channel_keeps_set, tc)
{
	struct svc_anoint_set set;
	struct svc_lookup_channel *lc;
	struct pump_ctx ctx;
	pthread_t pump;
	char envbuf[16];
	int minted_fd, kq, priv, count;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	want_real_channel = true;

	set_with(&set, (const char *const[]){ TRACE_ANOINT }, 1);
	set.admin_rights = true;
	minted_fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 1002,
	    &set, &minted_fd, kq));

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	ATF_REQUIRE(snprintf(envbuf, sizeof(envbuf), "%d", minted_fd) <
	    (int)sizeof(envbuf));
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, envbuf, 1));
	priv = service_ambient_lookup_channel();
	if (priv < 0 || priv == minted_fd) {
		ctx.stop = 1;
		(void)pthread_join(pump, NULL);
		domain_channel_teardown();
		close(minted_fd);
		close(kq);
		want_real_channel = false;
		atf_tc_skip("private lookup-channel registration unavailable");
	}

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);

	/* Both switchboard-side channels carry the identical set. */
	count = 0;
	for (lc = lookup_channels; lc != NULL; lc = lc->next) {
		ATF_CHECK_EQ(SVC_DOMAIN_USER, lc->domain.kind);
		ATF_CHECK_EQ(1002, lc->domain.uid);
		ATF_CHECK_EQ(1U, lc->domain.anoint.n);
		ATF_CHECK_STREQ(TRACE_ANOINT, lc->domain.anoint.names[0]);
		ATF_CHECK(!lc->domain.anoint.all);
		ATF_CHECK(lc->domain.anoint.admin_rights);
		count++;
	}
	ATF_CHECK_EQ(2, count);

	domain_channel_teardown();
	close(minted_fd);
	close(kq);
	want_real_channel = false;
}

/* ------------------------------------------------------------------ */
/* Edge cases and negatives: the match at its bounds.                  */
/* ------------------------------------------------------------------ */

/*
 * A set (or a manifest) followed by a canary so a copy that runs past the
 * bound is caught rather than silently corrupting whatever lies after it.
 */
#define	CANARY_LEN	64
#define	CANARY_BYTE	0xa5

struct set_with_canary {
	struct svc_anoint_set	set;
	unsigned char		canary[CANARY_LEN];
};

static void
canary_arm(unsigned char *canary)
{

	memset(canary, CANARY_BYTE, CANARY_LEN);
}

static bool
canary_intact(const unsigned char *canary)
{
	unsigned i;

	for (i = 0; i < CANARY_LEN; i++)
		if (canary[i] != CANARY_BYTE)
			return (false);
	return (true);
}

/* A name of exactly SVC_ANOINT_NAME_MAX - 1 (63) characters, unique per seed. */
static void
max_name(char *buf, size_t buflen, unsigned seed)
{
	size_t i;

	ATF_REQUIRE(buflen >= SVC_ANOINT_NAME_MAX);
	for (i = 0; i < SVC_ANOINT_NAME_MAX - 1; i++)
		buf[i] = (char)('a' + ((seed + i) % 26));
	buf[SVC_ANOINT_NAME_MAX - 1] = '\0';
	ATF_REQUIRE_EQ(SVC_ANOINT_NAME_MAX - 1, strlen(buf));
}

ATF_TC_WITHOUT_HEAD(covers_duplicate_requires);
ATF_TC_BODY(covers_duplicate_requires, tc)
{
	struct svc_anoint_set one, empty, dup;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	char buf[128];

	set_one(&one, "a.b");
	memset(&empty, 0, sizeof(empty));

	/* requires ["a.b","a.b"] against a set holding "a.b" once: covered. */
	requires_fill(req, (const char *const[]){ "a.b", "a.b" }, 2);
	ATF_CHECK(svc_anoint_covers(&one, CREQ(req), 2));
	/* ...and against nothing: a miss, with the duplicate reported twice
	 * (the rendering is per requires entry, not per distinct name). */
	ATF_CHECK(!svc_anoint_covers(&empty, CREQ(req), 2));
	ATF_CHECK_EQ(2, svc_anoint_missing(&empty, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("a.b,a.b", buf);

	/* A set holding the name twice is no different from holding it once. */
	set_with(&dup, (const char *const[]){ "a.b", "a.b" }, 2);
	ATF_CHECK(svc_anoint_covers(&dup, CREQ(req), 2));
	requires_fill(req, (const char *const[]){ "a.b", "a.c" }, 2);
	ATF_CHECK(!svc_anoint_covers(&dup, CREQ(req), 2));
	ATF_CHECK_EQ(1, svc_anoint_missing(&dup, CREQ(req), 2, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("a.c", buf);

	/* Eight copies of the same missing name: eight misses. */
	requires_fill(req, (const char *const[]){ "z.z", "z.z", "z.z", "z.z",
	    "z.z", "z.z", "z.z", "z.z" }, 8);
	ATF_CHECK(!svc_anoint_covers(&one, CREQ(req), 8));
	ATF_CHECK_EQ(8, svc_anoint_missing(&one, CREQ(req), 8, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("z.z,z.z,z.z,z.z,z.z,z.z,z.z,z.z", buf);
}

ATF_TC_WITHOUT_HEAD(covers_at_set_bound);
ATF_TC_BODY(covers_at_set_bound, tc)
{
	struct set_with_canary sc;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	char store[SVC_ANOINT_MAX][16];
	const char *names[SVC_ANOINT_MAX];
	unsigned i;

	for (i = 0; i < SVC_ANOINT_MAX; i++) {
		snprintf(store[i], sizeof(store[i]), "n.%u", i);
		names[i] = store[i];
	}
	canary_arm(sc.canary);
	set_with(&sc.set, names, SVC_ANOINT_MAX);
	ATF_REQUIRE_EQ((unsigned)SVC_ANOINT_MAX, sc.set.n);

	/* The first and the 32nd are held; a 33rd (unknown) is not. */
	requires_fill(req, (const char *const[]){ "n.0" }, 1);
	ATF_CHECK(svc_anoint_covers(&sc.set, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "n.31" }, 1);
	ATF_CHECK(svc_anoint_covers(&sc.set, CREQ(req), 1));
	ATF_CHECK(svc_anoint_holds(&sc.set, "n.31"));
	requires_fill(req, (const char *const[]){ "n.32" }, 1);
	ATF_CHECK(!svc_anoint_covers(&sc.set, CREQ(req), 1));
	ATF_CHECK(!svc_anoint_holds(&sc.set, "n.32"));
	/* All-of across the bound: the 32nd plus an unknown is a miss. */
	requires_fill(req, (const char *const[]){ "n.31", "n.32" }, 2);
	ATF_CHECK(!svc_anoint_covers(&sc.set, CREQ(req), 2));
	/* Eight held names spanning the set: covered. */
	requires_fill(req, (const char *const[]){ "n.0", "n.7", "n.15", "n.16",
	    "n.23", "n.24", "n.30", "n.31" }, 8);
	ATF_CHECK(svc_anoint_covers(&sc.set, CREQ(req), 8));

	/*
	 * A corrupt count past the bound is clamped by holds(): the names
	 * array is never indexed past SVC_ANOINT_MAX, and the canary after the
	 * set is untouched by the whole exercise.
	 */
	sc.set.n = SVC_ANOINT_MAX + 7;
	ATF_CHECK(svc_anoint_holds(&sc.set, "n.31"));
	ATF_CHECK(!svc_anoint_holds(&sc.set, "n.32"));
	sc.set.n = 0xffffffffU;
	ATF_CHECK(svc_anoint_holds(&sc.set, "n.0"));
	ATF_CHECK(!svc_anoint_holds(&sc.set, "nope"));
	ATF_CHECK(canary_intact(sc.canary));

	/* n == 0 holds nothing even with names left in the slots. */
	sc.set.n = 0;
	ATF_CHECK(!svc_anoint_holds(&sc.set, "n.0"));
	requires_fill(req, (const char *const[]){ "n.0" }, 1);
	ATF_CHECK(!svc_anoint_covers(&sc.set, CREQ(req), 1));
}

/*
 * The empty name.  Neither production constructor can put "" into a set
 * (set_from_manifest skips an empty slot; set_from_mint refuses it with
 * EINVAL) and the bundle parser refuses "" in a requires list, so an empty
 * requires entry never matches a set built the normal way.  The raw match
 * itself is a plain strcmp: DOCUMENTED here, a hand-built set whose counted
 * slot is "" does hold "" -- the guarantee lives in the constructors, not in
 * svc_anoint_holds().
 */
ATF_TC_WITHOUT_HEAD(covers_empty_name_semantics);
ATF_TC_BODY(covers_empty_name_semantics, tc)
{
	struct svc_anoint_set set, raw, all;
	struct svc_manifest m;
	struct svc_mint_domain_req req;
	char reqs[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];

	requires_fill(reqs, (const char *const[]){ "" }, 1);

	/* From a manifest: the empty slot is dropped, so "" is not held. */
	memset(&m, 0, sizeof(m));
	strlcpy(m.anointments[0], "", sizeof(m.anointments[0]));
	strlcpy(m.anointments[1], "a.b", sizeof(m.anointments[1]));
	m.nanointments = 2;
	svc_anoint_set_from_manifest(&set, &m);
	ATF_CHECK_EQ(1U, set.n);
	ATF_CHECK(!svc_anoint_holds(&set, ""));
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(reqs), 1));
	/* Nor does a set holding a real name match an empty requires entry. */
	set_one(&set, "a.b");
	ATF_CHECK(!svc_anoint_holds(&set, ""));
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(reqs), 1));
	/* The empty set does not hold "". */
	memset(&set, 0, sizeof(set));
	ATF_CHECK(!svc_anoint_holds(&set, ""));
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(reqs), 1));

	/* From a mint: "" is refused outright. */
	mint_req_init(&req, 0, (const char *const[]){ "" }, 1);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* A hand-built set with a counted empty slot still never holds "":
	 * the match refuses an empty name before comparing (defence in depth
	 * against a corrupted set), and such a slot matches no real name. */
	memset(&raw, 0, sizeof(raw));
	raw.n = 1;			/* names[0] == "" */
	ATF_CHECK(!svc_anoint_holds(&raw, ""));
	ATF_CHECK(!svc_anoint_covers(&raw, CREQ(reqs), 1));
	ATF_CHECK(!svc_anoint_holds(&raw, "a.b"));

	/* `all` short-circuits before the name is examined: it covers an
	 * empty requires entry too (all covers everything), even though the
	 * membership helper itself never holds "". */
	memset(&all, 0, sizeof(all));
	all.all = true;
	ATF_CHECK(!svc_anoint_holds(&all, ""));
	ATF_CHECK(svc_anoint_covers(&all, CREQ(reqs), 1));
}

ATF_TC_WITHOUT_HEAD(covers_prefix_suffix_case);
ATF_TC_BODY(covers_prefix_suffix_case, tc)
{
	struct svc_anoint_set set;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	static const char *const near_misses[] = {
		"system.notify.system",		/* longer (suffix added) */
		"system.notif",			/* shorter (truncated) */
		"system.notify.",		/* trailing dot */
		".system.notify",		/* leading dot */
		"System.Notify",		/* case */
		"SYSTEM.NOTIFY",
		"system.Notify",
		"system.notify ",		/* trailing space */
		" system.notify",		/* leading space */
		"system-notify",		/* separator */
		"system_notify",
		"system..notify",
		"notify",
		"system",
		"*",
		"system.*",
		"system.notify*",
	};
	unsigned i;

	set_one(&set, "system.notify");
	for (i = 0; i < nitems(near_misses); i++) {
		requires_fill(req, &near_misses[i], 1);
		ATF_CHECK_MSG(!svc_anoint_holds(&set, near_misses[i]),
		    "'%s' must not match 'system.notify'", near_misses[i]);
		ATF_CHECK_MSG(!svc_anoint_covers(&set, CREQ(req), 1),
		    "'%s' must not be covered by 'system.notify'",
		    near_misses[i]);
	}
	/* The exact name still matches after all of that. */
	requires_fill(req, (const char *const[]){ "system.notify" }, 1);
	ATF_CHECK(svc_anoint_covers(&set, CREQ(req), 1));

	/* The other direction: holding the longer name does not cover the
	 * shorter (no prefix semantics either way), nor does a different case. */
	set_one(&set, "system.notify.system");
	requires_fill(req, (const char *const[]){ "system.notify" }, 1);
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(req), 1));
	set_one(&set, "System.Notify.System");
	requires_fill(req, (const char *const[]){ "system.notify.system" }, 1);
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "System.Notify.System" }, 1);
	ATF_CHECK(svc_anoint_covers(&set, CREQ(req), 1));

	/* Two near-misses in a set do not add up to the real name. */
	set_with(&set, (const char *const[]){ "system.notify.", "System.Notify",
	    "system.notify.system" }, 3);
	requires_fill(req, (const char *const[]){ "system.notify" }, 1);
	ATF_CHECK(!svc_anoint_covers(&set, CREQ(req), 1));
}

/*
 * `all` is a flag beside the names, not a name: it covers with or without
 * names in the list, and (DOCUMENTED) covers even a degenerate requires
 * entry such as "" -- covers() returns before it looks at the list.
 */
ATF_TC_WITHOUT_HEAD(covers_all_flag_with_names);
ATF_TC_BODY(covers_all_flag_with_names, tc)
{
	struct svc_anoint_set all;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	char buf[64];

	set_with(&all, (const char *const[]){ "a.one" }, 1);
	all.all = true;
	ATF_CHECK_EQ(1U, all.n);

	requires_fill(req, (const char *const[]){ "a.one" }, 1);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "not.listed" }, 1);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "" }, 1);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "a.one", "", "x.y.z" }, 3);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 3));
	/* Nothing is ever reported missing for `all`. */
	ATF_CHECK_EQ(0, svc_anoint_missing(&all, CREQ(req), 3, buf,
	    sizeof(buf)));
	ATF_CHECK_STREQ("", buf);
	/* Beyond the requires bound, still covered (clamped, not indexed). */
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), SWITCHBOARD_MAX_REQUIRES +
	    100));
	ATF_CHECK(svc_anoint_covers(&all, NULL, 0xffffffffU));

	/* Clearing the flag makes the names count again. */
	all.all = false;
	requires_fill(req, (const char *const[]){ "a.one" }, 1);
	ATF_CHECK(svc_anoint_covers(&all, CREQ(req), 1));
	requires_fill(req, (const char *const[]){ "not.listed" }, 1);
	ATF_CHECK(!svc_anoint_covers(&all, CREQ(req), 1));
}

/*
 * svc_anoint_set_from_manifest at the bound.  A manifest whose count exceeds
 * SWITCHBOARD_MAX_ANOINTMENTS (corrupt; the parser enforces the bound)
 * DOCUMENTED: is silently clamped to the first SVC_ANOINT_MAX slots -- no
 * error, no overflow, and the destination (guarded by a canary here) is
 * written only within the set.  Max-length names copy intact; an
 * unterminated slot (corrupt) is truncated by strlcpy to 63 characters.
 */
ATF_TC_WITHOUT_HEAD(set_from_manifest_bounds);
ATF_TC_BODY(set_from_manifest_bounds, tc)
{
	struct set_with_canary sc;
	struct svc_manifest m;
	char expect[SVC_ANOINT_NAME_MAX];
	unsigned i;

	memset(&m, 0, sizeof(m));
	for (i = 0; i < SWITCHBOARD_MAX_ANOINTMENTS; i++)
		max_name(m.anointments[i], sizeof(m.anointments[i]), i);

	/* Exactly the bound: every slot, every character. */
	m.nanointments = SWITCHBOARD_MAX_ANOINTMENTS;
	canary_arm(sc.canary);
	memset(&sc.set, 0xff, sizeof(sc.set));
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, sc.set.n);
	for (i = 0; i < SVC_ANOINT_MAX; i++) {
		max_name(expect, sizeof(expect), i);
		ATF_CHECK_STREQ(expect, sc.set.names[i]);
		ATF_CHECK(svc_anoint_holds(&sc.set, expect));
	}
	ATF_CHECK(canary_intact(sc.canary));
	ATF_CHECK(!sc.set.all);
	ATF_CHECK(!sc.set.admin_rights);

	/* One past the bound, and the largest possible count: clamped. */
	m.nanointments = SWITCHBOARD_MAX_ANOINTMENTS + 1;
	canary_arm(sc.canary);
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, sc.set.n);
	ATF_CHECK(canary_intact(sc.canary));
	m.nanointments = 0xffffffffU;
	canary_arm(sc.canary);
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, sc.set.n);
	max_name(expect, sizeof(expect), SVC_ANOINT_MAX - 1);
	ATF_CHECK(svc_anoint_holds(&sc.set, expect));
	ATF_CHECK(canary_intact(sc.canary));

	/* Empty slots interleaved: compacted, count is what survived. */
	m.nanointments = SWITCHBOARD_MAX_ANOINTMENTS;
	m.anointments[0][0] = '\0';
	m.anointments[SWITCHBOARD_MAX_ANOINTMENTS - 1][0] = '\0';
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX - 2, sc.set.n);
	max_name(expect, sizeof(expect), 1);
	ATF_CHECK_STREQ(expect, sc.set.names[0]);
	max_name(expect, sizeof(expect), SVC_ANOINT_MAX - 2);
	ATF_CHECK_STREQ(expect, sc.set.names[SVC_ANOINT_MAX - 3]);
	ATF_CHECK_EQ('\0', sc.set.names[SVC_ANOINT_MAX - 2][0]);

	/* An unterminated slot (corrupt): truncated to 63, NUL-terminated. */
	memset(&m, 0, sizeof(m));
	memset(m.anointments[0], 'q', sizeof(m.anointments[0]));
	strlcpy(m.anointments[1], "a.b", sizeof(m.anointments[1]));
	m.nanointments = 2;
	canary_arm(sc.canary);
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK_EQ(2U, sc.set.n);
	ATF_CHECK_EQ(SVC_ANOINT_NAME_MAX - 1, strlen(sc.set.names[0]));
	ATF_CHECK_EQ('\0', sc.set.names[0][SVC_ANOINT_NAME_MAX - 1]);
	ATF_CHECK_STREQ("a.b", sc.set.names[1]);
	ATF_CHECK(canary_intact(sc.canary));

	/* A stale all/admin on the destination is always cleared. */
	memset(&m, 0, sizeof(m));
	sc.set.all = true;
	sc.set.admin_rights = true;
	svc_anoint_set_from_manifest(&sc.set, &m);
	ATF_CHECK(!sc.set.all);
	ATF_CHECK(!sc.set.admin_rights);
}

/*
 * svc_anoint_missing() with the largest possible rendering: eight names of
 * 63 characters plus seven commas is 511 characters, exactly what the
 * production buffer (SWITCHBOARD_MAX_REQUIRES * SWITCHBOARD_LABEL_MAX = 512)
 * holds with its NUL.  Smaller buffers truncate, always NUL-terminate, never
 * write past the end (canary), and still count every miss.
 */
ATF_TC_WITHOUT_HEAD(missing_rendering_max_names);
ATF_TC_BODY(missing_rendering_max_names, tc)
{
	struct svc_anoint_set empty, one;
	char req[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	struct {
		char		buf[SWITCHBOARD_MAX_REQUIRES *
				    SWITCHBOARD_LABEL_MAX];
		unsigned char	canary[CANARY_LEN];
	} full;
	struct {
		char		buf[100];
		unsigned char	canary[CANARY_LEN];
	} small;
	struct {
		char		buf[2];
		unsigned char	canary[CANARY_LEN];
	} tiny;
	char expect[SWITCHBOARD_MAX_REQUIRES * SWITCHBOARD_LABEL_MAX];
	size_t len, i;

	memset(&empty, 0, sizeof(empty));
	expect[0] = '\0';
	for (i = 0; i < SWITCHBOARD_MAX_REQUIRES; i++) {
		max_name(req[i], sizeof(req[i]), (unsigned)i * 3);
		if (i > 0)
			strlcat(expect, ",", sizeof(expect));
		strlcat(expect, req[i], sizeof(expect));
	}
	ATF_REQUIRE_EQ(SWITCHBOARD_MAX_REQUIRES * SWITCHBOARD_LABEL_MAX - 1,
	    strlen(expect));

	/* The production-sized buffer holds the whole rendering. */
	canary_arm(full.canary);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, full.buf, sizeof(full.buf)));
	ATF_CHECK_STREQ(expect, full.buf);
	ATF_CHECK(canary_intact(full.canary));

	/* A 100-byte buffer: the first 99 characters, NUL, canary intact. */
	canary_arm(small.canary);
	memset(small.buf, 'X', sizeof(small.buf));
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, small.buf,
	    sizeof(small.buf)));
	len = strnlen(small.buf, sizeof(small.buf));
	ATF_CHECK_EQ(sizeof(small.buf) - 1, len);
	ATF_CHECK_EQ(0, strncmp(expect, small.buf, len));
	ATF_CHECK(canary_intact(small.canary));

	/* A 2-byte buffer: one character and the NUL. */
	canary_arm(tiny.canary);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, tiny.buf, sizeof(tiny.buf)));
	ATF_CHECK_EQ(expect[0], tiny.buf[0]);
	ATF_CHECK_EQ('\0', tiny.buf[1]);
	ATF_CHECK(canary_intact(tiny.canary));

	/* Truncation exactly at a comma boundary: buffer of 64 = one name + NUL. */
	canary_arm(small.canary);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, small.buf,
	    SWITCHBOARD_LABEL_MAX));
	ATF_CHECK_STREQ(req[0], small.buf);
	ATF_CHECK(canary_intact(small.canary));
	/* ...and one byte more: the comma, then NUL. */
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, small.buf,
	    SWITCHBOARD_LABEL_MAX + 1));
	ATF_CHECK_EQ(SWITCHBOARD_LABEL_MAX, strlen(small.buf));
	ATF_CHECK_EQ(',', small.buf[SWITCHBOARD_LABEL_MAX - 1]);

	/* Holding one of the eight drops it from the rendering, count 7. */
	set_one(&one, req[3]);
	canary_arm(full.canary);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES - 1, svc_anoint_missing(&one,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES, full.buf, sizeof(full.buf)));
	ATF_CHECK(strstr(full.buf, req[3]) == NULL);
	ATF_CHECK(strstr(full.buf, req[2]) != NULL);
	ATF_CHECK(strstr(full.buf, req[4]) != NULL);
	ATF_CHECK(canary_intact(full.canary));

	/* A count past the bound is clamped: never more than 8 rendered. */
	canary_arm(full.canary);
	ATF_CHECK_EQ(SWITCHBOARD_MAX_REQUIRES, svc_anoint_missing(&empty,
	    CREQ(req), SWITCHBOARD_MAX_REQUIRES + 50, full.buf,
	    sizeof(full.buf)));
	ATF_CHECK_STREQ(expect, full.buf);
	ATF_CHECK(canary_intact(full.canary));
}

/* ------------------------------------------------------------------ */
/* svc_anoint_set_from_mint: the wire validator at its edges.          */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(set_from_mint_name_lengths);
ATF_TC_BODY(set_from_mint_name_lengths, tc)
{
	struct svc_mint_domain_req req;
	struct set_with_canary sc;
	char name[SVC_ANOINT_NAME_MAX];
	unsigned i;

	/* Exactly 63 characters (+ NUL in byte 63): accepted verbatim. */
	max_name(name, sizeof(name), 5);
	mint_req_init(&req, 0, (const char *const[]){ name }, 1);
	ATF_REQUIRE_EQ('\0', req.anointments[0][SVC_ANOINT_NAME_MAX - 1]);
	canary_arm(sc.canary);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK_EQ(1U, sc.set.n);
	ATF_CHECK_STREQ(name, sc.set.names[0]);
	ATF_CHECK(svc_anoint_holds(&sc.set, name));
	ATF_CHECK(canary_intact(sc.canary));

	/* 64 characters without a NUL: refused. */
	mint_req_init(&req, 0, NULL, 0);
	memset(req.anointments[0], 'b', SVC_ANOINT_NAME_MAX);
	req.nanointments = 1;
	canary_arm(sc.canary);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK_EQ(0U, sc.set.n);
	ATF_CHECK(canary_intact(sc.canary));

	/* The unterminated name in the LAST slot: refused, no read past. */
	mint_req_init(&req, 0, NULL, 0);
	for (i = 0; i < SVC_ANOINT_MAX; i++)
		snprintf(req.anointments[i], sizeof(req.anointments[i]),
		    "n.%u", i);
	memset(req.anointments[SVC_ANOINT_MAX - 1], 'c', SVC_ANOINT_NAME_MAX);
	req.nanointments = SVC_ANOINT_MAX;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &sc.set));
	/* ...but the same request with that slot beyond the count is fine. */
	req.nanointments = SVC_ANOINT_MAX - 1;
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX - 1, sc.set.n);
	ATF_CHECK(!svc_anoint_holds(&sc.set, "n.31"));
	ATF_CHECK_EQ('\0', sc.set.names[SVC_ANOINT_MAX - 1][0]);

	/* A single-character name is the shortest accepted. */
	mint_req_init(&req, 0, (const char *const[]){ "a" }, 1);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK(svc_anoint_holds(&sc.set, "a"));

	/* Exactly the bound of names, each at max length. */
	mint_req_init(&req, 0, NULL, 0);
	for (i = 0; i < SVC_ANOINT_MAX; i++)
		max_name(req.anointments[i], sizeof(req.anointments[i]), i);
	req.nanointments = SVC_ANOINT_MAX;
	canary_arm(sc.canary);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, sc.set.n);
	max_name(name, sizeof(name), SVC_ANOINT_MAX - 1);
	ATF_CHECK_STREQ(name, sc.set.names[SVC_ANOINT_MAX - 1]);
	ATF_CHECK(canary_intact(sc.canary));
	/* One more than the bound with the same payload: refused. */
	req.nanointments = SVC_ANOINT_MAX + 1;
	canary_arm(sc.canary);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &sc.set));
	ATF_CHECK(canary_intact(sc.canary));
}

/*
 * An embedded NUL: "a.b\0junk" in a slot.  DOCUMENTED: the validator
 * measures with strnlen, so the name is accepted as "a.b" and the bytes past
 * the NUL are never copied (the set slot is zeroed first).  A wire caller
 * cannot smuggle anything past the first NUL.
 */
ATF_TC_WITHOUT_HEAD(set_from_mint_embedded_nul);
ATF_TC_BODY(set_from_mint_embedded_nul, tc)
{
	struct svc_mint_domain_req req;
	struct svc_anoint_set set;
	size_t i;

	mint_req_init(&req, 0, NULL, 0);
	memcpy(req.anointments[0], "a.b\0junk", 8);
	req.nanointments = 1;
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK_EQ(1U, set.n);
	ATF_CHECK_STREQ("a.b", set.names[0]);
	for (i = 4; i < SVC_ANOINT_NAME_MAX; i++)
		ATF_CHECK_EQ('\0', set.names[0][i]);
	ATF_CHECK(svc_anoint_holds(&set, "a.b"));
	ATF_CHECK(!svc_anoint_holds(&set, "junk"));
	/* A C literal with an embedded NUL is just "a.b" to the matcher too. */
	ATF_CHECK(svc_anoint_holds(&set, "a.b\0junk"));

	/* A "*" hidden after the NUL is not seen; a "*" before it is. */
	mint_req_init(&req, 0, NULL, 0);
	memcpy(req.anointments[0], "a.b\0*", 5);
	req.nanointments = 1;
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
	memcpy(req.anointments[0], "*\0a.b", 5);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));

	/* Only a leading NUL is "empty": refused. */
	mint_req_init(&req, 0, NULL, 0);
	memcpy(req.anointments[0], "\0a.b", 4);
	req.nanointments = 1;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
}

ATF_TC_WITHOUT_HEAD(set_from_mint_flags_matrix);
ATF_TC_BODY(set_from_mint_flags_matrix, tc)
{
	struct svc_mint_domain_req req;
	struct svc_anoint_set set;
	static const uint32_t good[] = {
		0,
		SVC_MINT_FLAG_RESEND,
		SVC_MINT_FLAG_ANOINT_ALL,
		SVC_MINT_FLAG_ADMIN_RIGHTS,
		SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ANOINT_ALL,
		SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ADMIN_RIGHTS,
		SVC_MINT_FLAG_ANOINT_ALL | SVC_MINT_FLAG_ADMIN_RIGHTS,
		SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ANOINT_ALL |
		    SVC_MINT_FLAG_ADMIN_RIGHTS,
	};
	static const uint32_t reserved[] = { 1, 0x80000000U, 0xffffffffU };
	static const uint32_t bad[] = {
		0x8U,
		0x10U,
		0x100U,
		0x8000U,
		0x80000000U,
		0xfffffff8U,
		0xffffffffU,
		SVC_MINT_FLAG_RESEND | 0x8U,
		SVC_MINT_FLAG_ANOINT_ALL | SVC_MINT_FLAG_ADMIN_RIGHTS | 0x8U,
	};
	unsigned i;

	for (i = 0; i < nitems(good); i++) {
		mint_req_init(&req, good[i], A_ONE, 1);
		ATF_CHECK_EQ_MSG(0, svc_anoint_set_from_mint(&req, &set),
		    "flags %#x must be accepted", good[i]);
		ATF_CHECK_EQ((good[i] & SVC_MINT_FLAG_ANOINT_ALL) != 0, set.all);
		ATF_CHECK_EQ((good[i] & SVC_MINT_FLAG_ADMIN_RIGHTS) != 0,
		    set.admin_rights);
		/* RESEND is transport-only: it never shows in the set. */
		ATF_CHECK(svc_anoint_holds(&set, "a.one"));
	}
	for (i = 0; i < nitems(bad); i++) {
		mint_req_init(&req, bad[i], A_ONE, 1);
		ATF_CHECK_EQ_MSG(EINVAL, svc_anoint_set_from_mint(&req, &set),
		    "flags %#x must be refused", bad[i]);
		ATF_CHECK(!set.all);
		ATF_CHECK(!set.admin_rights);
		ATF_CHECK_EQ(0U, set.n);
	}

	/* reserved: every nonzero value is refused, whatever the flags. */
	for (i = 0; i < nitems(reserved); i++) {
		mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL |
		    SVC_MINT_FLAG_ADMIN_RIGHTS, NULL, 0);
		req.reserved = reserved[i];
		ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
		ATF_CHECK(!set.all && !set.admin_rights);
	}

	/* uid and domain are not the validator's business. */
	mint_req_init(&req, 0, A_ONE, 1);
	req.uid = 0xffffffffU;
	req.domain = 0xffffffffU;
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	/* Nor is op: a wrong op word is the dispatcher's problem. */
	req.op = 0;
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
}

/*
 * ANOINT_ALL with a literal list attached.  DOCUMENTED: the request is
 * accepted -- the set is `all`, and the names ride along in the set (they are
 * redundant, never consulted while `all` is set).  The list is still
 * validated: a bad name or an oversize count is refused even under
 * ANOINT_ALL, so the flag is no way around the validator.
 */
ATF_TC_WITHOUT_HEAD(set_from_mint_all_with_names);
ATF_TC_BODY(set_from_mint_all_with_names, tc)
{
	struct svc_mint_domain_req req;
	struct svc_anoint_set set;

	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL, A_BOTH, 2);
	ATF_CHECK_EQ(0, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(set.all);
	ATF_CHECK_EQ(2U, set.n);
	ATF_CHECK_STREQ("a.one", set.names[0]);
	ATF_CHECK(svc_anoint_holds(&set, "a.one"));
	ATF_CHECK(svc_anoint_holds(&set, "nothing.listed"));
	ATF_CHECK(!set.admin_rights);

	/* ANOINT_ALL does not excuse a bad list. */
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL,
	    (const char *const[]){ "a.one", "*" }, 2);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL,
	    (const char *const[]){ "" }, 1);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL, NULL, 0);
	req.nanointments = SVC_ANOINT_MAX + 1;
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
	mint_req_init(&req, SVC_MINT_FLAG_ANOINT_ALL, A_ONE, 1);
	memset(req.anointments[0], 'd', SVC_ANOINT_NAME_MAX);
	ATF_CHECK_EQ(EINVAL, svc_anoint_set_from_mint(&req, &set));
	ATF_CHECK(!set.all);
}

/*
 * The wire shape handle_mint_domain() length-checks against.  The handler
 * itself is not linked here (svc_proto.c owns the channel dispatch), but its
 * one guard is `length != sizeof(struct svc_mint_domain_req)` -> EINVAL, so
 * pin the size the guard compares with: a v12 (pre-anointment) request or a
 * truncated list can never alias a valid one.
 */
ATF_TC_WITHOUT_HEAD(mint_req_wire_shape);
ATF_TC_BODY(mint_req_wire_shape, tc)
{

	ATF_CHECK_EQ(6 * sizeof(uint32_t) + SVC_ANOINT_MAX * SVC_ANOINT_NAME_MAX,
	    sizeof(struct svc_mint_domain_req));
	ATF_CHECK_EQ(6 * sizeof(uint32_t),
	    offsetof(struct svc_mint_domain_req, anointments));
	ATF_CHECK_EQ(SVC_ANOINT_MAX * SVC_ANOINT_NAME_MAX,
	    sizeof(((struct svc_mint_domain_req *)0)->anointments));
	/* The set never grows past what the wire can carry. */
	ATF_CHECK(sizeof(((struct svc_anoint_set *)0)->names) ==
	    sizeof(((struct svc_mint_domain_req *)0)->anointments));
}

/* ------------------------------------------------------------------ */
/* naming_lookup: more of the matrix.                                   */
/* ------------------------------------------------------------------ */

/*
 * Two requires, partial coverage from either side, and the audit count:
 * exactly one record per refusal regardless of how many names are missing.
 */
ATF_TC_WITHOUT_HEAD(lookup_two_requires_partial_and_audit_count);
ATF_TC_BODY(lookup_two_requires_partial_and_audit_count, tc)
{
	struct svc_runtime provider, two_only, none;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.X/x", BOTH_NAME, A_BOTH, 2);
	unit_init(&two_only, "com.example.two/u",
	    (const char *const[]){ "a.two" }, 1);
	unit_init(&none, "com.example.none/u", NULL, 0);
	memset(&sender, 0, sizeof(sender));
	sender.uid = 77;

	/* Holds a.two only: one record naming only a.one. */
	fd = naming_lookup(BOTH_NAME, &two_only, &two_only.domain, &sender,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(77, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: com.example.two/u -> " BOTH_NAME
	    " missing a.one", last_audit);
	ATF_CHECK(strstr(last_audit, "a.two") == NULL);

	/* Holds neither: still ONE record, both names in it. */
	fd = naming_lookup(BOTH_NAME, &none, &none.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);
	ATF_CHECK_STREQ("anointment refused: com.example.none/u -> " BOTH_NAME
	    " missing a.one,a.two", last_audit);

	/* Repeating the refusal audits again: one per attempt. */
	fd = naming_lookup(BOTH_NAME, &none, &none.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(3U, audit_count);
	ATF_CHECK_EQ(0U, grant_count);
	ATF_CHECK_EQ(0U, provider.connection_count);

	/* Gaining the other name (a re-derived set) connects, no record. */
	unit_init(&two_only, "com.example.two/u", A_BOTH, 2);
	fd = naming_lookup(BOTH_NAME, &two_only, &two_only.domain, &sender,
	    &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(3U, audit_count);
	ATF_CHECK_EQ(1U, grant_count);

	naming_remove_owner(&provider);
}

/*
 * A unit whose channel is USER kind (not the SYSTEM default) asking for a
 * gated endpoint that is NOT user_resolvable: the gate makes it visible, so
 * the holder connects and the non-holder is refused by the anointment match
 * (audited).  An OPEN system-only name stays out of scope for that same
 * unit -- refused by the domain rule, never audited as an anointment miss.
 */
ATF_TC_WITHOUT_HEAD(lookup_user_kind_unit_gated_visibility);
ATF_TC_BODY(lookup_user_kind_unit_gated_visibility, tc)
{
	struct svc_runtime gated, sysonly, holder, plain;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&gated, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	provider_register(&sysonly, "system.Filesystem/fs", SYSTEM_ONLY_NAME,
	    NULL, 0);
	unit_init(&holder, "com.example.holder/u", NOTIFY_ONE, 1);
	holder.domain.kind = SVC_DOMAIN_USER;
	holder.domain.uid = 1001;
	unit_init(&plain, "com.example.plain/u", NULL, 0);
	plain.domain.kind = SVC_DOMAIN_USER;
	plain.domain.uid = 1001;
	memset(&sender, 0, sizeof(sender));
	sender.uid = 1001;
	sender.nonce = 11;

	/* Visibility: the gated, non-user-resolvable name resolves in USER. */
	ATF_REQUIRE(svc_domain_resolves(&holder.domain, GATED_NAME));
	ATF_REQUIRE(!svc_domain_resolves(&holder.domain, SYSTEM_ONLY_NAME));

	/* Holder connects. */
	fd = naming_lookup(GATED_NAME, &holder, &holder.domain, &sender, &error,
	    NULL);
	ATF_REQUIRE_MSG(fd >= 0, "holder in USER kind: error %d", error);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_STREQ("com.example.holder/u", last_grant.client_label);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);

	/* Non-holder: EACCES from the match, audited. */
	fd = naming_lookup(GATED_NAME, &plain, &plain.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_STREQ("anointment refused: com.example.plain/u -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);

	/* The open system-only name: out of scope for USER, not audited. */
	audit_reset();
	fd = naming_lookup(SYSTEM_ONLY_NAME, &holder, &holder.domain, &sender,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(0U, audit_count);
	/* Even `all` does not widen visibility of an OPEN system-only name. */
	holder.domain.anoint.all = true;
	fd = naming_lookup(SYSTEM_ONLY_NAME, &holder, &holder.domain, &sender,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(0U, audit_count);

	naming_remove_owner(&gated);
	naming_remove_owner(&sysonly);
}

/*
 * Identity without a kernel stamp and with a Linux-ABI stamp, on the session
 * path (requester == NULL).  ABI is information only: it neither helps nor
 * hurts reach, and an unknown ABI value passes through untouched.
 */
ATF_TC_WITHOUT_HEAD(lookup_identity_without_stamp_and_linux_abi);
ATF_TC_BODY(lookup_identity_without_stamp_and_linux_abi, tc)
{
	struct svc_runtime provider;
	struct svc_domain holder, plain;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	memset(&holder, 0, sizeof(holder));
	holder.kind = SVC_DOMAIN_USER;
	holder.uid = 1002;
	set_one(&holder.anoint, GATED_ANOINT);
	memset(&plain, 0, sizeof(plain));
	plain.kind = SVC_DOMAIN_USER;
	plain.uid = 1001;

	/* sender == NULL, holder: connects; grant nonce 0, ABI 0. */
	memset(&last_grant, 0xff, sizeof(last_grant));
	fd = naming_lookup(GATED_NAME, NULL, &holder, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0ULL, last_grant.client_nonce);
	ATF_CHECK_EQ(0, last_grant.client_abi);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_UNKNOWN, last_grant.client_abi);
	ATF_CHECK_STREQ("org.5bsd.user-session", last_grant.client_label);

	/* sender == NULL, non-holder: refused; audit uid is getuid(). */
	fd = naming_lookup(GATED_NAME, NULL, &plain, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(getuid(), last_audit_uid);

	/* Linux ABI, holder: connects, grant says 3, everything else same. */
	memset(&sender, 0, sizeof(sender));
	sender.uid = 1002;
	sender.nonce = 0xabcdULL;
	sender.abi = SVC_CLIENT_ABI_LINUX;
	fd = naming_lookup(GATED_NAME, NULL, &holder, &sender, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(3, last_grant.client_abi);
	ATF_CHECK_EQ(SVC_CLIENT_ABI_LINUX, last_grant.client_abi);
	ATF_CHECK_EQ(0xabcdULL, last_grant.client_nonce);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN, last_grant.rights);
	ATF_CHECK_EQ(1U, audit_count);

	/* Linux ABI, non-holder: still refused -- ABI never gates reach. */
	sender.uid = 1001;
	fd = naming_lookup(GATED_NAME, NULL, &plain, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);
	ATF_CHECK_EQ(1001, last_audit_uid);

	/* An ABI value the daemon does not know passes through verbatim. */
	sender.uid = 1002;
	sender.abi = 0xff;
	fd = naming_lookup(GATED_NAME, NULL, &holder, &sender, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0xff, last_grant.client_abi);

	naming_remove_owner(&provider);
}

/*
 * A unit never gets SVC_RIGHTS_ADMIN, even with its set forced to `all`: the
 * bit follows admin_rights alone, and svc_anoint_set_from_manifest() never
 * sets that (re-deriving the set clears a hand-planted one).  `all` does
 * widen the unit's reach -- that is what the flag means -- so the invariant
 * "units never hold *" is libcapbundle's (the parser refuses it), not the
 * matcher's.
 */
ATF_TC_WITHOUT_HEAD(lookup_unit_never_admin_even_with_all);
ATF_TC_BODY(lookup_unit_never_admin_even_with_all, tc)
{
	struct svc_runtime provider, unit;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Storage/bsdfilesystem", STORAGE_NAME,
	    (const char *const[]){ STORAGE_ANOINT }, 1);
	unit_init(&unit, "com.example.pub/pub", NOTIFY_ONE, 1);
	memset(&sender, 0, sizeof(sender));
	sender.uid = 0;		/* root-running unit: uid does not matter */

	/* Without `all` the unit does not reach STORAGE_NAME. */
	fd = naming_lookup(STORAGE_NAME, &unit, &unit.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);

	/* With `all` forced on the runtime it reaches it -- without ADMIN. */
	unit.domain.anoint.all = true;
	ATF_CHECK(!unit.domain.anoint.admin_rights);
	fd = naming_lookup(STORAGE_NAME, &unit, &unit.domain, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN, last_grant.rights);
	ATF_CHECK_STREQ("com.example.pub/pub", last_grant.client_label);

	/* Re-deriving from the manifest drops `all` and a planted admin bit. */
	unit.domain.anoint.admin_rights = true;
	svc_anoint_set_from_manifest(&unit.domain.anoint, &unit.manifest);
	ATF_CHECK(!unit.domain.anoint.all);
	ATF_CHECK(!unit.domain.anoint.admin_rights);
	ATF_CHECK_EQ(1U, unit.domain.anoint.n);
	fd = naming_lookup(STORAGE_NAME, &unit, &unit.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);

	naming_remove_owner(&provider);
}

/*
 * Rights are not reach: a session with admin_rights = true and an EMPTY set
 * carries SVC_RIGHTS_ADMIN into an open endpoint's grant and is still
 * refused (audited) on a gated one.
 */
ATF_TC_WITHOUT_HEAD(lookup_session_admin_rights_without_reach);
ATF_TC_BODY(lookup_session_admin_rights_without_reach, tc)
{
	struct svc_runtime gated, open_provider;
	struct svc_domain session;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&gated, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	provider_register(&open_provider, "system.Notify/bsdnotify2",
	    OPEN_USER_NAME, NULL, 0);
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_SYSTEM;
	session.anoint.admin_rights = true;
	ATF_REQUIRE_EQ(0U, session.anoint.n);
	ATF_REQUIRE(!session.anoint.all);
	memset(&sender, 0, sizeof(sender));
	sender.uid = 0;

	/* Open: connects with the ADMIN bit. */
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK(last_grant.rights & SVC_RIGHTS_ADMIN);
	ATF_CHECK_EQ(SVC_RIGHTS_ALL, last_grant.rights);
	ATF_CHECK_EQ(0U, audit_count);

	/* Gated: refused, audited under uid 0, no grant pushed. */
	fd = naming_lookup(GATED_NAME, NULL, &session, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(0, last_audit_uid);
	ATF_CHECK_EQ(1U, grant_count);
	ATF_CHECK_EQ(0U, gated.connection_count);

	/* Same in USER kind (the gated name is visible there; still a miss). */
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	fd = naming_lookup(GATED_NAME, NULL, &session, &sender, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);

	naming_remove_owner(&gated);
	naming_remove_owner(&open_provider);
}

/*
 * The self-served control names, holder by holder: the exact anointment
 * alone passes (both names), `all` passes, near-misses of the name do not,
 * and a unit is refused before the anointment is even consulted (so nothing
 * is audited for it -- it is not an anointment miss, it is "not a session").
 */
ATF_TC_WITHOUT_HEAD(lookup_self_control_holder_variants);
ATF_TC_BODY(lookup_self_control_holder_variants, tc)
{
	struct svc_domain session;
	struct svc_runtime unit;
	struct channel_sender sender;
	static const char *const control_names[] = {
		SWITCHBOARD_CONTROL_NAME, SWITCHBOARD_LIFECYCLE_NAME,
	};
	static const char *const near_misses[] = {
		"System.Switchboard.Admin",
		"system.switchboard.admin.x",
		"system.switchboard",
		"system.switchboard.admi",
		"*",
	};
	unsigned i, j;
	int fd, error;

	memset(&sender, 0, sizeof(sender));
	sender.uid = 0;

	for (i = 0; i < nitems(control_names); i++) {
		/* Exactly the admin anointment, nothing else, USER kind. */
		audit_reset();
		memset(&session, 0, sizeof(session));
		session.kind = SVC_DOMAIN_USER;
		session.uid = 0;
		set_one(&session.anoint, SVC_ANOINT_SWITCHBOARD_ADMIN);
		error = 0;
		fd = naming_lookup(control_names[i], NULL, &session, &sender,
		    &error, NULL);
		if (fd >= 0)
			close(fd);
		else
			ATF_CHECK_MSG(error != EACCES && error != ENOENT,
			    "%s: gate passed but error is %d",
			    control_names[i], error);
		ATF_CHECK_EQ(0U, audit_count);

		/* `all` without admin_rights. */
		memset(&session, 0, sizeof(session));
		session.kind = SVC_DOMAIN_USER;
		session.anoint.all = true;
		fd = naming_lookup(control_names[i], NULL, &session, &sender,
		    &error, NULL);
		if (fd >= 0)
			close(fd);
		else
			ATF_CHECK_MSG(error != EACCES && error != ENOENT,
			    "%s: all: gate passed but error is %d",
			    control_names[i], error);
		ATF_CHECK_EQ(0U, audit_count);

		/* Near-misses of the name: refused, one audit record each. */
		for (j = 0; j < nitems(near_misses); j++) {
			audit_reset();
			memset(&session, 0, sizeof(session));
			session.kind = SVC_DOMAIN_SYSTEM;
			session.anoint.admin_rights = true;
			set_one(&session.anoint, near_misses[j]);
			fd = naming_lookup(control_names[i], NULL, &session,
			    &sender, &error, NULL);
			ATF_CHECK_EQ(-1, fd);
			ATF_CHECK_EQ(EACCES, error);
			ATF_CHECK_EQ_MSG(1U, audit_count, "%s holding '%s'",
			    control_names[i], near_misses[j]);
			ATF_CHECK_EQ(0, last_audit_uid);
		}

		/* A unit, even with `all` and the admin name: EACCES, no
		 * audit (refused as a service, not as a miss). */
		audit_reset();
		unit_init(&unit, "com.example.admin/u", ADMIN_ONE, 1);
		unit.domain.anoint.all = true;
		fd = naming_lookup(control_names[i], &unit, &unit.domain,
		    &sender, &error, NULL);
		ATF_CHECK_EQ(-1, fd);
		ATF_CHECK_EQ(EACCES, error);
		ATF_CHECK_EQ(0U, audit_count);
		ATF_CHECK_EQ(0U, grant_count);
	}
}

/*
 * An open endpoint (nrequires == 0) with a requester holding nothing at all:
 * connects, nothing audited, on both the unit and the session path, with
 * and without a stamp, in USER and SYSTEM kind, and through a NULL domain.
 */
ATF_TC_WITHOUT_HEAD(lookup_open_endpoint_no_set);
ATF_TC_BODY(lookup_open_endpoint_no_set, tc)
{
	struct svc_runtime provider, unit;
	struct svc_domain session;
	struct channel_sender sender;
	int fd, error;

	audit_reset();
	provider_register(&provider, "system.Notify/bsdnotify", OPEN_USER_NAME,
	    NULL, 0);
	ATF_REQUIRE(!svc_anoint_name_gated(OPEN_USER_NAME));
	unit_init(&unit, "com.example.nothing/u", NULL, 0);
	unit.domain.kind = SVC_DOMAIN_USER;
	unit.domain.uid = 1001;
	memset(&sender, 0, sizeof(sender));
	sender.uid = 1001;
	sender.nonce = 3;

	fd = naming_lookup(OPEN_USER_NAME, &unit, &unit.domain, NULL, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_STREQ("com.example.nothing/u", last_grant.client_label);
	ATF_CHECK_EQ(0ULL, last_grant.client_nonce);
	ATF_CHECK_EQ(0, last_grant.rights & SVC_RIGHTS_ADMIN);

	unit.domain.kind = SVC_DOMAIN_SYSTEM;
	fd = naming_lookup(OPEN_USER_NAME, &unit, &unit.domain, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(3ULL, last_grant.client_nonce);

	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	fd = naming_lookup(OPEN_USER_NAME, NULL, &session, &sender, &error,
	    NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_STREQ("org.5bsd.user-session", last_grant.client_label);

	fd = naming_lookup(OPEN_USER_NAME, NULL, NULL, NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(4U, grant_count);
	ATF_CHECK_EQ(4U, provider.connection_count);

	naming_remove_owner(&provider);
}

/*
 * The on-demand pre-check when the registry gates a name whose provider is
 * NOT running: the refusal (or permission) is decided from the registry
 * alone, before any launch.  A name the registry does not know is open (0),
 * as is a NULL name; the refusal record names only what is missing, under
 * the session label when the caller had none.
 */
ATF_TC_WITHOUT_HEAD(precheck_stopped_provider);
ATF_TC_BODY(precheck_stopped_provider, tc)
{
	struct svc_anoint_set empty, partial, both, all;

	ATF_REQUIRE(!naming_exists(BOTH_NAME));
	ATF_REQUIRE(!naming_exists(GATED_NAME));
	ATF_REQUIRE(svc_anoint_name_gated(BOTH_NAME));
	memset(&empty, 0, sizeof(empty));
	set_one(&partial, "a.two");
	set_with(&both, A_BOTH, 2);
	memset(&all, 0, sizeof(all));
	all.all = true;

	audit_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, od_anoint_precheck(BOTH_NAME, &empty,
	    "com.example.app/app", 1001));
	ATF_CHECK_EQ(EACCES, errno);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(1001, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: com.example.app/app -> " BOTH_NAME
	    " missing a.one,a.two", last_audit);

	errno = 0;
	ATF_CHECK_EQ(-1, od_anoint_precheck(BOTH_NAME, &partial, NULL, 42));
	ATF_CHECK_EQ(EACCES, errno);
	ATF_CHECK_EQ(2U, audit_count);
	ATF_CHECK_EQ(42, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    BOTH_NAME " missing a.one", last_audit);

	/* Holders: permitted, nothing recorded. */
	ATF_CHECK_EQ(0, od_anoint_precheck(BOTH_NAME, &both,
	    "com.example.both/u", 1001));
	ATF_CHECK_EQ(0, od_anoint_precheck(BOTH_NAME, &all, NULL, 0));
	ATF_CHECK_EQ(0, od_anoint_precheck(GATED_NAME, &all, NULL, 0));
	ATF_CHECK_EQ(2U, audit_count);

	/* Unknown to the registry, and NULL: open. */
	ATF_CHECK_EQ(0, od_anoint_precheck(UNKNOWN_NAME, &empty, NULL, 0));
	ATF_CHECK_EQ(0, od_anoint_precheck(UNKNOWN_NAME, NULL, NULL, 0));
	ATF_CHECK_EQ(0, od_anoint_precheck(NULL, &empty, NULL, 0));
	ATF_CHECK_EQ(0, od_anoint_precheck(NULL, NULL, NULL, 0));
	ATF_CHECK_EQ(2U, audit_count);

	/* The gate is by exact name: a near-miss holder is refused. */
	set_with(&partial, (const char *const[]){ "a.one", "A.two" }, 2);
	ATF_CHECK_EQ(-1, od_anoint_precheck(BOTH_NAME, &partial, "x/y", 1));
	ATF_CHECK_EQ(3U, audit_count);
	ATF_CHECK_STREQ("anointment refused: x/y -> " BOTH_NAME
	    " missing a.two", last_audit);
}

/*
 * The reserved "helper." namespace is refused by the CALLERS of
 * naming_lookup() -- svc_proto.c handle_lookup() on a unit channel and
 * domain.c lookup_channel_request() on an ambient channel -- before the
 * name reaches the resolver.  naming_lookup() itself treats a helper name
 * like any other: an unregistered one is out of scope or on-demand-eligible
 * by the domain rule with nothing audited, and a registered one (a provider
 * that publishes it) goes through the ordinary anointment match.  The
 * upstream rule is exercised over a real channel in
 * lookup_helper_names_over_minted_channel.
 */
ATF_TC_WITHOUT_HEAD(lookup_helper_names_pure);
ATF_TC_BODY(lookup_helper_names_pure, tc)
{
	struct svc_runtime unit, provider;
	struct svc_domain session;
	int fd, error;

	audit_reset();
	unit_init(&unit, "com.example.app/app", NULL, 0);
	unit.domain.anoint.all = true;

	/* Unregistered helper name, SYSTEM kind: ENOENT, not audited. */
	error = 0;
	fd = naming_lookup("helper.org.example.Priv", &unit, &unit.domain,
	    NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(0U, audit_count);

	/* USER kind: out of scope (EACCES), not audited, `all` or not. */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	session.anoint.all = true;
	fd = naming_lookup("helper.org.example.Priv", NULL, &session, NULL,
	    &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(0U, audit_count);

	/* A helper name that is also "Control"-suffixed is not a control
	 * name: same service-plane answer. */
	fd = naming_lookup("helper.org.example.Control", &unit, &unit.domain,
	    NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(0U, audit_count);

	/*
	 * A registered helper name gated in the provider's own manifest (the
	 * registry does not know it): the ordinary match applies -- the
	 * non-holder is refused and audited, the holder connects.
	 */
	memset(&provider, 0, sizeof(provider));
	strlcpy(provider.manifest.label, "org.example.h/h",
	    sizeof(provider.manifest.label));
	strlcpy(provider.manifest.provides[0], "helper.org.example.Priv",
	    sizeof(provider.manifest.provides[0]));
	provider.manifest.nprovides = 1;
	provider.manifest.nrequires[0] = 1;
	requires_fill(provider.manifest.requires[0], NOTIFY_ONE, 1);
	provider.protocol_ready = true;
	provider.state = SVC_STATE_RUNNING;
	provider.channel_fd = 99;
	/* name_valid() accepts the helper form: it is an ordinary name here. */
	ATF_REQUIRE_EQ(0, naming_register("helper.org.example.Priv", &provider,
	    true));
	unit_init(&unit, "com.example.app/app", NULL, 0);
	fd = naming_lookup("helper.org.example.Priv", &unit, &unit.domain,
	    NULL, &error, NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	unit_init(&unit, "com.example.app/app", NOTIFY_ONE, 1);
	fd = naming_lookup("helper.org.example.Priv", &unit, &unit.domain,
	    NULL, &error, NULL);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(1U, audit_count);
	naming_remove_owner(&provider);
}

ATF_TC(lookup_helper_names_over_minted_channel);
ATF_TC_HEAD(lookup_helper_names_over_minted_channel, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "over a real minted session channel the reserved helper. "
	    "namespace is refused by the ambient lookup handler before the "
	    "anointment match: EACCES on the wire, nothing audited, even for "
	    "a session holding every anointment");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lookup_helper_names_over_minted_channel, tc)
{
	struct svc_anoint_set set;
	int all_fd, plain_fd, kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	want_real_channel = true;

	memset(&set, 0, sizeof(set));
	set.all = true;
	set.admin_rights = true;
	all_fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_SYSTEM, 0,
	    &set, &all_fd, kq));
	memset(&set, 0, sizeof(set));
	plain_fd = -1;
	require_real_channel(domain_mint_session_channel(SVC_DOMAIN_USER, 1001,
	    &set, &plain_fd, kq));

	audit_reset();
	ATF_CHECK_EQ(EACCES, lookup_over_channel(all_fd, kq,
	    "helper.org.example.Priv"));
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(EACCES, lookup_over_channel(plain_fd, kq,
	    "helper.org.example.Priv"));
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(EACCES, lookup_over_channel(all_fd, kq,
	    "helper.org.example.Control"));
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(0U, grant_count);

	domain_channel_teardown();
	close(all_fd);
	close(plain_fd);
	close(kq);
	want_real_channel = false;
}

/* ------------------------------------------------------------------ */
/* One refusal, one AUE_SWITCHBOARD_ANOINT record (anoint.c).           */
/* ------------------------------------------------------------------ */

/*
 * The caller contract every lookup site follows (svc_proto.c handle_lookup /
 * handle_helper_open, domain.c lookup_channel_request, on_demand.c
 * on_demand_broker): naming_lookup() first, and ONLY an ENOENT answer is
 * followed by the on-demand path, whose pre-check (od_anoint_precheck) is the
 * second refusal site.  An EACCES from naming_lookup() is final -- it is
 * never on-demanded -- so a lookup can be refused by at most one of the two.
 * EAGAIN stands in for "the launch was initiated; the reply is deferred".
 */
static int
lookup_then_activate(const char *name, struct svc_runtime *requester,
    const struct svc_domain *domain, const struct channel_sender *sender,
    int *errp)
{
	const struct svc_anoint_set *set;
	int fd;

	*errp = 0;
	fd = naming_lookup(name, requester, domain, sender, errp, NULL);
	if (fd >= 0)
		return (fd);
	if (*errp != ENOENT)
		return (-1);
	/* od_launch(): the requester's own set, else the ambient channel's. */
	if (requester != NULL)
		set = &requester->domain.anoint;
	else if (domain != NULL)
		set = &domain->anoint;
	else
		set = NULL;
	if (od_anoint_precheck(name, set, requester != NULL ?
	    requester->manifest.label : SVC_SESSION_LABEL,
	    sender != NULL ? (uid_t)sender->uid : getuid()) == -1) {
		*errp = EACCES;
		return (-1);
	}
	*errp = EAGAIN;
	return (-1);
}

ATF_TC_WITHOUT_HEAD(one_refusal_one_record_on_demand_path);
ATF_TC_BODY(one_refusal_one_record_on_demand_path, tc)
{
	struct svc_runtime provider, app, holder;
	struct svc_domain session;
	struct channel_sender sender;
	int fd, error;

	ATF_REQUIRE(!naming_exists(GATED_NAME));
	unit_init(&app, "com.example.app/app", NULL, 0);		/* U2 */
	unit_init(&holder, "com.example.pub/pub", NOTIFY_ONE, 1);	/* U1 */
	memset(&sender, 0, sizeof(sender));
	sender.uid = 4242;
	sender.nonce = 7;

	/*
	 * Provider stopped, non-holder unit.  naming_lookup() alone answers
	 * ENOENT (on-demand eligible) and records NOTHING: the registry is
	 * consulted, but the refusal belongs to the pre-check...
	 */
	audit_reset();
	fd = naming_lookup(GATED_NAME, &app, &app.domain, &sender, &error,
	    NULL);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(0U, audit_count);
	/* ...which then refuses with exactly one record, before any launch. */
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, &app, &app.domain, &sender,
	    &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(AUE_SWITCHBOARD_ANOINT, last_audit_event);
	ATF_CHECK_EQ(EACCES, last_audit_error);
	ATF_CHECK_EQ(4242, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: com.example.app/app -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);
	ATF_CHECK_EQ(0U, grant_count);

	/* Provider stopped, holder: no record on either side; the launch
	 * goes ahead. */
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, &holder, &holder.domain, &sender,
	    &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EAGAIN, error);
	ATF_CHECK_EQ(0U, audit_count);

	/*
	 * The provider comes up (the activation the holder started).  The
	 * post-activation resolve of that same lookup is a connect with zero
	 * records: the pre-check's decision is not re-audited.
	 */
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, &holder, &holder.domain, &sender,
	    &error);
	ATF_REQUIRE_MSG(fd >= 0, "holder not connected after activation: %d",
	    error);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	ATF_CHECK_EQ(1U, grant_count);

	/*
	 * Provider running, non-holder: naming_lookup() refuses EACCES with
	 * ONE record and -- EACCES not being ENOENT -- the pre-check is never
	 * reached.  The count stays at one across the whole caller sequence.
	 */
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, &app, &app.domain, &sender,
	    &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: com.example.app/app -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);
	ATF_CHECK_EQ(0U, grant_count);
	/* Repeating the refused lookup is a second refusal: still 1:1. */
	fd = lookup_then_activate(GATED_NAME, &app, &app.domain, &sender,
	    &error);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(2U, audit_count);
	naming_remove_owner(&provider);
	ATF_REQUIRE(!naming_exists(GATED_NAME));

	/*
	 * A login session (requester NULL, the set on the channel) on both
	 * sides of activation: one record each time, attributed to the
	 * session label and the stamped uid.
	 */
	memset(&session, 0, sizeof(session));
	session.kind = SVC_DOMAIN_USER;
	session.uid = 1001;
	sender.uid = 1001;
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, NULL, &session, &sender, &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(1001, last_audit_uid);
	ATF_CHECK_STREQ("anointment refused: org.5bsd.user-session -> "
	    GATED_NAME " missing " GATED_ANOINT, last_audit);
	provider_register(&provider, "system.Notify/bsdnotify", GATED_NAME,
	    NOTIFY_ONE, 1);
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, NULL, &session, &sender, &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_EQ(1001, last_audit_uid);
	/* The holder session: no record, a connect. */
	set_one(&session.anoint, GATED_ANOINT);
	audit_reset();
	fd = lookup_then_activate(GATED_NAME, NULL, &session, &sender, &error);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	naming_remove_owner(&provider);

	/* An all-of endpoint partially covered: one record naming the rest,
	 * on the pre-check path and on the resolve path alike. */
	ATF_REQUIRE(!naming_exists(BOTH_NAME));
	unit_init(&holder, "com.example.one/u", A_ONE, 1);		/* U6 */
	audit_reset();
	fd = lookup_then_activate(BOTH_NAME, &holder, &holder.domain, &sender,
	    &error);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: com.example.one/u -> " BOTH_NAME
	    " missing a.two", last_audit);
	provider_register(&provider, "system.X/x", BOTH_NAME, A_BOTH, 2);
	audit_reset();
	fd = lookup_then_activate(BOTH_NAME, &holder, &holder.domain, &sender,
	    &error);
	ATF_CHECK_EQ(EACCES, error);
	ATF_CHECK_EQ(1U, audit_count);
	ATF_CHECK_STREQ("anointment refused: com.example.one/u -> " BOTH_NAME
	    " missing a.two", last_audit);
	naming_remove_owner(&provider);

	/* An open endpoint never records on either path. */
	ATF_REQUIRE(!naming_exists(OPEN_USER_NAME));
	audit_reset();
	fd = lookup_then_activate(OPEN_USER_NAME, &app, &app.domain, &sender,
	    &error);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(EAGAIN, error);
	ATF_CHECK_EQ(0U, audit_count);
	provider_register(&provider, "system.Notify/bsdnotify", OPEN_USER_NAME,
	    NULL, 0);
	fd = lookup_then_activate(OPEN_USER_NAME, &app, &app.domain, &sender,
	    &error);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0U, audit_count);
	naming_remove_owner(&provider);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, covers_table);
	ATF_TP_ADD_TC(tp, set_from_manifest);
	ATF_TP_ADD_TC(tp, set_from_mint_valid);
	ATF_TP_ADD_TC(tp, set_from_mint_rejects);
	ATF_TP_ADD_TC(tp, endpoint_requires_from_registry);
	ATF_TP_ADD_TC(tp, unit_requires_from_manifest);
	ATF_TP_ADD_TC(tp, missing_rendering);
	ATF_TP_ADD_TC(tp, user_visibility_of_gated_names);
	ATF_TP_ADD_TC(tp, unit_covered_connects_with_identity);
	ATF_TP_ADD_TC(tp, unit_uncovered_refused_and_audited);
	ATF_TP_ADD_TC(tp, unit_all_of_several);
	ATF_TP_ADD_TC(tp, registry_wins_over_stale_unit_manifest);
	ATF_TP_ADD_TC(tp, session_sets);
	ATF_TP_ADD_TC(tp, rights_follow_admin_rights_knob);
	ATF_TP_ADD_TC(tp, self_control_requires_switchboard_admin);
	ATF_TP_ADD_TC(tp, on_demand_precheck);
	ATF_TP_ADD_TC(tp, unregistered_gated_name_is_ondemand_eligible);
	ATF_TP_ADD_TC(tp, minted_channel_carries_set);
	ATF_TP_ADD_TC(tp, session_reach_over_minted_channel);
	ATF_TP_ADD_TC(tp, registered_private_channel_keeps_set);
	ATF_TP_ADD_TC(tp, covers_duplicate_requires);
	ATF_TP_ADD_TC(tp, covers_at_set_bound);
	ATF_TP_ADD_TC(tp, covers_empty_name_semantics);
	ATF_TP_ADD_TC(tp, covers_prefix_suffix_case);
	ATF_TP_ADD_TC(tp, covers_all_flag_with_names);
	ATF_TP_ADD_TC(tp, set_from_manifest_bounds);
	ATF_TP_ADD_TC(tp, missing_rendering_max_names);
	ATF_TP_ADD_TC(tp, set_from_mint_name_lengths);
	ATF_TP_ADD_TC(tp, set_from_mint_embedded_nul);
	ATF_TP_ADD_TC(tp, set_from_mint_flags_matrix);
	ATF_TP_ADD_TC(tp, set_from_mint_all_with_names);
	ATF_TP_ADD_TC(tp, mint_req_wire_shape);
	ATF_TP_ADD_TC(tp, lookup_two_requires_partial_and_audit_count);
	ATF_TP_ADD_TC(tp, lookup_user_kind_unit_gated_visibility);
	ATF_TP_ADD_TC(tp, lookup_identity_without_stamp_and_linux_abi);
	ATF_TP_ADD_TC(tp, lookup_unit_never_admin_even_with_all);
	ATF_TP_ADD_TC(tp, lookup_session_admin_rights_without_reach);
	ATF_TP_ADD_TC(tp, lookup_self_control_holder_variants);
	ATF_TP_ADD_TC(tp, lookup_open_endpoint_no_set);
	ATF_TP_ADD_TC(tp, precheck_stopped_provider);
	ATF_TP_ADD_TC(tp, lookup_helper_names_pure);
	ATF_TP_ADD_TC(tp, lookup_helper_names_over_minted_channel);
	ATF_TP_ADD_TC(tp, one_refusal_one_record_on_demand_path);
	return (atf_no_error());
}
