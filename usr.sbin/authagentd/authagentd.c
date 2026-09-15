/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authagentd — the identity->capability mint boundary (system.authagent).
 *
 * A capsicum-sandboxed capability service.  A login program (login/su/sshd),
 * after authenticating a principal, connects to system.authagent and asks for
 * that session's capability bundle.  authagentd applies the principal policy
 * (capbundle_principal_resolve) and mints the scoped session lookup channel
 * over its OWN bootstrap channel to switchboard, then forwards it to the
 * login program.  The login program never holds mint authority itself.  See
 * docs/auth-agent-design.md.
 *
 * IPC anointments v1 (docs/ipc-anointments-design.md, "Domains and sessions"
 * and "Elevation"): the mint carries the principal's anointment set from
 * principal-policy.ucl, and a second operation, ELEVATE, is the sudo/doas
 * replacement -- a process on a session channel asks for ONE name from its
 * principal's `may_elevate`, authenticates against master.passwd inside the
 * agent, and receives a channel holding session-set-plus-one.
 */

#include <sys/types.h>
#include <sys/capsicum.h>	/* cap_xfer_limit, CAP_XFER_ONCE */
#include <sys/event.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>		/* crypt(3) */

#include <channel.h>
#include <libservice.h>
#include <libcapbundle.h>

#include <authagent_proto.h>

#include "authagentd_test.h"
#include "authagentd_probes.h"

#ifndef AUTHAGENTD_TESTING
#include <auditcmp.h>
#include <auditcmp_server.h>
#endif

/* Our own consumer handle on the bootstrap channel, used to mint. */
static struct service_context	*g_context;
static int			 g_kq = -1;
/*
 * The principal policy, delivered as a read-only descriptor (capabilities.open)
 * so the daemon never opens a path in capability mode.  -1 when absent, in
 * which case capbundle_principal_resolve applies the historical root-or-wheel
 * rule (root/wheel hold "*" with admin rights, everyone else nothing).
 */
static int			 g_policy_fd = -1;
/*
 * In-process NSS for authoritative passwd/group resolution inside the sandbox.
 * The agent NEVER trusts principal attributes from the wire — it resolves the
 * uid to its passwd and group membership itself, so a compromised login client
 * cannot claim admin membership it does not have.
 *
 * The Identity fold: rather than a Casper zygote (system.pwd/system.grp), the
 * agent retains read-only descriptors on /etc/passwd and /etc/group, opened
 * before it enters capability mode.  Capability mode forbids opening a path,
 * but lseek+read on an already-open descriptor is legal, so each lookup reads a
 * fresh snapshot from the top and parses it — authoritative, Casper-free, and
 * live (a user added to a group takes effect with no restart; unbuffered raw
 * reads, unlike a cached stdio stream).  We only need uid/name/gid (fields
 * 0,2,3 of passwd; 0,2,3 plus the member list of group), at the same offsets in
 * the 7-field public passwd and 10-field master.passwd, so the parse is
 * format-agnostic.
 */
static int			 g_pwfd = -1;	/* /etc/passwd, read-only */
static int			 g_grfd = -1;	/* /etc/group, read-only */
/*
 * ELEVATE authenticates the caller inside the agent (PAM module stacks cannot
 * run in the sandbox).  A read-only descriptor on /etc/master.passwd, retained
 * the same way, supplies the password hash; the snapshot is zeroed after
 * every verification.  -1 when tzfsd did not grant it: ELEVATE then fails
 * closed (ENXIO), MINT is unaffected.
 */
static int			 g_mpwfd = -1;	/* /etc/master.passwd, read-only */

/*
 * Bounded per-lookup snapshots.  Independent buffers, never used
 * concurrently: the provider serves requests serially from one kqueue loop,
 * so file-scope statics are safe and avoid large stack frames.
 */
#define	ID_SNAP_MAX	(128 * 1024)
static char			 g_pwbuf[ID_SNAP_MAX];
static char			 g_grbuf[ID_SNAP_MAX];
static char			 g_mpwbuf[ID_SNAP_MAX];

/* The per-uid ELEVATE failure limiter (in memory; lost on restart). */
static struct authagent_ratelimit g_ratelimit;

/*
 * BSM audit (AUE_AUTHAGENT_ELEVATE / AUE_AUTHAGENT_MINT) is committed through
 * system.Audit (libauditcmp): the agent runs in capability mode and cannot
 * reach the audit pipe itself, and auditbrokerd maps the operation's first
 * path component to the event class (auditcmp_policy.c).  The session is
 * opened lazily from the request path, over the lookup channel the agent
 * holds in capability mode, the first time a record is due -- never at
 * start-up: authagentd is on the login critical path (every session's
 * lookup channel is minted here) and system.Audit comes up beside it, so
 * waiting for the broker before checking in would make the console autologin
 * and early ssh sessions lose their channel on a slow boot.  If system.Audit
 * is not up or the session later dies, the record is dropped with a syslog
 * line and the open is retried at most once every AUDIT_RETRY_SEC: no hard
 * dependency, and the LOG_AUTHPRIV syslog lines stay in every case.  For the
 * same reason the record is committed right AFTER the reply, so a slow broker
 * (each submit is bounded by libauditcmp) delays the next request, never the
 * one it describes.  The test build has no broker; it gets a hook instead.
 *
 * The wire allows only [A-Za-z0-9._/-] in the subject and the operation, 64
 * bytes each, so a record is
 *   subject    "<caller label>/uid<N>"        (label truncated to fit)
 *   operation  "elevate/<stage>/<name>"       (name dropped if it cannot fit)
 *              "mint/<kind>/n<count>[/all][/admin][/default]"
 *              "mint/<stage>"                 (refused before a grant)
 * and the result is the reply status.  Never the password.
 */
#define	AUDIT_RETRY_SEC		5
#define	AGENT_AUDIT_MAX		64
#ifndef AUTHAGENTD_TESTING
_Static_assert(AGENT_AUDIT_MAX == AUDITCMP_MAX_SUBJECT &&
    AGENT_AUDIT_MAX == AUDITCMP_MAX_OPERATION,
    "audit subject/operation buffers must match the system.Audit wire");
static struct auditcmp_client	*g_audit;
static time_t			 g_audit_retry_at;
#else
static authagentd_test_audit_fn	 g_audit_hook;
#endif

_Static_assert(CAPBUNDLE_LABEL_MAX == SERVICE_ANOINT_NAME_MAX,
    "principal grant names must be passable to the mint unchanged");
_Static_assert(CAPBUNDLE_PRINCIPAL_MAX_NAMES == SERVICE_ANOINT_MAX,
    "principal grant set bound must equal the mint set bound");
_Static_assert(AUTHAGENT_NAME_MAX == SERVICE_ANOINT_NAME_MAX,
    "elevate request name bound must equal the mint name bound");

#ifndef AUTHAGENTD_TESTING
/*
 * Open the identity databases.  authagentd is born in capability mode, so it
 * cannot open a path itself; it obtains read-only, seekable (CAP_READ|CAP_SEEK,
 * for the per-lookup pread snapshots) descriptors on demand through the
 * filesystem provider (service_open_isolated(3)), authorized by tzfsd's
 * per-label open policy.  Returns 0, or -1 with the descriptor(s) left -1 (a
 * resolution then fails closed -> the mint is denied).  Only main() calls this.
 */
static int
id_open_databases(void)
{
	int error;

	if (service_open_isolated(g_context, "/etc/passwd", SERVICE_OPEN_READ,
	    0, &g_pwfd) == -1 ||
	    service_open_isolated(g_context, "/etc/group", SERVICE_OPEN_READ,
	    0, &g_grfd) == -1) {
		error = errno;
		if (g_pwfd >= 0)
			close(g_pwfd);
		if (g_grfd >= 0)
			close(g_grfd);
		g_pwfd = g_grfd = -1;
		return (errno = error, -1);
	}
	return (0);
}
#endif /* !AUTHAGENTD_TESTING */

/*
 * Read the retained descriptor from the top into buf as a fresh, NUL-terminated
 * snapshot.  Returns its length, or -1.  An oversized file is rejected in
 * full so a truncated final record can never become a valid identity.
 */
static ssize_t
id_snapshot(int fd, char *buf, size_t bufsz)
{
	char extra;
	size_t off;
	ssize_t n;

	if (fd == -1 || buf == NULL || bufsz < 2)
		return (errno = EINVAL, -1);
	if (lseek(fd, 0, SEEK_SET) == -1)
		return (-1);
	off = 0;
	while (off < bufsz - 1) {
		n = read(fd, buf + off, bufsz - 1 - off);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	if (off == bufsz - 1) {
		do {
			n = read(fd, &extra, sizeof(extra));
		} while (n == -1 && errno == EINTR);
		if (n == -1)
			return (-1);
		if (n != 0)
			return (errno = EOVERFLOW, -1);
	}
	buf[off] = '\0';
	return ((ssize_t)off);
}

/* Parse a canonical unsigned decimal uid/gid without signs or whitespace. */
static bool
id_parse_number(const char *text, uintmax_t maximum, uintmax_t *valuep)
{
	uintmax_t value;
	unsigned int digit;

	if (text == NULL || text[0] == '\0' || valuep == NULL)
		return (false);
	value = 0;
	for (; *text != '\0'; text++) {
		if (*text < '0' || *text > '9')
			return (false);
		digit = (unsigned int)(*text - '0');
		if (value > (maximum - digit) / 10)
			return (false);
		value = value * 10 + digit;
	}
	*valuep = value;
	return (true);
}

/* uid -> passwd (name/uid/gid only), from /etc/passwd.  NULL if not found. */
static struct passwd *
id_getpwuid(uid_t uid)
{
	static struct passwd pw;
	static char namebuf[MAXLOGNAME + 1];
	char *cursor, *line, *p, *f_name, *f_uid, *f_gid;
	uintmax_t parsed_uid, parsed_gid;

	if (id_snapshot(g_pwfd, g_pwbuf, sizeof(g_pwbuf)) == -1)
		return (NULL);
	cursor = g_pwbuf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		(void)strsep(&p, ":");		/* password field, ignored */
		f_uid = strsep(&p, ":");
		f_gid = strsep(&p, ":");
		if (f_name == NULL || f_name[0] == '\0' ||
		    strlen(f_name) > MAXLOGNAME ||
		    !id_parse_number(f_uid, UID_MAX, &parsed_uid) ||
		    !id_parse_number(f_gid, GID_MAX, &parsed_gid))
			continue;
		if ((uid_t)parsed_uid != uid)
			continue;
		(void)strlcpy(namebuf, f_name, sizeof(namebuf));
		memset(&pw, 0, sizeof(pw));
		pw.pw_name = namebuf;
		pw.pw_uid = uid;
		pw.pw_gid = (gid_t)parsed_gid;
		return (&pw);
	}
	return (NULL);
}

#ifndef AUTHAGENTD_TESTING
/* name -> uid, from /etc/passwd.  Used once at startup; false if absent. */
static bool
id_getpwnam_uid(const char *name, uid_t *uidp)
{
	char *cursor, *line, *p, *f_name, *f_uid;
	uintmax_t parsed_uid;

	if (id_snapshot(g_pwfd, g_pwbuf, sizeof(g_pwbuf)) == -1)
		return (false);
	cursor = g_pwbuf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		(void)strsep(&p, ":");		/* password field, ignored */
		f_uid = strsep(&p, ":");
		if (f_name == NULL || strcmp(f_name, name) != 0 ||
		    !id_parse_number(f_uid, UID_MAX, &parsed_uid))
			continue;
		*uidp = (uid_t)parsed_uid;
		return (true);
	}
	return (false);
}
#endif /* !AUTHAGENTD_TESTING */

/* Group-name -> gid for the policy engine, from /etc/group.  -1 if absent. */
static gid_t
agent_name2gid(void *ctx __unused, const char *name)
{
	char *cursor, *line, *p, *f_name, *f_gid;
	uintmax_t parsed_gid;

	if (name == NULL ||
	    id_snapshot(g_grfd, g_grbuf, sizeof(g_grbuf)) == -1)
		return ((gid_t)-1);
	cursor = g_grbuf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		(void)strsep(&p, ":");		/* password field, ignored */
		f_gid = strsep(&p, ":");
		if (f_name == NULL || f_name[0] == '\0' ||
		    !id_parse_number(f_gid, GID_MAX, &parsed_gid))
			continue;
		if (strcmp(f_name, name) == 0)
			return ((gid_t)parsed_gid);
	}
	return ((gid_t)-1);
}

/*
 * Resolve a principal's group membership authoritatively: its primary gid plus
 * every group whose member list names it.  Scan /etc/group (a mint is
 * infrequent), same as the former cap_grp enumeration.
 */
static unsigned
agent_member_gids(const struct passwd *pw, gid_t *out, unsigned max)
{
	char *cursor, *line, *p, *f_gid, *members, *m, *save;
	uintmax_t parsed_gid;
	gid_t gid;
	unsigned n;

	if (pw == NULL || out == NULL || max == 0)
		return (0);
	n = 0;
	out[n++] = pw->pw_gid;
	if (id_snapshot(g_grfd, g_grbuf, sizeof(g_grbuf)) == -1)
		return (n);
	cursor = g_grbuf;
	while (n < max && (line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		(void)strsep(&p, ":");		/* group name, ignored */
		(void)strsep(&p, ":");		/* password field, ignored */
		f_gid = strsep(&p, ":");
		members = p;			/* remainder: comma-separated */
		if (members == NULL ||
		    !id_parse_number(f_gid, GID_MAX, &parsed_gid))
			continue;
		gid = (gid_t)parsed_gid;
		if (gid == pw->pw_gid)		/* primary already recorded */
			continue;
		for (m = strtok_r(members, ",", &save); m != NULL;
		    m = strtok_r(NULL, ",", &save)) {
			if (strcmp(m, pw->pw_name) == 0) {
				out[n++] = gid;
				break;
			}
		}
	}
	return (n);
}

/*
 * Resolve the grant for a uid: passwd -> member gids -> principal policy.
 * Returns 0, or ENOENT when the uid has no passwd entry (the grant is then
 * untouched).  Both MINT and ELEVATE go through here so the two operations can
 * never disagree about what a principal holds.
 */
static int
agent_resolve_grant(uid_t uid, struct capbundle_principal_grant *grant)
{
	gid_t members[NGROUPS_MAX];
	struct passwd *pw;
	unsigned nmember;

	pw = id_getpwuid(uid);
	if (pw == NULL)
		return (ENOENT);
	nmember = agent_member_gids(pw, members, nitems(members));
	if (capbundle_principal_resolve(g_policy_fd, uid, members, nmember,
	    agent_name2gid, NULL, grant) == -1)
		return (errno != 0 ? errno : EINVAL);
	AUTHAGENT_PROBE_POLICY_RESOLVE(uid, grant->nanointments,
	    grant->anoint_all, grant->admin_rights, grant->from_default_rule);
	return (0);
}

/*
 * One connected caller.  The channel's fd is the kqueue key; udata
 * distinguishes it from the listener (whose udata is the listener pointer).
 */
struct client {
	TAILQ_ENTRY(client)	entry;
	int			fd;
	struct channel		*chan;
	/*
	 * The connecting caller's identity, as stamped by switchboard when it
	 * brokered this connection (naming.c) and delivered by
	 * service_listener_accept().  The MINT gate in handle_request()
	 * consults `rights`; the ELEVATE gate consults `client_label` (a
	 * session, never a unit); both log the label for audit.
	 */
	service_rights_t	rights;
	char			client_label[64];
};
static TAILQ_HEAD(, client) clients = TAILQ_HEAD_INITIALIZER(clients);

/*
 * The mint caller-gate predicate (docs/auth-agent-design.md, P1c), factored out
 * of handle_request() so the privilege-escalation regression is unit-testable
 * without a live plane.  A caller may ask us to mint iff switchboard stamped
 * SERVICE_RIGHTS_ADMIN on its brokered session — the bit switchboard (naming.c)
 * grants only to an ambient login-session lookup (requester==NULL) on a
 * full-discovery (root/wheel) channel, i.e. exactly and only the login family
 * (login/su/sshd).  Every ordinary unit, including a compromised SYSTEM unit
 * that looks us up over its own bootstrap channel, is stamped without the admin
 * bit and refused.  Fail closed: an unknown or empty identity (no rights) is
 * denied.  The gate logic is identical to its former inline form.
 */
bool
authagent_caller_allowed(service_rights_t rights)
{

	return (service_rights_allow(rights, SERVICE_RIGHTS_ADMIN));
}

/*
 * The SYSTEM-vs-USER decision for a resolved grant.  A principal that holds
 * "*" or carries admin rights mints a full-discovery SYSTEM channel; every
 * other principal mints a per-uid USER channel that carries its (possibly
 * empty) anointment set.  Pure.
 */
enum service_mint_kind
authagent_mint_kind_for_grant(const struct capbundle_principal_grant *grant)
{

	if (grant == NULL)
		return (SERVICE_MINT_USER);
	return ((grant->admin_rights || grant->anoint_all) ?
	    SERVICE_MINT_SYSTEM : SERVICE_MINT_USER);
}

/*
 * The SYSTEM-vs-USER mint decision, factored for unit testing.  Pure: the
 * caller supplies the resolved member gids and a group-name resolver, exactly
 * as handle_request() does from the retained identity databases.  Now
 * grant-based: it is authagent_mint_kind_for_grant() over the resolved grant.
 */
enum service_mint_kind
authagent_mint_kind(int policy_fd, uid_t uid, const gid_t *member_gids,
    unsigned nmember, capbundle_group_gid_fn name2gid, void *ctx)
{
	struct capbundle_principal_grant grant;

	if (capbundle_principal_resolve(policy_fd, uid, member_gids, nmember,
	    name2gid, ctx, &grant) == -1)
		return (SERVICE_MINT_USER);	/* fail closed */
	return (authagent_mint_kind_for_grant(&grant));
}

/*
 * ELEVATE caller gate (docs/ipc-anointments-design.md "Elevation", step 1;
 * scenario E5).  Only a process on a login-session channel may elevate: its
 * brokered connection is stamped with the session label switchboard uses for
 * an ambient (requester == NULL) lookup.  A unit -- whose label is its
 * bundle's -- is refused: units declare their anointments in their policy
 * file, they do not elevate.  Fail closed on an empty/unknown label.
 */
bool
authagent_elevate_caller_allowed(const char *client_label)
{

	return (client_label != NULL &&
	    strcmp(client_label, AUTHAGENT_SESSION_LABEL) == 0);
}

/*
 * An anointment name as the wire and the policy accept it: reverse-domain
 * syntax ([A-Za-z0-9._-], at least one dot, no leading/trailing/doubled dot),
 * shorter than maxlen.  "*" is a policy-file wildcard, never a name a caller
 * may ask for.  Mirrors libcapbundle's service-name rule.
 */
bool
authagent_valid_name(const char *name, size_t maxlen)
{
	const unsigned char *p;
	size_t len;
	bool has_dot;

	if (name == NULL)
		return (false);
	len = strnlen(name, maxlen);
	if (len == 0 || len >= maxlen || name[0] == '.' ||
	    name[len - 1] == '.')
		return (false);
	has_dot = false;
	for (p = (const unsigned char *)name; *p != '\0'; p++) {
		if (*p == '.') {
			if (p > (const unsigned char *)name && p[-1] == '.')
				return (false);
			has_dot = true;
		} else if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
			return (false);
	}
	return (has_dot);
}

/*
 * ELEVATE policy check (step 2; scenarios S6, P5).  `name` must be in the
 * principal's may_elevate (or the entry has "*").  Returns 0 or EPERM.  Pure;
 * runs BEFORE any password is looked at.
 */
int
authagent_elevate_check(const struct capbundle_principal_grant *grant,
    const char *name)
{

	if (grant == NULL || name == NULL)
		return (EPERM);
	return (capbundle_principal_may_elevate(grant, name) ? 0 : EPERM);
}

/*
 * In-agent password verification (step 3; scenarios P3, P4).  `masterpw` is
 * a mutable, NUL-terminated master.passwd snapshot
 * (name:hash:uid:gid:class:change:expire:gecos:home:shell); the first record
 * whose uid field is `uid` supplies the hash.  Returns:
 *   0       crypt(password, hash) == hash (compared in constant time)
 *   EACCES  the password does not match
 *   EPERM   the account cannot authenticate at all: empty hash, or locked
 *           ("*" / "!" prefixed) -- refused without consulting crypt(3)
 *   ENOENT  no record for the uid (malformed lines are skipped)
 *   EINVAL  null argument
 * The caller owns the snapshot and must zero it afterwards; this function
 * zeroes nothing but also retains nothing.  Pure apart from crypt(3), which
 * needs no files and works in capability mode.
 */
int
authagent_verify_password(char *masterpw, uid_t uid, const char *password)
{
	char *cursor, *line, *p, *f_name, *f_hash, *f_uid, *computed;
	uintmax_t parsed_uid;
	size_t hash_len;

	if (masterpw == NULL || password == NULL)
		return (EINVAL);
	cursor = masterpw;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		f_hash = strsep(&p, ":");
		f_uid = strsep(&p, ":");
		if (f_name == NULL || f_name[0] == '\0' || f_hash == NULL ||
		    f_uid == NULL ||
		    !id_parse_number(f_uid, UID_MAX, &parsed_uid))
			continue;		/* malformed: skip, never match */
		if ((uid_t)parsed_uid != uid)
			continue;
		hash_len = strlen(f_hash);
		if (hash_len == 0 || f_hash[0] == '*' || f_hash[0] == '!')
			return (EPERM);
		computed = crypt(password, f_hash);
		if (computed == NULL || strlen(computed) != hash_len ||
		    timingsafe_bcmp(computed, f_hash, hash_len) != 0)
			return (EACCES);
		return (0);
	}
	return (ENOENT);
}

/*
 * Per-uid failure limiter (step 3, "repeated failures for a uid are
 * rate-limited").  After AUTHAGENT_RL_MAX_FAILURES failures within
 * AUTHAGENT_RL_WINDOW_SEC of the first, the uid is refused (EAGAIN) without
 * any password check until the window has elapsed; a success clears it.  The
 * clock is a caller-supplied monotonic second so the policy is testable.
 * Slots are a small fixed table; when full, the stalest slot is recycled.
 */
static struct authagent_ratelimit_slot *
ratelimit_find(struct authagent_ratelimit *rl, uid_t uid)
{
	unsigned i;

	for (i = 0; i < nitems(rl->slots); i++)
		if (rl->slots[i].used && rl->slots[i].uid == uid)
			return (&rl->slots[i]);
	return (NULL);
}

/* Failures recorded for a uid in its current window (0 if none), for tracing. */
static unsigned
ratelimit_failures(struct authagent_ratelimit *rl, uid_t uid)
{
	const struct authagent_ratelimit_slot *slot;

	slot = rl != NULL ? ratelimit_find(rl, uid) : NULL;
	return (slot != NULL ? slot->failures : 0);
}

static bool
ratelimit_expired(const struct authagent_ratelimit_slot *slot, time_t now)
{

	return (now < slot->window_start ||
	    now - slot->window_start >= AUTHAGENT_RL_WINDOW_SEC);
}

bool
authagent_ratelimit_blocked(struct authagent_ratelimit *rl, uid_t uid,
    time_t now)
{
	struct authagent_ratelimit_slot *slot;

	if (rl == NULL)
		return (false);
	slot = ratelimit_find(rl, uid);
	if (slot == NULL)
		return (false);
	if (ratelimit_expired(slot, now)) {
		memset(slot, 0, sizeof(*slot));
		return (false);
	}
	return (slot->failures >= AUTHAGENT_RL_MAX_FAILURES);
}

void
authagent_ratelimit_failure(struct authagent_ratelimit *rl, uid_t uid,
    time_t now)
{
	struct authagent_ratelimit_slot *slot, *victim;
	unsigned i;

	if (rl == NULL)
		return;
	slot = ratelimit_find(rl, uid);
	if (slot == NULL) {
		victim = NULL;
		for (i = 0; i < nitems(rl->slots); i++) {
			if (!rl->slots[i].used ||
			    ratelimit_expired(&rl->slots[i], now)) {
				victim = &rl->slots[i];
				break;
			}
			if (victim == NULL ||
			    rl->slots[i].window_start < victim->window_start)
				victim = &rl->slots[i];
		}
		slot = victim;
		memset(slot, 0, sizeof(*slot));
		slot->used = true;
		slot->uid = uid;
	} else if (ratelimit_expired(slot, now)) {
		slot->failures = 0;
	}
	if (slot->failures == 0)
		slot->window_start = now;
	if (slot->failures < UINT_MAX)
		slot->failures++;
}

void
authagent_ratelimit_success(struct authagent_ratelimit *rl, uid_t uid)
{
	struct authagent_ratelimit_slot *slot;

	if (rl == NULL)
		return;
	slot = ratelimit_find(rl, uid);
	if (slot != NULL)
		memset(slot, 0, sizeof(*slot));
}

/*
 * The set an elevated channel carries (step 4; scenario E1): the principal's
 * policy set plus `name`, deduplicated.  A principal holding "*" already
 * holds `name`: the result is "all" with an empty list (*nout = 0, *all =
 * true).  Returns 0, or E2BIG when the list is full and `name` is not
 * already in it, or EINVAL.
 */
int
authagent_compose_set(const struct capbundle_principal_grant *grant,
    const char *name, char (*out)[SERVICE_ANOINT_NAME_MAX], unsigned max,
    unsigned *nout, bool *all)
{
	unsigned i, n;

	if (grant == NULL || name == NULL || out == NULL || nout == NULL ||
	    all == NULL || grant->nanointments > max)
		return (EINVAL);
	*nout = 0;
	*all = grant->anoint_all;
	if (grant->anoint_all)
		return (0);
	n = 0;
	for (i = 0; i < grant->nanointments; i++) {
		if (strlcpy(out[n], grant->anointments[i],
		    SERVICE_ANOINT_NAME_MAX) >= SERVICE_ANOINT_NAME_MAX)
			return (EINVAL);
		n++;
	}
	if (capbundle_principal_holds(grant, name)) {
		*nout = n;
		return (0);
	}
	if (n >= max)
		return (E2BIG);
	if (strlcpy(out[n], name, SERVICE_ANOINT_NAME_MAX) >=
	    SERVICE_ANOINT_NAME_MAX)
		return (EINVAL);
	*nout = n + 1;
	return (0);
}

#ifndef AUTHAGENTD_TESTING
static void
client_destroy(struct client *c)
{
	struct kevent kev;

	EV_SET(&kev, c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
	EV_SET(&kev, c->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
	if (c->chan != NULL)
		channel_destroy(c->chan);
	TAILQ_REMOVE(&clients, c, entry);
	free(c);
}
#endif /* !AUTHAGENTD_TESTING */

/* Track the channel's queued-output state in the kqueue write filter. */
static void
client_sync_events(struct client *c)
{
	struct kevent kev;
	int wants;

	wants = channel_wants_write(c->chan);
	if (wants == -1)
		return;
	EV_SET(&kev, c->fd, EVFILT_WRITE,
	    EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0, 0, c);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
}

static time_t
monotonic_seconds(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return (0);
	return (ts.tv_sec);
}

/*
 * Everything one request's decision leaves behind for the probes and the
 * audit record: filled by handle_mint()/handle_elevate(), consumed by
 * handle_request() once the decision is made.  Never the password.
 */
struct request_trace {
	uint32_t	uid;		/* principal uid; UINT32_MAX if unknown */
	uint32_t	flags;		/* MINT request flags */
	int		kind;		/* MINT: service_mint_kind, -1 undecided */
	const char	*stage;		/* decision stage the outcome came from */
	char		name[AUTHAGENT_NAME_MAX];	/* ELEVATE name */
	bool		have_grant;	/* the grant shape below is meaningful */
	unsigned	nanointments;	/* policy set size (mint) */
	bool		all;
	bool		admin_rights;
	bool		from_default_rule;
};

static void
request_trace_init(struct request_trace *t)
{

	memset(t, 0, sizeof(*t));
	t->uid = UINT32_MAX;
	t->kind = -1;
	t->stage = "caller";
}

static void
agent_audit(const char *subject, const char *operation, int error)
{
#ifdef AUTHAGENTD_TESTING
	if (g_audit_hook != NULL)
		g_audit_hook(subject, operation, error);
#else
	time_t now;
	int saved;

	if (g_audit == NULL) {
		now = monotonic_seconds();
		if (now < g_audit_retry_at)
			goto dropped;
		g_audit_retry_at = now + AUDIT_RETRY_SEC;
		if (auditcmp_client_open(&g_audit) == -1) {
			g_audit = NULL;
			syslog(LOG_AUTHPRIV | LOG_WARNING,
			    "audit: system.Audit unavailable (%m); records "
			    "are dropped until it answers");
			goto dropped;
		}
	}
	if (auditcmp_submit(g_audit, subject, operation, error) == 0)
		return;
	saved = errno;
	syslog(LOG_AUTHPRIV | LOG_WARNING, "audit: %s %s result=%d: %m",
	    subject, operation, error);
	if (saved != EAGAIN && saved != EINVAL) {
		/* The broker session is gone (restart?): reconnect lazily. */
		auditcmp_client_close(g_audit);
		g_audit = NULL;
		g_audit_retry_at = monotonic_seconds() + AUDIT_RETRY_SEC;
	}
	return;
dropped:
	syslog(LOG_AUTHPRIV | LOG_WARNING,
	    "audit: record dropped (system.Audit unavailable): %s %s result=%d",
	    subject, operation, error);
#endif
}

/* "<label>/uid<N>", the label cut so the uid always fits; label-only if unknown. */
static void
agent_audit_subject(char *buf, size_t buflen, const char *label,
    size_t labelmax, uint32_t uid)
{
	size_t labellen, keep;

	if (label == NULL || label[0] == '\0') {
		label = "unknown";
		labelmax = strlen(label);
	}
	labellen = strnlen(label, labelmax);
	keep = buflen - 1 - strlen("/uid4294967295");
	if (labellen > keep)
		labellen = keep;
	if (uid == UINT32_MAX)
		(void)snprintf(buf, buflen, "%.*s", (int)labellen, label);
	else
		(void)snprintf(buf, buflen, "%.*s/uid%u", (int)labellen, label,
		    (unsigned)uid);
}

static void
agent_audit_elevate(const struct client *c, const struct request_trace *t,
    int status)
{
	char subject[AGENT_AUDIT_MAX + 1], operation[AGENT_AUDIT_MAX + 1];

	agent_audit_subject(subject, sizeof(subject), c->client_label,
	    sizeof(c->client_label), t->uid);
	if (t->name[0] == '\0') {
		(void)snprintf(operation, sizeof(operation), "elevate/%s",
		    t->stage);
		agent_audit(subject, operation, status);
		return;
	}
	if (snprintf(operation, sizeof(operation), "elevate/%s/%s", t->stage,
	    t->name) < (int)sizeof(operation)) {
		agent_audit(subject, operation, status);
		return;
	}
	/*
	 * The name does not fit beside the stage in the 64-byte operation
	 * field (any name past ~48 characters).  Never lose it from the trail:
	 * commit the stage record, then a second record whose operation is the
	 * bare name.  A name never contains '/', so it cannot be mistaken for
	 * an "elevate/..." or "mint/..." operation.
	 */
	(void)snprintf(operation, sizeof(operation), "elevate/%s", t->stage);
	agent_audit(subject, operation, status);
	(void)snprintf(operation, sizeof(operation), "%s", t->name);
	agent_audit(subject, operation, status);
}

static void
agent_audit_mint(const struct client *c, const struct request_trace *t,
    int status)
{
	char subject[AGENT_AUDIT_MAX + 1], operation[AGENT_AUDIT_MAX + 1];

	agent_audit_subject(subject, sizeof(subject), c->client_label,
	    sizeof(c->client_label), t->uid);
	if (!t->have_grant)
		(void)snprintf(operation, sizeof(operation), "mint/%s",
		    t->stage);
	else
		(void)snprintf(operation, sizeof(operation),
		    "mint/%s/n%u%s%s%s",
		    t->kind == (int)SERVICE_MINT_SYSTEM ? "system" : "user",
		    t->nanointments, t->all ? "/all" : "",
		    t->admin_rights ? "/admin" : "",
		    t->from_default_rule ? "/default" : "");
	agent_audit(subject, operation, status);
}

/*
 * Serve one AUTHAGENT_OP_MINT_SESSION request.  No credential is trusted from
 * the wire: the scope is derived from policy applied to the named principal.
 * The minted fd is delivered transferable by switchboard (RESEND) and
 * re-attenuated here to CAP_XFER_ONCE, so the single reply send consumes it to
 * CAP_XFER_NONE at the login program — the session leaf cannot re-delegate its
 * lookup channel.  Returns the reply status; *fdp is the minted channel on 0.
 */
static int
handle_mint(struct client *c, const void *data, size_t len, size_t nfds,
    int *fdp, struct request_trace *t)
{
	const struct authagent_mint_req *req;
	struct capbundle_principal_grant grant;
	enum service_mint_kind kind;
	bool forwardable;
	int error, fd, status;

	/*
	 * Caller gate — the mint boundary (docs/auth-agent-design.md, P1c).
	 * authagentd gates the MINTER (only its own whitelisted bootstrap
	 * channel can call switchboard's SVC_OP_MINT_DOMAIN), but that says
	 * nothing about WHO may ask us to mint.  system.authagent is now
	 * reachable from every session (resolvable_by user, for ELEVATE), so
	 * any session or SYSTEM unit could otherwise send MINT_SESSION{uid=0}
	 * and be handed a SYSTEM admin channel — the exact proxy escalation
	 * the switchboard mint-gate was written to close.
	 *
	 * In this OS authority is a held right, not a name string.  switchboard
	 * (naming.c) stamps SERVICE_RIGHTS_ADMIN on a brokered session only for
	 * an ambient login-session lookup (requester==NULL) on a SYSTEM
	 * (full-discovery, i.e. root/wheel) channel — which is exactly, and only,
	 * the channel the login family (login, su, sshd) reaches us over.  Every
	 * ordinary unit — including a compromised SYSTEM unit that looks us up
	 * over its own bootstrap channel — is stamped requester!=NULL and thus
	 * WITHOUT the admin bit.  Gate on that right and fail closed: any caller
	 * that does not hold SERVICE_RIGHTS_ADMIN (unknown/empty identity
	 * included) is refused before we mint or even parse the request.
	 */
	if (!authagent_caller_allowed(c->rights)) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "mint denied: caller '%.*s' lacks authenticator authority",
		    (int)sizeof(c->client_label), c->client_label);
		t->stage = "caller";
		return (EPERM);
	}
	t->stage = "shape";
	if (nfds != 0 || data == NULL || len != sizeof(*req))
		return (EINVAL);
	req = data;
	t->uid = req->uid;
	t->flags = req->flags;
	if (req->version != AUTHAGENTD_PROTO_VERSION ||
	    req->op != AUTHAGENT_OP_MINT_SESSION ||
	    (req->flags & ~AUTHAGENT_FLAG_FORWARDABLE) != 0)
		return (EINVAL);
	t->stage = "identity";
	error = agent_resolve_grant((uid_t)req->uid, &grant);
	if (error != 0)
		return (error);
	forwardable = (req->flags & AUTHAGENT_FLAG_FORWARDABLE) != 0;
	kind = authagent_mint_kind_for_grant(&grant);
	t->kind = (int)kind;
	t->have_grant = true;
	t->nanointments = grant.nanointments;
	t->all = grant.anoint_all;
	t->admin_rights = grant.admin_rights;
	t->from_default_rule = grant.from_default_rule;
	t->stage = "mint";

	/*
	 * A session leaf (login/su) receives the channel non-transferable:
	 * attenuate to CAP_XFER_ONCE so the reply's own SCM_RIGHTS send
	 * consumes it to CAP_XFER_NONE at the caller.  A forwarding caller
	 * (sshd monitor) receives it still-transferable and re-attenuates
	 * before its own single forward.
	 */
	fd = -1;
	if (service_context_mint_domain_anointed(g_context, kind,
	    (uid_t)req->uid,
	    (const char (*)[SERVICE_ANOINT_NAME_MAX])grant.anointments,
	    grant.nanointments, grant.anoint_all, grant.admin_rights,
	    &fd) == 0 && fd >= 0 &&
	    (forwardable || cap_xfer_limit(fd, CAP_XFER_ONCE) == 0)) {
		status = 0;
		*fdp = fd;
		t->stage = "ok";
	} else {
		status = errno != 0 ? errno : EIO;
		if (fd >= 0)
			close(fd);
	}
	/*
	 * Log which grant applied (no secrets): the kind, whether the
	 * historical rule stood in for a missing/malformed policy (P10), and
	 * the shape of the set.  The policy engine does not surface the
	 * matching entry's key, so the grant's shape is what is logged.
	 */
	syslog(LOG_INFO,
	    "mint %s uid=%u caller='%.*s' anointments=%s%u may_elevate=%s%u "
	    "admin_rights=%d%s -> %d",
	    kind == SERVICE_MINT_SYSTEM ? "system" : "user",
	    (unsigned)req->uid, (int)sizeof(c->client_label), c->client_label,
	    grant.anoint_all ? "*+" : "", grant.nanointments,
	    grant.elevate_all ? "*+" : "", grant.nmay_elevate,
	    grant.admin_rights ? 1 : 0,
	    grant.from_default_rule ? " (policy absent: historical rule)" : "",
	    status);
	return (status);
}

/*
 * Serve one AUTHAGENT_OP_ELEVATE request (docs/ipc-anointments-design.md
 * "Elevation").  The caller's uid comes ONLY from the kernel-stamped sender
 * credential on the message (E4); the payload contributes the requested name
 * and the password for the caller's own account, nothing else.  Order of
 * checks, each audited: session label (E5) -> shape -> policy (S6/P5, before
 * any password) -> rate limit -> password (P3/P4) -> mint session-plus-one
 * (E1).  Returns the reply status; *fdp is the minted channel on 0.
 */
static int
handle_elevate(struct client *c, struct channel_message *request,
    const void *data, size_t len, size_t nfds, int *fdp,
    struct request_trace *t)
{
	struct authagent_elevate_req req;
	struct capbundle_principal_grant grant;
	char names[SERVICE_ANOINT_MAX][SERVICE_ANOINT_NAME_MAX];
	const struct channel_sender *sender;
	enum service_mint_kind kind;
	uid_t uid;
	unsigned nnames;
	time_t now;
	bool all;
	int error, fd, status;

	/* Every exit passes through `out`, which zeroes both password copies. */
	memset(&req, 0, sizeof(req));
	status = EINVAL;
	t->stage = "caller";
	if (!authagent_elevate_caller_allowed(c->client_label)) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate denied: caller '%.*s' is not a session "
		    "(units declare, they do not elevate)",
		    (int)sizeof(c->client_label), c->client_label);
		status = EPERM;
		goto out;
	}
	t->stage = "shape";
	sender = channel_message_sender(request);
	if (sender == NULL)
		goto out;
	uid = (uid_t)sender->uid;
	t->uid = sender->uid;
	if (nfds != 0 || data == NULL || len != sizeof(req))
		goto out;
	memcpy(&req, data, sizeof(req));
	if (req.version != AUTHAGENTD_PROTO_VERSION ||
	    req.op != AUTHAGENT_OP_ELEVATE || req.flags != 0 ||
	    req.reserved != 0 ||
	    memchr(req.name, '\0', sizeof(req.name)) == NULL ||
	    memchr(req.password, '\0', sizeof(req.password)) == NULL ||
	    !authagent_valid_name(req.name, sizeof(req.name)))
		goto out;
	(void)strlcpy(t->name, req.name, sizeof(t->name));

	/* Policy first: never touch the password for a name not permitted. */
	t->stage = "policy";
	error = agent_resolve_grant(uid, &grant);
	if (error != 0) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate uid=%u name=%s: principal unresolvable (%s)",
		    (unsigned)uid, req.name, strerror(error));
		status = error;
		goto out;
	}
	if ((status = authagent_elevate_check(&grant, req.name)) != 0) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate denied uid=%u caller='%.*s' name=%s: not in "
		    "may_elevate%s", (unsigned)uid,
		    (int)sizeof(c->client_label), c->client_label, req.name,
		    grant.from_default_rule ?
		    " (policy absent: historical rule)" : "");
		goto out;
	}

	t->have_grant = true;
	t->nanointments = grant.nanointments;
	t->all = grant.anoint_all;
	t->admin_rights = grant.admin_rights;
	t->from_default_rule = grant.from_default_rule;

	/* Rate limit before any password work. */
	t->stage = "ratelimit";
	now = monotonic_seconds();
	if (authagent_ratelimit_blocked(&g_ratelimit, uid, now)) {
		AUTHAGENT_PROBE_RATELIMIT_BLOCK(uid,
		    ratelimit_failures(&g_ratelimit, uid));
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate refused uid=%u name=%s: too many failures "
		    "(%u within %u s)", (unsigned)uid, req.name,
		    AUTHAGENT_RL_MAX_FAILURES, AUTHAGENT_RL_WINDOW_SEC);
		status = EAGAIN;
		goto out;
	}

	/* Authenticate the caller in-agent against master.passwd. */
	t->stage = "password";
	if (g_mpwfd == -1 ||
	    id_snapshot(g_mpwfd, g_mpwbuf, sizeof(g_mpwbuf)) == -1) {
		syslog(LOG_AUTHPRIV | LOG_ERR,
		    "elevate uid=%u name=%s: master.passwd unavailable (%s)",
		    (unsigned)uid, req.name,
		    g_mpwfd == -1 ? "not granted" : strerror(errno));
		explicit_bzero(g_mpwbuf, sizeof(g_mpwbuf));
		status = ENXIO;
		goto out;
	}
	status = authagent_verify_password(g_mpwbuf, uid, req.password);
	explicit_bzero(g_mpwbuf, sizeof(g_mpwbuf));
	if (status != 0) {
		authagent_ratelimit_failure(&g_ratelimit, uid, now);
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate failed uid=%u caller='%.*s' name=%s: %s",
		    (unsigned)uid, (int)sizeof(c->client_label),
		    c->client_label, req.name,
		    status == EACCES ? "authentication failed" :
		    status == EPERM ? "account locked or has no password" :
		    status == ENOENT ? "no master.passwd record" :
		    strerror(status));
		goto out;
	}
	authagent_ratelimit_success(&g_ratelimit, uid);

	/* Mint session-set-plus-one, bound to the same uid. */
	t->stage = "mint";
	status = authagent_compose_set(&grant, req.name, names,
	    nitems(names), &nnames, &all);
	if (status != 0) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "elevate uid=%u name=%s: cannot compose set: %s",
		    (unsigned)uid, req.name, strerror(status));
		goto out;
	}
	kind = authagent_mint_kind_for_grant(&grant);
	fd = -1;
	if (service_context_mint_domain_anointed(g_context, kind, uid,
	    (const char (*)[SERVICE_ANOINT_NAME_MAX])names, nnames, all,
	    grant.admin_rights, &fd) == 0 && fd >= 0 &&
	    cap_xfer_limit(fd, CAP_XFER_ONCE) == 0) {
		status = 0;
		*fdp = fd;
		t->stage = "ok";
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "elevate uid=%u caller='%.*s' name=%s ok (%s, set=%s%u)",
		    (unsigned)uid, (int)sizeof(c->client_label),
		    c->client_label, req.name,
		    kind == SERVICE_MINT_SYSTEM ? "system" : "user",
		    all ? "*+" : "", nnames);
	} else {
		status = errno != 0 ? errno : EIO;
		if (fd >= 0)
			close(fd);
		syslog(LOG_AUTHPRIV | LOG_ERR,
		    "elevate uid=%u name=%s: mint failed: %s",
		    (unsigned)uid, req.name, strerror(status));
	}
 out:
	/* The password lives in our copy and in the message buffer; zero both. */
	explicit_bzero(&req, sizeof(req));
	if (data != NULL && len != 0)
		explicit_bzero(__DECONST(void *, data), len);
	return (status);
}

/*
 * Dispatch one request.  The first two words of every request are
 * (version, op); the op selects its own caller gate, so the gate is applied
 * before anything else in the payload is looked at.
 */
static void
handle_request(struct channel *ch __unused, struct channel_message *request,
    void *arg)
{
	struct client *c = arg;
	struct authagent_mint_reply reply;
	struct request_trace t;
	const void *data;
	const uint32_t *words;
	size_t len, nfds;
	uint32_t op;
	int fd, send_error;

	fd = -1;
	op = 0;
	send_error = 0;
	request_trace_init(&t);
	memset(&reply, 0, sizeof(reply));

	data = channel_message_data(request);
	len = channel_message_length(request);
	nfds = channel_message_fd_count(request);
	if (data != NULL && len >= 2 * sizeof(uint32_t)) {
		words = data;
		op = words[1];
	}

	if (op == AUTHAGENT_OP_ELEVATE) {
		AUTHAGENT_PROBE_ELEVATE_START(c->client_label);
		reply.status = handle_elevate(c, request, data, len, nfds, &fd,
		    &t);
	} else {
		/*
		 * Everything else, including an undecodable op, takes the
		 * MINT path, whose ADMIN gate answers before the payload is
		 * parsed: an unprivileged caller learns nothing beyond EPERM.
		 */
		AUTHAGENT_PROBE_REQUEST_START(c->client_label);
		reply.status = handle_mint(c, data, len, nfds, &fd, &t);
	}

	if (channel_send_reply(request, &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &reply,
		.length = sizeof(reply),
		.fds = reply.status == 0 ? &fd : NULL,
		.nfds = reply.status == 0 ? 1 : 0,
	    }) == -1) {
		send_error = errno;
		syslog(LOG_WARNING, "reply: %m");
	}

	/*
	 * The audit record goes out right after the reply (see g_audit): the
	 * decision is final either way, and a slow system.Audit must not hold
	 * a login's channel hostage.
	 */
	if (op == AUTHAGENT_OP_ELEVATE)
		agent_audit_elevate(c, &t, reply.status);
	else
		agent_audit_mint(c, &t, reply.status);
	if (op == AUTHAGENT_OP_ELEVATE)
		AUTHAGENT_PROBE_ELEVATE_DONE(c->client_label, t.uid, t.name,
		    reply.status, send_error, t.stage);
	else
		AUTHAGENT_PROBE_REQUEST_DONE(c->client_label, t.uid, t.kind,
		    t.flags, reply.status, send_error);
	if (fd >= 0)
		close(fd);
	channel_message_free(request);
	client_sync_events(c);
}

#ifndef AUTHAGENTD_TESTING
static int
client_adopt(int client_fd, const struct service_identity *identity)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct client *c;
	struct kevent kev;
	int error;

	options.max_pending_requests = 8;
	options.max_queued_messages = 32;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 4;

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		close(client_fd);
		return (-1);
	}
	/*
	 * Retain the caller's switchboard-stamped identity for the gates in
	 * handle_request().  The rights bitmask carries the authenticator
	 * authority (MINT); the label distinguishes a session from a unit
	 * (ELEVATE) and is logged for audit.
	 */
	c->rights = identity->rights;
	(void)strlcpy(c->client_label, identity->client_label,
	    sizeof(c->client_label));
	if (channel_create(client_fd, &options, &c->chan) == -1) {
		error = errno;
		free(c);
		close(client_fd);
		errno = error;
		return (-1);
	}
	c->fd = channel_fd(c->chan);
	if (channel_set_request_handler(c->chan, handle_request, c) == -1) {
		error = errno;
		channel_destroy(c->chan);
		free(c);
		errno = error;
		return (-1);
	}
	TAILQ_INSERT_TAIL(&clients, c, entry);
	EV_SET(&kev, c->fd, EVFILT_READ, EV_ADD, 0, 0, c);
	if (kevent(g_kq, &kev, 1, NULL, 0, NULL) == -1) {
		client_destroy(c);
		return (-1);
	}
	return (0);
}

/*
 * Obtain one file from the filesystem daemon with a bounded retry.  tzfsd may
 * not be serving yet this early in boot: its manifest might not be
 * registered when we ask, which fails fast rather than blocking on on-demand
 * launch (a registered-but-not-running provider would instead block until it
 * checks in).  A one-shot open would then leave the descriptor -1 for the
 * life of the process.  Retry a bounded number of times with a short backoff
 * (~1s worst case); a definitive answer (EACCES/EPERM — not granted) stops us
 * at once, and so does success.  Runs before cap_enter.  Returns the fd or
 * -1 with errno.
 */
static int
open_with_retry(const char *path)
{
	unsigned attempt;
	int fd, last_errno;

	fd = -1;
	last_errno = 0;
	for (attempt = 0; attempt < 8; attempt++) {
		if (service_open_isolated(g_context, path, SERVICE_OPEN_READ,
		    0, &fd) == 0)
			return (fd);
		last_errno = errno;
		fd = -1;
		if (errno == EACCES || errno == EPERM)
			break;	/* definitive: not granted */
		(void)nanosleep(&(struct timespec){
		    .tv_sec = 0, .tv_nsec = 125 * 1000 * 1000 }, NULL);
	}
	errno = last_errno;
	return (-1);
}

/*
 * The capability user is not a principal (docs/ipc-anointments-design.md):
 * it is the unprivileged uid switchboard runs units as, and units never
 * consult this file.  An entry that nonetheless grants it something is
 * almost certainly a misunderstanding of the model; warn so it is visible.
 * Detected semantically: resolve the grant for that uid and warn if it is
 * non-empty.  Never fatal.
 */
static void
warn_if_capability_user_granted(void)
{
	struct capbundle_principal_grant grant;
	uid_t uid;

	if (g_policy_fd == -1 || !id_getpwnam_uid("capability", &uid))
		return;
	if (agent_resolve_grant(uid, &grant) != 0 || grant.from_default_rule)
		return;
	if (grant.nanointments != 0 || grant.anoint_all ||
	    grant.nmay_elevate != 0 || grant.elevate_all ||
	    grant.admin_rights)
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "principal policy grants the capability user (uid %u) "
		    "anointments; units never consult this file and that uid "
		    "is not a principal -- check principal-policy.ucl",
		    (unsigned)uid);
}

int
main(void)
{
	struct service_provider *provider;
	struct service_listener *listener;
	struct service_identity identity;
	struct kevent event, change;
	int fd;

	openlog("authagentd", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
	/* ps(1) shows the unit name, not the ld-elf.so.1 launcher. */
	service_set_proctitle();

	g_kq = kqueuex(KQUEUE_CLOEXEC);
	if (g_kq == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_acquire(&g_context) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, AUTHAGENTD_NAME, &listener) == -1)
		err(1, "initialize");

	/*
	 * Adopt the principal policy from the filesystem daemon (tzfsd): ask it
	 * to open /Capabilities/Config/principal-policy.ucl on our behalf and
	 * hand back a read-only descriptor.  Nothing is declared in the
	 * manifest; tzfsd's own per-label policy decides whether this service
	 * may read it.  It is optional: an unreadable or ungranted policy
	 * leaves g_policy_fd == -1 and every grant falls back to the
	 * historical root-or-wheel rule (P10).  Done before cap_enter so no
	 * path is ever consulted at request time.  Make the fallback
	 * observable: a missing file (ENOENT) is the normal optional case —
	 * INFO; anything else (denied, or tzfsd never came up) is unexpected —
	 * WARNING, because an operator-configured policy is then silently not
	 * in effect.
	 */
	g_policy_fd = open_with_retry("/Capabilities/Config/principal-policy.ucl");
	if (g_policy_fd == -1)
		syslog(errno == ENOENT ? (LOG_AUTHPRIV | LOG_INFO) :
		    (LOG_AUTHPRIV | LOG_WARNING),
		    "principal policy unavailable (%m); "
		    "mint uses the root-or-wheel default");

	/*
	 * Open the identity databases (/etc/passwd, /etc/group) before entering
	 * the sandbox, so the agent can resolve a uid to its passwd and group
	 * membership authoritatively after cap_enter — the security basis for not
	 * trusting the login client's claims.  Reading the retained descriptors is
	 * capability-mode-legal; opening the paths would not be.  This is the
	 * Identity fold: in-process NSS, no Casper zygote.
	 */
	if (id_open_databases() == -1) {
		syslog(LOG_ERR, "identity databases unavailable: %m");
		return (1);
	}

	/*
	 * ELEVATE's in-agent authentication needs the password hashes:
	 * /etc/master.passwd, read-only, granted by the same tzfsd open policy.
	 * Optional in the sense that MINT keeps working without it; ELEVATE
	 * then fails closed (ENXIO) and the reason is logged once here.
	 */
	g_mpwfd = open_with_retry("/etc/master.passwd");
	if (g_mpwfd == -1)
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "master.passwd unavailable (%m); elevation disabled");

	warn_if_capability_user_granted();

	/*
	 * The audit session (AUE_AUTHAGENT_ELEVATE / _MINT via system.Audit)
	 * is NOT opened here: see g_audit.  Check in as soon as the identity
	 * databases are held -- logins are waiting on this.
	 */
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(g_kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		err(1, "initialize");
	syslog(LOG_NOTICE, "ready (elevation %s)",
	    g_mpwfd == -1 ? "disabled" : "enabled");

	for (;;) {
		if (kevent(g_kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}
		if (event.udata == listener) {
			memset(&identity, 0, sizeof(identity));
			identity.size = sizeof(identity);
			if (service_listener_accept(listener, &identity,
			    &fd) == -1) {
				if (errno == EINTR)
					continue;
				if (service_provider_quiescing(provider) == 1)
					break;
				syslog(LOG_WARNING, "accept: %m");
				continue;
			}
			if (client_adopt(fd, &identity) == -1)
				syslog(LOG_WARNING, "adopt client: %m");
			continue;
		}
		/* A connected caller's channel. */
		{
			struct client *c = event.udata;

			if (event.flags & EV_EOF) {
				/*
				 * A caller that half-closes its write end
				 * (shutdown(SHUT_WR)) right after sending its
				 * request shows up as EV_EOF while the request
				 * bytes are still buffered and its read end is
				 * still open for the reply.  Drain one dispatch
				 * pass so the reply is produced, then flush it
				 * best-effort before tearing the client down —
				 * do not destroy it out from under an unanswered
				 * request.  Only the read side can carry pending
				 * input; a write-side EOF has nothing to drain.
				 */
				if (event.filter == EVFILT_READ &&
				    channel_dispatch(c->chan) == 0)
					(void)channel_flush(c->chan);
				client_destroy(c);
				continue;
			}
			if (event.filter == EVFILT_WRITE) {
				if (channel_flush(c->chan) == -1) {
					client_destroy(c);
					continue;
				}
			} else if (event.filter == EVFILT_READ) {
				if (channel_dispatch(c->chan) == -1) {
					client_destroy(c);
					continue;
				}
			}
			client_sync_events(c);
		}
	}

	return (service_provider_quiesce_complete(provider, 0) == 0 ? 0 : 1);
}
#endif /* !AUTHAGENTD_TESTING */

#ifdef AUTHAGENTD_TESTING
/*
 * Test seam.  These entry points let an ATF provider test drive the real
 * handle_request() over a channel without standing up main()'s kqueue accept
 * loop.  They change no runtime behaviour: the daemon binary is built without
 * AUTHAGENTD_TESTING and never sees them.
 */
void
authagentd_test_configure(struct service_context *context, int policy_fd)
{

	g_context = context;
	g_policy_fd = policy_fd;
	/*
	 * Identity descriptors stay at -1 unless a parser test configures them.
	 * Provider tests drive the caller gate and protocol paths, not live
	 * uid resolution (which id_getpwuid then fails closed, ENOENT).
	 */
}

void
authagentd_test_identity_configure(int passwd_fd, int group_fd)
{

	g_pwfd = passwd_fd;
	g_grfd = group_fd;
}

void
authagentd_test_set_audit_hook(authagentd_test_audit_fn fn)
{

	g_audit_hook = fn;
}

void
authagentd_test_masterpw_configure(int masterpw_fd)
{

	g_mpwfd = masterpw_fd;
	memset(&g_ratelimit, 0, sizeof(g_ratelimit));
}

int
authagentd_test_resolve_identity(uid_t uid, char *name, size_t namesz,
    gid_t *primary_gid, gid_t *member_gids, unsigned max_members,
    unsigned *nmember)
{
	struct passwd *pw;

	if (name == NULL || namesz == 0 || primary_gid == NULL ||
	    member_gids == NULL || max_members == 0 || nmember == NULL)
		return (errno = EINVAL, -1);
	errno = 0;
	pw = id_getpwuid(uid);
	if (pw == NULL)
		return (errno = errno != 0 ? errno : ENOENT, -1);
	if (strlcpy(name, pw->pw_name, namesz) >= namesz)
		return (errno = ERANGE, -1);
	*primary_gid = pw->pw_gid;
	*nmember = agent_member_gids(pw, member_gids, max_members);
	return (0);
}

int
authagentd_test_name2gid(const char *name, gid_t *gidp)
{
	gid_t gid;

	if (name == NULL || gidp == NULL)
		return (errno = EINVAL, -1);
	gid = agent_name2gid(NULL, name);
	if (gid == (gid_t)-1)
		return (errno = ENOENT, -1);
	*gidp = gid;
	return (0);
}

int
authagentd_test_serve(int fd, const struct service_identity *identity)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct client c;
	int ready, wants;

	options.max_pending_requests = 8;
	options.max_queued_messages = 32;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 4;

	memset(&c, 0, sizeof(c));
	c.rights = identity->rights;
	(void)strlcpy(c.client_label, identity->client_label,
	    sizeof(c.client_label));
	if (channel_create(fd, &options, &c.chan) == -1)
		return (-1);
	c.fd = channel_fd(c.chan);
	if (channel_set_request_handler(c.chan, handle_request, &c) == -1) {
		channel_destroy(c.chan);
		return (-1);
	}
	for (;;) {
		wants = channel_wants_write(c.chan);
		if (wants == -1)
			break;
		ready = channel_wait(c.chan, wants, -1);
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(c.chan) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(c.chan) == -1)
			break;
	}
	channel_destroy(c.chan);
	return (0);
}
#endif /* AUTHAGENTD_TESTING */
