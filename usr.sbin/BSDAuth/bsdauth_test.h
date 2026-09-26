/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDAUTH_TEST_H_
#define _BSDAUTH_TEST_H_

#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <libservice.h>
#include <libcapbundle.h>

/*
 * The mint caller-gate predicate, factored out of handle_request() so the
 * privilege-escalation regression can be unit-tested without a live plane.
 * True iff the switchboard-stamped caller holds SERVICE_RIGHTS_ADMIN.  Non-static
 * for testability and declared here so the daemon build keeps a prototype in
 * scope; the runtime behaviour is unchanged.
 */
bool	authagent_caller_allowed(service_rights_t rights);

/*
 * The SYSTEM-vs-USER mint decision, factored for unit testing.  Pure: the
 * caller supplies the resolved member gids and a group-name resolver, exactly
 * as handle_request() does from the retained identity databases.  It is
 * authagent_mint_kind_for_grant() over the resolved principal grant.
 */
enum service_mint_kind authagent_mint_kind(int policy_fd, uid_t uid,
	    const gid_t *member_gids, unsigned nmember,
	    capbundle_group_gid_fn name2gid, void *ctx);
enum service_mint_kind authagent_mint_kind_for_grant(
	    const struct capbundle_principal_grant *grant);

/*
 * ELEVATE (docs/book/src/plane/anointments.md "Elevation"), factored into pure
 * pieces so every decision is unit-testable without a plane.
 */

/* The label switchboard stamps on an ambient login-session lookup. */
#define	AUTHAGENT_SESSION_LABEL	"org.5bsd.user-session"

/* Only a session may elevate; a unit's label is refused (E5). */
bool	authagent_elevate_caller_allowed(const char *client_label);

/* Reverse-domain anointment name; "*" is never a valid request. */
bool	authagent_valid_name(const char *name, size_t maxlen);

/* 0 if `name` is in the grant's may_elevate (or "*"), else EPERM. */
int	authagent_elevate_check(const struct capbundle_principal_grant *grant,
	    const char *name);

/*
 * Verify `password` for `uid` against a mutable master.passwd snapshot.
 * 0 / EACCES (mismatch) / EPERM (empty or locked hash) / ENOENT (no record).
 */
int	authagent_verify_password(char *masterpw, uid_t uid,
	    const char *password);

/* Per-uid failure limiter: AUTHAGENT_RL_MAX_FAILURES within _WINDOW_SEC. */
#define	AUTHAGENT_RL_MAX_FAILURES	5U
#define	AUTHAGENT_RL_WINDOW_SEC		60
#define	AUTHAGENT_RL_SLOTS		64
struct authagent_ratelimit_slot {
	bool		used;
	uid_t		uid;
	unsigned	failures;
	time_t		window_start;	/* monotonic seconds of first failure */
};
struct authagent_ratelimit {
	struct authagent_ratelimit_slot	slots[AUTHAGENT_RL_SLOTS];
};
bool	authagent_ratelimit_blocked(struct authagent_ratelimit *rl, uid_t uid,
	    time_t now);
void	authagent_ratelimit_failure(struct authagent_ratelimit *rl, uid_t uid,
	    time_t now);
void	authagent_ratelimit_success(struct authagent_ratelimit *rl, uid_t uid);
/*
 * MINT_AUTH's composite limiter key over (caller label, target uid): distinct
 * callers or distinct targets must map to distinct keys so one caller's failed
 * su attempts cannot throttle another caller's or another target's access.
 */
uid_t	mint_auth_ratelimit_key(const char *caller_label, uid_t target);

/*
 * Session set plus one: the grant's anointments with `name` appended unless
 * already held; "*" yields *all = true and *nout = 0.  0 / E2BIG / EINVAL.
 */
int	authagent_compose_set(const struct capbundle_principal_grant *grant,
	    const char *name, char (*out)[SERVICE_ANOINT_NAME_MAX],
	    unsigned max, unsigned *nout, bool *all);

/*
 * The audit sink of the test build: the daemon build commits records through
 * system.Audit (libauditcmp); tests, which link no broker, receive each
 * would-be record (subject, operation, result) here instead.
 */
typedef void (*bsdauth_test_audit_fn)(const char *subject,
	    const char *operation, int error);

#ifdef BSDAUTH_TESTING
struct service_context;
struct service_identity;

void	bsdauth_test_set_audit_hook(bsdauth_test_audit_fn fn);

/*
 * Install the mint state a subsequent bsdauth_test_serve() uses.  Tests
 * exercising only the caller gate or request validation may leave the context
 * NULL and policy fd -1 because those paths answer before minting or identity
 * lookup.  Parser tests install synthetic identity descriptors separately;
 * ELEVATE tests install a synthetic master.passwd descriptor (which also
 * resets the in-memory rate limiter).
 */
void	bsdauth_test_configure(struct service_context *context,
	    int policy_fd);
void	bsdauth_test_identity_configure(int passwd_fd, int group_fd);
void	bsdauth_test_masterpw_configure(int masterpw_fd);
int	bsdauth_test_resolve_identity(uid_t uid, char *name, size_t namesz,
	    gid_t *primary_gid, gid_t *member_gids, unsigned max_members,
	    unsigned *nmember);
int	bsdauth_test_name2gid(const char *name, gid_t *gidp);

/*
 * Test seam: run exactly one client's provider session over `fd`, using
 * `identity` as the switchboard-stamped caller (so a test can vary the caller's
 * rights and label directly).  Drives the real handle_request().  Returns 0
 * when the peer closes, -1 on channel setup failure.
 */
int	bsdauth_test_serve(int fd, const struct service_identity *identity);
#endif /* BSDAUTH_TESTING */

#endif /* _BSDAUTH_TEST_H_ */
