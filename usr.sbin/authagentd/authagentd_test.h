/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUTHAGENTD_TEST_H_
#define _AUTHAGENTD_TEST_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>

#include <libservice.h>
#include <libcapbundle.h>

/*
 * The mint caller-gate predicate, factored out of handle_request() so the
 * privilege-escalation regression can be unit-tested without a live plane.
 * True iff the serviced-stamped caller holds SERVICE_RIGHTS_ADMIN.  Non-static
 * for testability and declared here so the daemon build keeps a prototype in
 * scope; the runtime behaviour is unchanged.
 */
bool	authagent_caller_allowed(service_rights_t rights);

/*
 * The SYSTEM-vs-USER mint decision, factored for unit testing.  Pure: the
 * caller supplies the resolved member gids and a group-name resolver, exactly
 * as handle_request() does from the retained identity databases.
 */
enum service_mint_kind authagent_mint_kind(int policy_fd, uid_t uid,
	    const gid_t *member_gids, unsigned nmember,
	    capbundle_group_gid_fn name2gid, void *ctx);

#ifdef AUTHAGENTD_TESTING
struct service_context;
struct service_identity;

/*
 * Install the mint state a subsequent authagentd_test_serve() uses.  Tests
 * exercising only the caller gate or request validation may leave the context
 * NULL and policy fd -1 because those paths answer before minting or identity
 * lookup.  Parser tests install synthetic identity descriptors separately.
 */
void	authagentd_test_configure(struct service_context *context,
	    int policy_fd);
void	authagentd_test_identity_configure(int passwd_fd, int group_fd);
int	authagentd_test_resolve_identity(uid_t uid, char *name, size_t namesz,
	    gid_t *primary_gid, gid_t *member_gids, unsigned max_members,
	    unsigned *nmember);
int	authagentd_test_name2gid(const char *name, gid_t *gidp);

/*
 * Test seam: run exactly one client's provider session over `fd`, using
 * `identity` as the serviced-stamped caller (so a test can vary the caller's
 * rights directly).  Drives the real handle_request().  Returns 0 when the
 * peer closes, -1 on channel setup failure.
 */
int	authagentd_test_serve(int fd, const struct service_identity *identity);
#endif /* AUTHAGENTD_TESTING */

#endif /* _AUTHAGENTD_TEST_H_ */
