/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUTHAGENTD_TEST_H_
#define _AUTHAGENTD_TEST_H_

#include <sys/types.h>
#include <stdbool.h>

#include <libcasper.h>
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
 * as handle_request() does from Casper.
 */
enum service_mint_kind authagent_mint_kind(int policy_fd, uid_t uid,
	    const gid_t *member_gids, unsigned nmember,
	    capbundle_group_gid_fn name2gid, void *ctx);

#ifdef AUTHAGENTD_TESTING
struct service_context;
struct service_identity;

/*
 * Install the mint/Casper state a subsequent authagentd_test_serve() serves
 * with.  A test that only exercises the caller gate or request validation may
 * leave these NULL/-1: those paths answer before any mint or lookup.
 */
void	authagentd_test_configure(struct service_context *context,
	    cap_channel_t *pwd, cap_channel_t *grp, int policy_fd);

/*
 * Test seam: run exactly one client's provider session over `fd`, using
 * `identity` as the serviced-stamped caller (so a test can vary the caller's
 * rights directly).  Drives the real handle_request().  Returns 0 when the
 * peer closes, -1 on channel setup failure.
 */
int	authagentd_test_serve(int fd, const struct service_identity *identity);
#endif /* AUTHAGENTD_TESTING */

#endif /* _AUTHAGENTD_TEST_H_ */
