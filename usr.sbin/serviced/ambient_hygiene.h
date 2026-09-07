/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SYSTEM ambient-channel launch hygiene (§21).
 *
 * The SYSTEM ambient lookup channel confers the administrative bypass: a
 * lookup with requester==NULL on a SYSTEM domain is granted SVC_RIGHTS_ALL
 * (including SVC_RIGHTS_ADMIN) and resolves the self-served control names
 * (see naming.c naming_lookup / naming_lookup_self_control).  It must
 * therefore never survive a transition into an unprivileged uid — exactly as
 * login(1)/su(1) close or re-provision it rather than let a user shell
 * inherit it.  This predicate is the single decision point serviced's command
 * launcher (execute.c svc_exec_command) uses when scrubbing the child fd
 * table, factored out here so it is pure, self-documenting, and unit-tested.
 */
#ifndef SERVICED_AMBIENT_HYGIENE_H
#define SERVICED_AMBIENT_HYGIENE_H

#include <sys/types.h>
#include <stdbool.h>

/*
 * Decide which fd (if any) the launched child may keep as its SYSTEM ambient
 * lookup channel, given whether it is dropping credentials (have_creds) and
 * the uid it is dropping to.  Returns the fd to spare from the child's
 * closefrom(2) scrub, or -1 to scrub it away entirely; sets *unset_env when
 * SERVICE_LOOKUP_FD must also be removed from the environment so no stale fd
 * number is named to the child's execv(2).
 *
 * A unit that stays root (have_creds false, i.e. it runs as serviced's own
 * uid 0; or an explicit user=root) keeps the channel — root is the admin
 * principal by the plane's model, and rc plus the want_console bootstrap need
 * discovery.  A unit that drops to a non-root uid (manifest user=/group=) gets
 * NO ambient channel: the SYSTEM channel is scrubbed and SERVICE_LOOKUP_FD is
 * unset, closing the escalation whereby an unprivileged oneshot could look up
 * system.serviced / system.lifecycle over an inherited SYSTEM channel and drive
 * the admin control/lifecycle plane (reboot/halt/start/stop).
 */
static inline int
svc_exec_ambient_spare_fd(bool have_creds, uid_t uid, int ambient_fd,
    bool *unset_env)
{
	bool drop = have_creds && uid != 0;

	if (unset_env != NULL)
		*unset_env = drop;
	return (drop ? -1 : ambient_fd);
}

#endif /* SERVICED_AMBIENT_HYGIENE_H */
