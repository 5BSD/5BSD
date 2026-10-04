/* SPDX-License-Identifier: BSD-2-Clause */
/* Session discovery for PAM login providers; BSDAuth selects all grants. */
#include <sys/types.h>

#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#define PAM_SM_SESSION
#include <libservice.h>
#include <libservice_session.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags __unused, int argc,
    const char *argv[])
{
	const char *user;
	struct passwd *pw;
	uid_t uid;
	int provider, session, result, saved;
	uint32_t mint_flags = 0;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "unprivileged") == 0)
			mint_flags |= SERVICE_MINT_AGENT_UNPRIVILEGED;
		else {
			syslog(LOG_ERR, "pam_capability: unknown option %s", argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}

	provider = service_ambient_lookup_fd();
	/* Never leave provider authority behind on a provisioning failure. */
	if (service_clear_ambient_lookup() == -1 && errno != ENOSYS) {
		if (provider >= 0)
			(void)close(provider);
		return (PAM_SESSION_ERR);
	}
	result = pam_get_user(pamh, &user, NULL);
	if (result != PAM_SUCCESS || user == NULL) {
		if (provider >= 0)
			(void)close(provider);
		return (PAM_SESSION_ERR);
	}
	pw = getpwnam(user);
	if (pw == NULL) {
		if (provider >= 0)
			(void)close(provider);
		return (PAM_USER_UNKNOWN);
	}
	uid = pw->pw_uid;
	if (provider < 0)
		return (PAM_SUCCESS);
	session = -1;
	result = service_mint_session_via_agent(provider, uid, mint_flags,
	    SERVICE_MINT_SESSION_TIMEOUT_MS, &session);
	saved = errno;
	(void)close(provider);
	if (result == 0 && session >= 0) {
		result = service_install_ambient_lookup_uid(session, uid);
		saved = errno;
		if (result == 0)
			(void)service_session_join_coalition(session);
	}
	if (session >= 0)
		(void)close(session);
	if (result == -1)
		syslog(LOG_NOTICE,
		    "pam_capability: uid %u has no discovery context: %s",
		    (unsigned)uid, strerror(saved));
	/* Ordinary UNIX login remains available without capability discovery.
	 */
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	/* Session descendants own their references; close is not revocation. */
	return (PAM_SUCCESS);
}
PAM_MODULE_ENTRY("pam_capability");
