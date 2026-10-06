/* SPDX-License-Identifier: BSD-2-Clause */
/* Compatibility for local PAM configurations retained across package upgrades. */
#include <sys/types.h>
#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	/* Authentication belongs to the normal UNIX authentication modules. */
	return (PAM_IGNORE);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_capability");
