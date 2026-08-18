/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright 2001 Mark R V Murray
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <stddef.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "pam_deny_probes.h"

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	const char *user = NULL;
	int r;

	if ((r = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		PAM_DENY_PROBE_SM_AUTHENTICATE(user, r);
		return (r);
	}

	PAM_DENY_PROBE_SM_AUTHENTICATE(user, PAM_AUTH_ERR);
	return (PAM_AUTH_ERR);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc __unused, const char *argv[] __unused)
{
	const void *user = NULL;

	(void)pam_get_item(pamh, PAM_USER, &user);
	PAM_DENY_PROBE_SM_SETCRED((const char *)user, flags, PAM_CRED_ERR);
	return (PAM_CRED_ERR);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	const void *user = NULL;

	(void)pam_get_item(pamh, PAM_USER, &user);
	PAM_DENY_PROBE_SM_ACCT_MGMT((const char *)user, PAM_AUTH_ERR);
	return (PAM_AUTH_ERR);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	const void *user = NULL;

	(void)pam_get_item(pamh, PAM_USER, &user);
	PAM_DENY_PROBE_SM_CHAUTHTOK((const char *)user, PAM_AUTHTOK_ERR);
	return (PAM_AUTHTOK_ERR);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	const void *user = NULL;

	(void)pam_get_item(pamh, PAM_USER, &user);
	PAM_DENY_PROBE_SM_OPEN_SESSION((const char *)user, PAM_SESSION_ERR);
	return (PAM_SESSION_ERR);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	const void *user = NULL;

	(void)pam_get_item(pamh, PAM_USER, &user);
	PAM_DENY_PROBE_SM_CLOSE_SESSION((const char *)user, PAM_SESSION_ERR);
	return (PAM_SESSION_ERR);
}

PAM_MODULE_ENTRY("pam_deny");
