/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 Ian Lepore <ian@FreeBSD.org>
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <dev/mac_capability/mac_capability.h>
#include <security/mac/mac_policy.h>

static SYSCTL_NODE(_security_mac, OID_AUTO, ntpd,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "mac_ntpd policy controls");

static int ntpd_enabled = 1;
static int ntpd_uid = 123;
static bool ntpd_active;
static struct mtx ntpd_lock;
MTX_SYSINIT(mac_ntpd_lock, &ntpd_lock, "mac_ntpd", MTX_DEF);

/*
 * 5BSD: the capability plane's clock gate (SYS_GATE_SETTIME, claimed by
 * BSDTime) refuses every ambient caller of the clock syscalls.  Publish the
 * ntpd uid to it while this policy is active and enabled, so the user this
 * policy authorises can still step and slew the clock.  The gate checks the
 * same three privileges granted below and never accepts uid 0.
 */
static void
ntpd_publish(void)
{

	mtx_lock(&ntpd_lock);
	mac_capability_clock_delegate(ntpd_active && ntpd_enabled ?
	    ntpd_uid : -1);
	mtx_unlock(&ntpd_lock);
}

static int
ntpd_sysctl_int(SYSCTL_HANDLER_ARGS)
{
	int error;

	error = sysctl_handle_int(oidp, arg1, 0, req);
	/*
	 * A loader tunable reaches this handler when the sysctl registers,
	 * before the lock exists; mpo_init publishes the value then.
	 */
	if (error == 0 && req->newptr != NULL && ntpd_active)
		ntpd_publish();
	return (error);
}

SYSCTL_PROC(_security_mac_ntpd, OID_AUTO, enabled,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &ntpd_enabled, 0,
    ntpd_sysctl_int, "I", "Enable mac_ntpd policy");

SYSCTL_PROC(_security_mac_ntpd, OID_AUTO, uid,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &ntpd_uid, 0,
    ntpd_sysctl_int, "I", "User id for ntpd user");

static int
ntpd_priv_grant(struct ucred *cred, int priv)
{

	if (ntpd_enabled && cred->cr_uid == ntpd_uid) {
		switch (priv) {
		case PRIV_ADJTIME:
		case PRIV_CLOCK_SETTIME:
		case PRIV_NTP_ADJTIME:
		case PRIV_NETINET_RESERVEDPORT:
		case PRIV_NETINET_REUSEPORT:
			return (0);
		default:
			break;
		}
	}
	return (EPERM);
}

static void
ntpd_init(struct mac_policy_conf *mpc __unused)
{

	ntpd_active = true;
	ntpd_publish();
}

static void
ntpd_destroy(struct mac_policy_conf *mpc __unused)
{

	ntpd_active = false;
	ntpd_publish();
}

static struct mac_policy_ops ntpd_ops =
{
	.mpo_init = ntpd_init,
	.mpo_destroy = ntpd_destroy,
	.mpo_priv_grant = ntpd_priv_grant,
};

MAC_POLICY_SET(&ntpd_ops, mac_ntpd, "MAC/ntpd",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
/* Lets the loader see that a kernel with "options MAC_NTPD" provides it. */
MODULE_VERSION(mac_ntpd, 1);
