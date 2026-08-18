/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for libutil's credential-application engine.
 * setusercontext() is the shared choke point through which login(1), su(1),
 * jexec(8) and other privilege-transition tools apply a target credential
 * (setgid/initgroups/setloginclass/MAC label/setuid).  The probe fires once
 * per call with the target user, uid, the LOGIN_SET* flag mask, and the
 * result (0 == the full credential transition succeeded).
 */
provider logincap {
	probe setusercontext(const char *user, int uid, int flags, int error);
};
