/*
 * bluetooth.c
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001-2002 Maksim Yevmenkin <m_evmenkin@yahoo.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: ng_bluetooth.c,v 1.3 2003/04/26 22:37:31 max Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <netgraph/bluetooth/include/ng_bluetooth.h>

/*
 * Bluetooth stack sysctl globals
 */

static int	bluetooth_hci_command_timeout_value  = 5;   /* sec */
static int	bluetooth_hci_connect_timeout_value  = 60;  /* sec */
static int	bluetooth_hci_max_neighbor_age_value = 600; /* sec */
static int	bluetooth_l2cap_rtx_timeout_value    = 60;  /* sec */
static int	bluetooth_l2cap_ertx_timeout_value   = 300; /* sec */
static int	bluetooth_sco_rtx_timeout_value      = 60;  /* sec */
static int	bluetooth_iso_rtx_timeout_value      = 60;  /* sec */

/*
 * Define sysctl tree that shared by other parts of Bluetooth stack
 */

SYSCTL_NODE(_net, OID_AUTO, bluetooth, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth family");
SYSCTL_INT(_net_bluetooth, OID_AUTO, version,
	CTLFLAG_RD, SYSCTL_NULL_INT_PTR, NG_BLUETOOTH_VERSION, "Version of the stack");

/* 
 * HCI
 */

SYSCTL_NODE(_net_bluetooth, OID_AUTO, hci, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth HCI family");

static int
bluetooth_set_hci_command_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_hci_command_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (value > 0 && value <= INT_MAX / hz)
			bluetooth_hci_command_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_hci_command_timeout_value */

SYSCTL_PROC(_net_bluetooth_hci, OID_AUTO, command_timeout,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_hci_command_timeout_value, 5,
	bluetooth_set_hci_command_timeout_value,
	"I", "HCI command timeout (sec)");

static int
bluetooth_set_hci_connect_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_hci_connect_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (0 < value && value <= bluetooth_l2cap_rtx_timeout_value &&
		    value <= INT_MAX / hz)
			bluetooth_hci_connect_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_hci_connect_timeout_value */

SYSCTL_PROC(_net_bluetooth_hci, OID_AUTO, connection_timeout, 
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_hci_connect_timeout_value, 60,
	bluetooth_set_hci_connect_timeout_value,
	"I", "HCI connect timeout (sec)");

static int
bluetooth_set_hci_max_neighbor_age_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_hci_max_neighbor_age_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (value > 0)
			bluetooth_hci_max_neighbor_age_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_hci_max_neighbor_age_value */

SYSCTL_PROC(_net_bluetooth_hci, OID_AUTO, max_neighbor_age,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_hci_max_neighbor_age_value, 600,
	bluetooth_set_hci_max_neighbor_age_value,
	"I", "Maximal HCI neighbor cache entry age (sec)");

/* 
 * L2CAP
 */

SYSCTL_NODE(_net_bluetooth, OID_AUTO, l2cap, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth L2CAP family");

static int
bluetooth_set_l2cap_rtx_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_l2cap_rtx_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (bluetooth_hci_connect_timeout_value <= value &&
		    value <= bluetooth_l2cap_ertx_timeout_value &&
		    value <= INT_MAX / hz)
			bluetooth_l2cap_rtx_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_l2cap_rtx_timeout_value */

SYSCTL_PROC(_net_bluetooth_l2cap, OID_AUTO, rtx_timeout,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_l2cap_rtx_timeout_value, 60,
	bluetooth_set_l2cap_rtx_timeout_value,
	"I", "L2CAP RTX timeout (sec)");

static int
bluetooth_set_l2cap_ertx_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_l2cap_ertx_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (value >= bluetooth_l2cap_rtx_timeout_value &&
		    value <= INT_MAX / hz)
			bluetooth_l2cap_ertx_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_l2cap_ertx_timeout_value */

SYSCTL_PROC(_net_bluetooth_l2cap, OID_AUTO, ertx_timeout,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_l2cap_ertx_timeout_value, 300,
	bluetooth_set_l2cap_ertx_timeout_value,
	"I", "L2CAP ERTX timeout (sec)");

/*
 * Return various sysctl values
 */

uint32_t
bluetooth_hci_command_timeout(void)
{
	return (bluetooth_hci_command_timeout_value * hz);
} /* bluetooth_hci_command_timeout */

uint32_t
bluetooth_hci_connect_timeout(void)
{
	return (bluetooth_hci_connect_timeout_value * hz);
} /* bluetooth_hci_connect_timeout */

uint32_t
bluetooth_hci_max_neighbor_age(void)
{
	return (bluetooth_hci_max_neighbor_age_value);
} /* bluetooth_hci_max_neighbor_age */

uint32_t
bluetooth_l2cap_rtx_timeout(void)
{
	return (bluetooth_l2cap_rtx_timeout_value * hz);
} /* bluetooth_l2cap_rtx_timeout */

uint32_t
bluetooth_l2cap_ertx_timeout(void)
{
	return (bluetooth_l2cap_ertx_timeout_value * hz);
} /* bluetooth_l2cap_ertx_timeout */

uint32_t
bluetooth_sco_rtx_timeout(void)
{
	return (bluetooth_sco_rtx_timeout_value * hz);
} /* bluetooth_sco_rtx_timeout */

uint32_t
bluetooth_iso_rtx_timeout(void)
{
	return (bluetooth_iso_rtx_timeout_value * hz);
} /* bluetooth_iso_rtx_timeout */

/*
 * RFCOMM
 */

SYSCTL_NODE(_net_bluetooth, OID_AUTO, rfcomm, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth RFCOMM family");

/* 
 * SCO
 */

SYSCTL_NODE(_net_bluetooth, OID_AUTO, sco, CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 
    "Bluetooth SCO family");

static int
bluetooth_set_sco_rtx_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_sco_rtx_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (bluetooth_hci_connect_timeout_value <= value &&
		    value <= INT_MAX / hz)
			bluetooth_sco_rtx_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_sco_rtx_timeout_value */

SYSCTL_PROC(_net_bluetooth_sco, OID_AUTO, rtx_timeout,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_sco_rtx_timeout_value, 60,
	bluetooth_set_sco_rtx_timeout_value,
	"I", "SCO RTX timeout (sec)");

/*
 * ISO
 */

SYSCTL_NODE(_net_bluetooth, OID_AUTO, iso, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth ISO family");

static int
bluetooth_set_iso_rtx_timeout_value(SYSCTL_HANDLER_ARGS)
{
	int		value;
	int		error;

	value = bluetooth_iso_rtx_timeout_value;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (bluetooth_hci_connect_timeout_value <= value &&
		    value <= INT_MAX / hz)
			bluetooth_iso_rtx_timeout_value = value;
		else
			error = EINVAL;
	}

	return (error);
} /* bluetooth_set_iso_rtx_timeout_value */

SYSCTL_PROC(_net_bluetooth_iso, OID_AUTO, rtx_timeout,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	&bluetooth_iso_rtx_timeout_value, 60,
	bluetooth_set_iso_rtx_timeout_value,
	"I", "ISO RTX timeout (sec)");

/*
 * Handle loading and unloading for this code.
 */

static int
bluetooth_modevent(module_t mod, int event, void *data)
{
	int	error = 0;

	switch (event) {
	case MOD_LOAD:
		break; 

	case MOD_UNLOAD:
		break; 

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
} /* bluetooth_modevent */

/*
 * Module
 */

static moduledata_t	bluetooth_mod = {
	"ng_bluetooth",
	bluetooth_modevent,
	NULL
};

DECLARE_MODULE(ng_bluetooth, bluetooth_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(ng_bluetooth, NG_BLUETOOTH_VERSION);
