/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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
 */

/*
 * vhcitool - userspace virtual Bluetooth controller.
 *
 * Spins up one or more virtual HCI controllers with NO hardware.  Each
 * controller is a /dev/vhciN endpoint of the ng_hci_virt kernel node bound
 * to an in-process HCI controller emulator (the same spec-oracle state
 * machine used by the blued test suite).  By default vhcitool also wires
 * the standard ng_hci (and, with -L, ng_l2cap) nodes on top of each
 * endpoint and names the ng_hci node "vhciNhci" so the daemons can open the
 * adapter exactly as they would a real one:
 *
 *     blued -a vhci0
 *
 * The controller <-> host contract is byte-identical to ng_ubt, so the
 * whole stack (ng_hci / ng_l2cap / blued) attaches with zero changes.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>

#include <netgraph/bluetooth/include/ng_hci_virt.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "hci_emulator.h"

#define	VHCI_CTL_PATH	"/dev/" NG_HCI_VIRT_CTL_NAME

struct vctrl {
	int		unit;		/* /dev/vhciN unit number */
	int		fd;		/* open /dev/vhciN */
	bool		created;	/* VHCI_CREATE succeeded */
	bool		wired;		/* ng_hci mkpeer succeeded */
	struct hci_emu	*emu;		/* controller brain */
};

static volatile sig_atomic_t	stop;

static void
on_signal(int sig __unused)
{
	stop = 1;
}

/*
 * Emulator output callback: an event/ACL/SCO/ISO packet the controller
 * wants to hand to the host.  Write it up the /dev/vhciN endpoint; the
 * kernel forwards it to ng_hci verbatim.
 */
static void
emu_output(void *ctx, const uint8_t *pkt, size_t len)
{
	struct vctrl *c = ctx;
	ssize_t n;

	n = write(c->fd, pkt, len);
	if (n < 0)
		warn("vhci%d: write", c->unit);
	else if ((size_t)n != len)
		warnx("vhci%d: short write (%zd of %zu)", c->unit, n, len);
}

/* Build the standard netgraph topology on top of one /dev/vhciN endpoint. */
static int
wire_stack(int unit, bool add_l2cap)
{
	struct ngm_mkpeer mkp;
	char path[NG_PATHSIZ];
	char hciname[NG_NODESIZ];
	int cs, ds, error = 0;

	if (NgMkSockNode(NULL, &cs, &ds) < 0) {
		warn("vhci%d: NgMkSockNode", unit);
		return (-1);
	}

	/* mkpeer vhciN: hci hook drv  -> creates the ng_hci node. */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "hci");
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_HCI_VIRT_HOOK);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "drv");
	snprintf(path, sizeof(path), "%s%d:", NG_HCI_VIRT_NODE_TYPE, unit);
	if (NgSendMsg(cs, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp,
	    sizeof(mkp)) < 0) {
		warn("vhci%d: mkpeer hci", unit);
		error = -1;
		goto out;
	}

	/* name vhciN:hook  vhciNhci  (so bt_devopen("vhciN") resolves). */
	snprintf(hciname, sizeof(hciname), "%s%dhci", NG_HCI_VIRT_NODE_TYPE,
	    unit);
	snprintf(path, sizeof(path), "%s%d:%s", NG_HCI_VIRT_NODE_TYPE, unit,
	    NG_HCI_VIRT_HOOK);
	if (NgNameNode(cs, path, "%s", hciname) < 0) {
		warn("vhci%d: name hci node", unit);
		error = -1;
		goto out;
	}

	if (add_l2cap) {
		char l2name[NG_NODESIZ];

		/* mkpeer vhciNhci: l2cap acl hci */
		memset(&mkp, 0, sizeof(mkp));
		snprintf(mkp.type, sizeof(mkp.type), "l2cap");
		snprintf(mkp.ourhook, sizeof(mkp.ourhook), "acl");
		snprintf(mkp.peerhook, sizeof(mkp.peerhook), "hci");
		snprintf(path, sizeof(path), "%s:", hciname);
		if (NgSendMsg(cs, path, NGM_GENERIC_COOKIE, NGM_MKPEER, &mkp,
		    sizeof(mkp)) < 0) {
			warn("vhci%d: mkpeer l2cap", unit);
			error = -1;
			goto out;
		}
		snprintf(l2name, sizeof(l2name), "%s%dl2cap",
		    NG_HCI_VIRT_NODE_TYPE, unit);
		snprintf(path, sizeof(path), "%s:acl", hciname);
		if (NgNameNode(cs, path, "%s", l2name) < 0) {
			warn("vhci%d: name l2cap node", unit);
			error = -1;
			goto out;
		}
	}

out:
	close(cs);
	close(ds);
	return (error);
}

static int
ctrl_create(int ctl_fd, struct vctrl *c, bool wire, bool add_l2cap)
{
	char path[32];
	int unit;
	uint8_t bd_addr[6];

	if (ioctl(ctl_fd, VHCI_CREATE, &unit) < 0) {
		warn("VHCI_CREATE");
		return (-1);
	}
	c->unit = unit;
	c->created = true;

	snprintf(path, sizeof(path), "/dev/%s%d", NG_HCI_VIRT_NODE_TYPE, unit);
	c->fd = open(path, O_RDWR);
	if (c->fd < 0) {
		warn("open %s", path);
		return (-1);
	}

	c->emu = hci_emu_new();
	if (c->emu == NULL) {
		warnx("vhci%d: cannot allocate emulator", unit);
		return (-1);
	}
	hci_emu_set_output(c->emu, emu_output, c);

	/* Pin a deterministic, unique public address: 00:00:00:00:00:(unit+1) */
	memset(bd_addr, 0, sizeof(bd_addr));
	bd_addr[0] = (uint8_t)(unit + 1);
	hci_emu_set_bd_addr(c->emu, bd_addr);

	if (wire) {
		if (wire_stack(unit, add_l2cap) < 0)
			return (-1);
		c->wired = true;
	}

	printf("vhci%d: controller up on /dev/%s%d", unit,
	    NG_HCI_VIRT_NODE_TYPE, unit);
	if (wire)
		printf(" (adapter \"%s%d\")", NG_HCI_VIRT_NODE_TYPE, unit);
	printf("\n");

	return (0);
}

static void
ctrl_destroy(int ctl_fd, struct vctrl *c)
{
	if (c->emu != NULL)
		hci_emu_free(c->emu);
	if (c->fd >= 0)
		close(c->fd);
	if (c->created)
		(void)ioctl(ctl_fd, VHCI_DESTROY, &c->unit);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: vhcitool [-n count] [-l] [-L] [-W]\n"
	    "    -n count  number of virtual controllers (default 1)\n"
	    "    -l        link controllers pairwise into a shared air\n"
	    "    -L        also create ng_l2cap nodes on top of each adapter\n"
	    "    -W        do not wire ng_hci; expose the raw /dev/vhciN pipe\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	struct vctrl *ctrls;
	struct pollfd *pfds;
	int ctl_fd, i, ch, rc = EX_OK;
	long count = 1;
	bool link = false, add_l2cap = false, wire = true;

	while ((ch = getopt(argc, argv, "n:lLW")) != -1) {
		switch (ch) {
		case 'n':
			count = strtol(optarg, NULL, 10);
			if (count < 1 || count > NG_HCI_VIRT_MAX_UNITS)
				errx(EX_USAGE, "count must be 1..%d",
				    NG_HCI_VIRT_MAX_UNITS);
			break;
		case 'l':
			link = true;
			break;
		case 'L':
			add_l2cap = true;
			break;
		case 'W':
			wire = false;
			break;
		default:
			usage();
		}
	}

	ctl_fd = open(VHCI_CTL_PATH, O_RDWR);
	if (ctl_fd < 0)
		err(EX_OSFILE, "open %s (is ng_hci_virt loaded?)",
		    VHCI_CTL_PATH);

	ctrls = calloc(count, sizeof(*ctrls));
	pfds = calloc(count, sizeof(*pfds));
	if (ctrls == NULL || pfds == NULL)
		err(EX_OSERR, "calloc");
	for (i = 0; i < count; i++)
		ctrls[i].fd = -1;

	for (i = 0; i < count; i++) {
		if (ctrl_create(ctl_fd, &ctrls[i], wire, add_l2cap) < 0) {
			rc = EX_OSERR;
			goto cleanup;
		}
	}

	/* Link adjacent pairs into a shared simulated air. */
	if (link) {
		for (i = 0; i + 1 < count; i += 2) {
			hci_emu_link(ctrls[i].emu, ctrls[i + 1].emu);
			printf("linked vhci%d <-> vhci%d\n",
			    ctrls[i].unit, ctrls[i + 1].unit);
		}
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	printf("vhcitool: %ld controller(s) running; ^C to stop\n", count);

	/* Pump: read host->controller packets, feed the emulator brain. */
	while (!stop) {
		int n;

		for (i = 0; i < count; i++) {
			pfds[i].fd = ctrls[i].fd;
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
		}

		n = poll(pfds, count, -1);
		if (n < 0) {
			if (errno == EINTR)
				break;
			warn("poll");
			break;
		}

		for (i = 0; i < count; i++) {
			uint8_t buf[NG_HCI_VIRT_MTU];
			ssize_t r;

			if ((pfds[i].revents & POLLIN) == 0)
				continue;
			r = read(ctrls[i].fd, buf, sizeof(buf));
			if (r < 0) {
				if (errno == EINTR)
					continue;
				warn("vhci%d: read", ctrls[i].unit);
				continue;
			}
			if (r == 0)
				continue;
			hci_emu_input(ctrls[i].emu, buf, (size_t)r);
		}
	}

	printf("\nvhcitool: shutting down\n");

cleanup:
	for (i = 0; i < count; i++)
		ctrl_destroy(ctl_fd, &ctrls[i]);
	free(ctrls);
	free(pfds);
	close(ctl_fd);

	return (rc);
}
