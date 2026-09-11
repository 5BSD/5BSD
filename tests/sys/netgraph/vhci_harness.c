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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_hci_virt.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vhci_harness.h"

#define	VHCI_CTL_PATH	"/dev/" NG_HCI_VIRT_CTL_NAME

/* Our hook names on the ng_socket node; they mirror the peer hook names. */
#define	HOOK_RAW	"raw"
#define	HOOK_L2C	"l2c"
#define	HOOK_CTL	"ctl"

static void	vh_put16(uint8_t *p, uint16_t v);
static uint16_t	vh_get16(const uint8_t *p);
static void	vh_command(struct vhci_rig *, uint16_t opcode,
		    const void *rp, size_t rplen);

static void
vh_put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
vh_get16(const uint8_t *p)
{

	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

void
vh_require(void)
{
	struct stat sb;
	int id;

	if (geteuid() != 0)
		atf_tc_skip("must be run as root");

	id = modfind("ng_hci_virt");
	if (id < 0 && kldload("ng_hci_virt") < 0 && errno != EEXIST) {
		/*
		 * The kernel linker reports every load failure other than
		 * EEXIST as ENOEXEC (kern_linker.c calls this "less than
		 * ideal"), so a policy denial reads as a file-format problem.
		 * On a system running the capability plane, module loading
		 * is gated and a root shell holds no claim on it; the
		 * sanctioned path is the sysextd broker.  Say so, because a
		 * literal "Exec format error" sends the reader off to check
		 * module versions and build timestamps for nothing.
		 */
		if (errno == ENOEXEC)
			atf_tc_skip("ng_hci_virt(4) could not be loaded "
			    "(ENOEXEC, which the linker also uses for a "
			    "policy denial): if the capability plane is "
			    "active, load it first with "
			    "\"sysextctl load ng_hci_virt\"");
		atf_tc_skip("ng_hci_virt(4) is not available: %s",
		    strerror(errno));
	}

	if (stat(VHCI_CTL_PATH, &sb) != 0)
		atf_tc_skip("%s is not present", VHCI_CTL_PATH);
}

/*
 * Answer one HCI command the unit has just sent.  The command is read back
 * off /dev/vhciN (proving the kernel really emitted it), then completed with
 * a Command_Complete event carrying rp/rplen as the return parameters.
 *
 * ng_hci allows exactly one outstanding command, so callers must issue and
 * complete commands one at a time -- which is what a real controller sees.
 */
static void
vh_command(struct vhci_rig *r, uint16_t opcode, const void *rp, size_t rplen)
{
	uint8_t cmd[VH_BUFSZ], evt[VH_BUFSZ];
	ssize_t n;

	/* Submit the command down the ng_hci "raw" hook, as hccontrol does. */
	cmd[0] = NG_HCI_CMD_PKT;
	vh_put16(&cmd[1], opcode);
	cmd[3] = 0;			/* no command parameters */
	ATF_REQUIRE_MSG(NgSendData(r->ds, HOOK_RAW, cmd, 4) == 0,
	    "NgSendData(raw): %s", strerror(errno));

	/* It must come back out of the controller endpoint verbatim. */
	n = vh_capture(r, cmd, sizeof(cmd), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n == 4, "opcode %#x: expected a 4-octet command "
	    "packet, got %zd", opcode, n);
	ATF_REQUIRE_EQ(NG_HCI_CMD_PKT, cmd[0]);
	ATF_REQUIRE_EQ(opcode, vh_get16(&cmd[1]));

	/* Command_Complete: num_cmd_pkts, opcode, return parameters. */
	ATF_REQUIRE(rplen + 5 <= sizeof(evt));
	evt[0] = NG_HCI_EVENT_PKT;
	evt[1] = NG_HCI_EVENT_COMMAND_COMPL;
	evt[2] = (uint8_t)(3 + rplen);
	evt[3] = 1;			/* num_cmd_pkts */
	vh_put16(&evt[4], opcode);
	memcpy(&evt[6], rp, rplen);
	vh_inject(r, evt, 6 + rplen);
}

void
vh_up(struct vhci_rig *r)
{
	struct ngm_mkpeer mkp;
	struct ngm_connect con;
	uint8_t rp[16];
	char path[NG_PATHSIZ];
	int unit;

	memset(r, 0, sizeof(*r));
	r->ctl_fd = r->dev_fd = r->cs = r->ds = -1;

	r->ctl_fd = open(VHCI_CTL_PATH, O_RDWR);
	ATF_REQUIRE_MSG(r->ctl_fd >= 0, "open %s: %s", VHCI_CTL_PATH,
	    strerror(errno));

	ATF_REQUIRE_MSG(ioctl(r->ctl_fd, VHCI_CREATE, &unit) == 0,
	    "VHCI_CREATE: %s", strerror(errno));
	r->unit = unit;
	r->created = true;

	snprintf(path, sizeof(path), "/dev/%s%d", NG_HCI_VIRT_NODE_TYPE, unit);
	r->dev_fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(r->dev_fd >= 0, "open %s: %s", path, strerror(errno));

	ATF_REQUIRE_MSG(NgMkSockNode(NULL, &r->cs, &r->ds) == 0,
	    "NgMkSockNode: %s", strerror(errno));

	snprintf(r->hci, sizeof(r->hci), "%s%dhci", NG_HCI_VIRT_NODE_TYPE,
	    unit);
	snprintf(r->l2cap, sizeof(r->l2cap), "%s%dl2cap",
	    NG_HCI_VIRT_NODE_TYPE, unit);

	/* mkpeer vhciN: hci hook drv */
	memset(&mkp, 0, sizeof(mkp));
	strlcpy(mkp.type, "hci", sizeof(mkp.type));
	strlcpy(mkp.ourhook, NG_HCI_VIRT_HOOK, sizeof(mkp.ourhook));
	strlcpy(mkp.peerhook, NG_HCI_HOOK_DRV, sizeof(mkp.peerhook));
	snprintf(path, sizeof(path), "%s%d:", NG_HCI_VIRT_NODE_TYPE, unit);
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, path, NGM_GENERIC_COOKIE, NGM_MKPEER,
	    &mkp, sizeof(mkp)) >= 0, "mkpeer hci: %s", strerror(errno));

	snprintf(path, sizeof(path), "%s%d:%s", NG_HCI_VIRT_NODE_TYPE, unit,
	    NG_HCI_VIRT_HOOK);
	ATF_REQUIRE_MSG(NgNameNode(r->cs, path, "%s", r->hci) >= 0,
	    "name hci node: %s", strerror(errno));

	/* mkpeer vhciNhci: l2cap acl hci */
	memset(&mkp, 0, sizeof(mkp));
	strlcpy(mkp.type, "l2cap", sizeof(mkp.type));
	strlcpy(mkp.ourhook, NG_HCI_HOOK_ACL, sizeof(mkp.ourhook));
	strlcpy(mkp.peerhook, NG_L2CAP_HOOK_HCI, sizeof(mkp.peerhook));
	snprintf(path, sizeof(path), "%s:", r->hci);
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, path, NGM_GENERIC_COOKIE, NGM_MKPEER,
	    &mkp, sizeof(mkp)) >= 0, "mkpeer l2cap: %s", strerror(errno));

	snprintf(path, sizeof(path), "%s:%s", r->hci, NG_HCI_HOOK_ACL);
	ATF_REQUIRE_MSG(NgNameNode(r->cs, path, "%s", r->l2cap) >= 0,
	    "name l2cap node: %s", strerror(errno));

	/* connect . raw vhciNhci: raw */
	memset(&con, 0, sizeof(con));
	snprintf(con.path, sizeof(con.path), "%s:", r->hci);
	strlcpy(con.ourhook, HOOK_RAW, sizeof(con.ourhook));
	strlcpy(con.peerhook, NG_HCI_HOOK_RAW, sizeof(con.peerhook));
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, ".", NGM_GENERIC_COOKIE, NGM_CONNECT,
	    &con, sizeof(con)) >= 0, "connect raw: %s", strerror(errno));

	/* connect . l2c vhciNl2cap: l2c */
	memset(&con, 0, sizeof(con));
	snprintf(con.path, sizeof(con.path), "%s:", r->l2cap);
	strlcpy(con.ourhook, HOOK_L2C, sizeof(con.ourhook));
	strlcpy(con.peerhook, NG_L2CAP_HOOK_L2C, sizeof(con.peerhook));
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, ".", NGM_GENERIC_COOKIE, NGM_CONNECT,
	    &con, sizeof(con)) >= 0, "connect l2c: %s", strerror(errno));

	/* connect . ctl vhciNl2cap: ctl */
	memset(&con, 0, sizeof(con));
	snprintf(con.path, sizeof(con.path), "%s:", r->l2cap);
	strlcpy(con.ourhook, HOOK_CTL, sizeof(con.ourhook));
	strlcpy(con.peerhook, NG_L2CAP_HOOK_CTL, sizeof(con.peerhook));
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, ".", NGM_GENERIC_COOKIE, NGM_CONNECT,
	    &con, sizeof(con)) >= 0, "connect ctl: %s", strerror(errno));

	/*
	 * Bring the unit to NG_HCI_UNIT_READY the way a real host does.
	 *
	 * Read_Buffer_Size gives the unit ACL credits; without them
	 * ng_hci_send_data() never dequeues an outbound ACL packet and
	 * nothing the stack emits would ever reach the controller endpoint.
	 * Read_BD_ADDR gives the unit a non-zero BD_ADDR, without which
	 * NGM_HCI_NODE_INIT fails with ENXIO.
	 */
	/*
	 * The rig deliberately advertises a large ACL buffer count and never
	 * sends Number_Of_Completed_Packets: modelling controller-side flow
	 * control would make every case's assertions depend on when credits
	 * came back.  Cases must therefore stay well under this many
	 * outbound ACL packets, which is easy -- they exchange single frames.
	 */
	memset(rp, 0, sizeof(rp));
	rp[0] = 0x00;			/* status: success */
	vh_put16(&rp[1], 27);		/* max_acl_size: the LE minimum */
	rp[3] = 0;			/* max_sco_size */
	vh_put16(&rp[4], 255);		/* num_acl_pkt */
	vh_put16(&rp[6], 0);		/* num_sco_pkt */
	vh_command(r, NG_HCI_OPCODE(NG_HCI_OGF_INFO,
	    NG_HCI_OCF_READ_BUFFER_SIZE), rp, 8);

	memset(rp, 0, sizeof(rp));
	rp[0] = 0x00;			/* status: success */
	rp[1] = 0x11;			/* BD_ADDR 00:00:00:00:00:11 */
	vh_command(r, NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_BDADDR),
	    rp, 7);

	snprintf(path, sizeof(path), "%s:", r->hci);
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, path, NGM_HCI_COOKIE,
	    NGM_HCI_NODE_INIT, NULL, 0) >= 0, "NODE_INIT: %s",
	    strerror(errno));

	/* Drain the NODE_UP notifications the init raises. */
	while (vh_recv_msg(r, 50) != NULL)
		;
}

void
vh_down(struct vhci_rig *r)
{
	char path[NG_PATHSIZ];

	if (r->cs >= 0) {
		if (r->l2cap[0] != '\0') {
			snprintf(path, sizeof(path), "%s:", r->l2cap);
			(void)NgSendMsg(r->cs, path, NGM_GENERIC_COOKIE,
			    NGM_SHUTDOWN, NULL, 0);
		}
		if (r->hci[0] != '\0') {
			snprintf(path, sizeof(path), "%s:", r->hci);
			(void)NgSendMsg(r->cs, path, NGM_GENERIC_COOKIE,
			    NGM_SHUTDOWN, NULL, 0);
		}
	}
	if (r->dev_fd >= 0)
		close(r->dev_fd);
	if (r->created && r->ctl_fd >= 0)
		(void)ioctl(r->ctl_fd, VHCI_DESTROY, &r->unit);
	if (r->ctl_fd >= 0)
		close(r->ctl_fd);
	if (r->cs >= 0)
		close(r->cs);
	if (r->ds >= 0)
		close(r->ds);
	r->ctl_fd = r->dev_fd = r->cs = r->ds = -1;
	r->created = false;
}

void
vh_inject(struct vhci_rig *r, const void *pkt, size_t len)
{
	ssize_t n;

	n = write(r->dev_fd, pkt, len);
	ATF_REQUIRE_MSG(n >= 0, "write(/dev/vhci%d): %s", r->unit,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG((size_t)n, len, "short write: %zd of %zu", n, len);
}

ssize_t
vh_capture(struct vhci_rig *r, void *buf, size_t len, int ms)
{
	struct pollfd pfd;
	ssize_t n;

	pfd.fd = r->dev_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	for (;;) {
		int rc = poll(&pfd, 1, ms);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			atf_tc_fail("poll(/dev/vhci%d): %s", r->unit,
			    strerror(errno));
		}
		if (rc == 0)
			return (-1);
		break;
	}

	n = read(r->dev_fd, buf, len);
	ATF_REQUIRE_MSG(n >= 0, "read(/dev/vhci%d): %s", r->unit,
	    strerror(errno));

	return (n);
}

void
vh_expect_quiet(struct vhci_rig *r, int ms)
{
	uint8_t buf[VH_BUFSZ];
	ssize_t n;

	n = vh_capture(r, buf, sizeof(buf), ms);
	if (n < 0)
		return;

	atf_tc_fail("expected no host->controller packet, but the kernel "
	    "emitted %zd octets starting %#x %#x %#x", n, buf[0],
	    n > 1 ? buf[1] : 0, n > 2 ? buf[2] : 0);
}

void
vh_le_connect(struct vhci_rig *r, uint16_t handle, uint8_t role)
{
	uint8_t evt[22];

	/*
	 * HCI LE Connection Complete (Vol 4 Part E 7.7.65.1).  ng_hci turns
	 * this into a connection descriptor, then LP_ConnectInd followed by
	 * LP_ConnectCfm, which is what makes ng_l2cap create the link and
	 * its ATT and SMP fixed channels.  Nothing else is required: LE
	 * connections are already established at the controller when the
	 * event is delivered, so no Accept_Connection handshake happens.
	 */
	r->handle = handle;
	memset(r->bdaddr, 0, sizeof(r->bdaddr));
	r->bdaddr[0] = 0x22;

	evt[0] = NG_HCI_EVENT_PKT;
	evt[1] = NG_HCI_EVENT_LE;
	evt[2] = 19;			/* parameter length */
	evt[3] = NG_HCI_LEEV_CON_COMPL;
	evt[4] = 0x00;			/* status: success */
	vh_put16(&evt[5], handle);
	evt[7] = role;			/* 0x00 Central, 0x01 Peripheral */
	evt[8] = 0x00;			/* peer address type: public */
	memcpy(&evt[9], r->bdaddr, 6);
	vh_put16(&evt[15], 24);		/* connection interval */
	vh_put16(&evt[17], 0);		/* peripheral latency */
	vh_put16(&evt[19], 42);		/* supervision timeout */
	evt[21] = 0x00;			/* central clock accuracy */

	vh_inject(r, evt, sizeof(evt));

	/* Let the LP_ConnectInd/Cfm round trip settle. */
	while (vh_recv_msg(r, 100) != NULL)
		;
}

void
vh_send_bframe(struct vhci_rig *r, uint16_t cid, const void *payload,
    size_t len)
{
	uint8_t pkt[VH_BUFSZ];

	ATF_REQUIRE(len + 9 <= sizeof(pkt));

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	/* PB = NG_HCI_LE_PACKET_START (0x0), BC = 0. */
	vh_put16(&pkt[1], r->handle);
	vh_put16(&pkt[3], (uint16_t)(len + 4));	/* ACL payload length */
	vh_put16(&pkt[5], (uint16_t)len);	/* L2CAP length */
	vh_put16(&pkt[7], cid);			/* L2CAP CID */
	memcpy(&pkt[9], payload, len);

	vh_inject(r, pkt, len + 9);
}

ssize_t
vh_recv_bframe(struct vhci_rig *r, uint16_t *cid, void *buf, size_t len,
    int ms)
{
	uint8_t pkt[VH_BUFSZ];
	uint16_t l2len;
	ssize_t n;

	for (;;) {
		n = vh_capture(r, pkt, sizeof(pkt), ms);
		if (n < 0)
			return (-1);
		if (n > 0 && pkt[0] == NG_HCI_ACL_DATA_PKT)
			break;
		/*
		 * An HCI command (for example an LE Connection Update the
		 * stack decided to issue) is not a B-frame.  Callers that
		 * care about commands use vh_capture() directly, so a
		 * command reaching here is a protocol error in the case.
		 */
		atf_tc_fail("expected an ACL frame, got packet type %#x",
		    pkt[0]);
	}

	ATF_REQUIRE_MSG(n >= 9, "runt ACL frame, %zd octets", n);
	l2len = vh_get16(&pkt[5]);
	*cid = vh_get16(&pkt[7]);
	ATF_REQUIRE_MSG((size_t)n == (size_t)l2len + 9,
	    "L2CAP length %u does not match frame length %zd", l2len, n);
	ATF_REQUIRE(l2len <= len);
	memcpy(buf, &pkt[9], l2len);

	return (l2len);
}

/*
 * Read one datagram off the netgraph data socket, discarding anything that
 * did not arrive on the wanted hook.  The ng_hci "raw" hook receives a copy
 * of every packet in both directions, so it is drained and ignored here.
 */
static ssize_t
vh_recv_hook(struct vhci_rig *r, const char *want, void *buf, size_t len,
    int ms)
{
	struct pollfd pfd;
	char hook[NG_HOOKSIZ];
	u_char *data;
	struct timeval start, now;
	int elapsed, rc;
	ssize_t n;

	gettimeofday(&start, NULL);
	for (;;) {
		gettimeofday(&now, NULL);
		elapsed = (int)((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_usec - start.tv_usec) / 1000);
		if (elapsed >= ms)
			return (-1);

		pfd.fd = r->ds;
		pfd.events = POLLIN;
		pfd.revents = 0;
		rc = poll(&pfd, 1, ms - elapsed);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			atf_tc_fail("poll(ng data): %s", strerror(errno));
		}
		if (rc == 0)
			return (-1);

		data = NULL;
		n = NgAllocRecvData(r->ds, &data, hook);
		if (n < 0) {
			free(data);
			atf_tc_fail("NgAllocRecvData: %s", strerror(errno));
		}
		if (strcmp(hook, want) == 0) {
			ATF_REQUIRE((size_t)n <= len);
			memcpy(buf, data, (size_t)n);
			free(data);
			return (n);
		}
		free(data);
	}
}

ssize_t
vh_recv_l2c(struct vhci_rig *r, uint16_t *idtype, void *buf, size_t len,
    int ms)
{
	uint8_t frame[VH_BUFSZ];
	ssize_t n;

	n = vh_recv_hook(r, HOOK_L2C, frame, sizeof(frame), ms);
	if (n < 0)
		return (-1);

	ATF_REQUIRE_MSG(n >= 2, "runt l2c frame, %zd octets", n);
	*idtype = vh_get16(frame);
	ATF_REQUIRE((size_t)(n - 2) <= len);
	memcpy(buf, &frame[2], (size_t)(n - 2));

	return (n - 2);
}

struct ng_mesg *
vh_recv_msg(struct vhci_rig *r, int ms)
{
	struct pollfd pfd;
	struct ng_mesg *m = NULL;
	char path[NG_PATHSIZ];
	int rc;

	for (;;) {
		pfd.fd = r->cs;
		pfd.events = POLLIN;
		pfd.revents = 0;
		rc = poll(&pfd, 1, ms);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			atf_tc_fail("poll(ng ctl): %s", strerror(errno));
		}
		if (rc == 0)
			return (NULL);
		break;
	}

	if (NgAllocRecvMsg(r->cs, &m, path) < 0) {
		free(m);
		atf_tc_fail("NgAllocRecvMsg: %s", strerror(errno));
	}

	return (m);
}
