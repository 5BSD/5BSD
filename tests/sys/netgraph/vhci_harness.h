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

/*
 * vhci_harness - a raw frame injector/capturer for the Bluetooth netgraph
 * stack, built on ng_hci_virt(4).
 *
 * The test process *is* the controller.  It opens /dev/vhciN, so every
 * host->controller octet the kernel emits (HCI commands and ACL data) is
 * read(2) back verbatim, and every controller->host octet (HCI events and
 * ACL data) is write(2)n verbatim.  Nothing between the assertion and the
 * wire interprets the bytes.
 *
 * Two more observation points are wired to an ng_socket(4) node:
 *
 *   "raw"  <- ng_hci "raw" hook.  Used to *submit* HCI commands the way
 *             hccontrol(8) does, so the unit can be brought to
 *             NG_HCI_UNIT_READY through the real code path.
 *   "l2c"  <- ng_l2cap "l2c" hook.  Carries L2CAP payloads delivered to
 *             the upper layer, plus the L2CA_* control responses, so a
 *             test can assert that a frame really reached the top of
 *             L2CAP rather than merely failing to provoke an answer.
 *   "ctl"  <- ng_l2cap "ctl" hook.  Carries L2CA_ConnectInd and friends.
 *
 * Topology:
 *
 *   /dev/vhciN <-> [vhciN] hook---drv [vhciNhci] acl---hci [vhciNl2cap]
 *                                       raw                l2c    ctl
 *                                        |                  |      |
 *                                        +----- ng_socket ---+------+
 */

#ifndef _VHCI_HARNESS_H_
#define _VHCI_HARNESS_H_

#include <sys/types.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>

#include <stdbool.h>
#include <stdint.h>

/* Largest frame any case here exchanges, comfortably under the vhci MTU. */
#define	VH_BUFSZ	1024

/* Default wait for a frame the kernel is expected to emit. */
#define	VH_TIMEO_MS	1000

/*
 * Wait proving a frame is *not* emitted.  The kernel paths under test are
 * synchronous with respect to the injection (netgraph queues, no timers),
 * so a quarter second is generous; it is not a race, it is a settle.
 */
#define	VH_QUIET_MS	250

struct vhci_rig {
	int		ctl_fd;		/* /dev/vhci control device */
	int		dev_fd;		/* /dev/vhciN controller endpoint */
	int		unit;		/* vhci unit number */
	int		cs;		/* netgraph control socket */
	int		ds;		/* netgraph data socket */
	bool		created;	/* VHCI_CREATE succeeded */
	char		hci[NG_NODESIZ];	/* ng_hci node name */
	char		l2cap[NG_NODESIZ];	/* ng_l2cap node name */
	uint8_t		bdaddr[6];	/* peer address of the LE link */
	uint16_t	handle;		/* connection handle of the LE link */
};

/*
 * Skip the calling test unless ng_hci_virt(4) is loadable and /dev/vhci is
 * present.  Must be called first in every test body.
 */
void	vh_require(void);

/*
 * Bring up a virtual controller with ng_hci and ng_l2cap wired on top,
 * drive it to NG_HCI_UNIT_READY through the real HCI command path, and
 * attach the observation sockets.  Registers an atf cleanup-safe teardown
 * via vh_down(), which the caller must invoke.
 */
void	vh_up(struct vhci_rig *);
void	vh_down(struct vhci_rig *);

/* Raw inject: one type-prefixed controller->host packet. */
void	vh_inject(struct vhci_rig *, const void *, size_t);

/*
 * Raw capture: one type-prefixed host->controller packet.  Returns the
 * length, or -1 if nothing arrived within ms milliseconds.
 */
ssize_t	vh_capture(struct vhci_rig *, void *, size_t, int ms);

/* Fail the test unless nothing at all is emitted within ms milliseconds. */
void	vh_expect_quiet(struct vhci_rig *, int ms);

/*
 * Raise an LE ACL link into L2CAP by injecting an LE Connection Complete
 * meta event.  role is 0x00 (we are Central) or 0x01 (we are Peripheral).
 */
void	vh_le_connect(struct vhci_rig *, uint16_t handle, uint8_t role);

/* Inject one complete L2CAP B-frame on cid over the LE link. */
void	vh_send_bframe(struct vhci_rig *, uint16_t cid, const void *,
	    size_t);

/*
 * Capture the next ACL frame the kernel emits, strip the HCI and L2CAP
 * headers, and return the payload.  *cid receives the L2CAP channel.
 * Returns the payload length, or -1 on timeout.
 */
ssize_t	vh_recv_bframe(struct vhci_rig *, uint16_t *cid, void *, size_t,
	    int ms);

/*
 * Capture the next frame delivered up the ng_l2cap "l2c" hook.  *idtype
 * receives the 2-octet id-type prefix ng_l2cap prepends.  Returns the
 * length of the remainder (the L2CAP header plus payload), or -1.
 */
ssize_t	vh_recv_l2c(struct vhci_rig *, uint16_t *idtype, void *, size_t,
	    int ms);

/*
 * Capture the next netgraph control message arriving on the control
 * socket (from the l2c/ctl hooks).  Caller frees.  NULL on timeout.
 */
struct ng_mesg *vh_recv_msg(struct vhci_rig *, int ms);

#endif /* _VHCI_HARNESS_H_ */
