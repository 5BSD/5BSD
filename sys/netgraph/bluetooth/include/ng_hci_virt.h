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
 * ng_hci_virt.h - virtual HCI controller transport.
 *
 * ng_hci_virt is a software stand-in for a physical Bluetooth controller
 * (the ng_ubt USB driver).  It presents the identical upstream netgraph
 * contract to ng_hci -- a single hook ("hook") that connects to the ng_hci
 * node's "drv" hook and carries type-prefixed HCI packets in BOTH
 * directions (see sys/netgraph/bluetooth/hci/ng_hci_main.c
 * ng_hci_drv_rcvdata()) -- so ng_hci / ng_l2cap / blued attach to it exactly
 * as they would to a real adapter, with no USB hardware present.
 *
 * The other side of the node is bridged to userspace through a per-instance
 * cloning character device, /dev/vhciN:
 *
 *   host -> controller  (HCI Command / ACL / SCO / ISO, type byte 0x01/
 *                         0x02/0x03/0x05): arrives down the netgraph hook
 *                         from ng_hci, is queued, and is delivered to
 *                         userspace via read(2).
 *   controller -> host  (HCI Event / ACL / SCO / ISO, type byte 0x04/
 *                         0x02/0x03/0x05): userspace write(2)s the raw
 *                         type-prefixed packet, which is forwarded up the
 *                         hook to ng_hci.
 *
 * The node performs NO parsing: the drv-hook wire format is byte-identical
 * to what the userspace controller emulator (usr.sbin/bluetooth/vhcitool)
 * already speaks, so the kernel half is a straight pipe.
 */

#ifndef _NETGRAPH_NG_HCI_VIRT_H_
#define _NETGRAPH_NG_HCI_VIRT_H_

#include <sys/ioccom.h>

/*
 * Netgraph node type and hook.  The hook name matches NG_UBT_HOOK ("hook")
 * so a mkpeer against ng_hci's "drv" hook reads the same as for ng_ubt.
 */
#define	NG_HCI_VIRT_NODE_TYPE	"vhci"
#define	NG_HCI_VIRT_HOOK	"hook"
#define	NGM_HCI_VIRT_COOKIE	1751500800

/* Control device: /dev/vhci.  Per-instance devices: /dev/vhci0 .. */
#define	NG_HCI_VIRT_CTL_NAME	"vhci"

/*
 * Maximum number of concurrent virtual controllers and the maximum size of
 * a single type-prefixed HCI packet exchanged over /dev/vhciN.  The largest
 * legitimate packet is an ACL/ISO data packet; 4096 bytes is comfortably
 * above the stack's L2CAP MTU while remaining a single-cluster copy.
 */
#define	NG_HCI_VIRT_MAX_UNITS	16
#define	NG_HCI_VIRT_MTU		4096

/*
 * Control-device ioctls (issued on /dev/vhci).
 *
 *   VHCI_CREATE  - allocate a virtual controller.  On success the kernel
 *                  writes back the unit number; the caller then opens the
 *                  matching /dev/vhciN.
 *   VHCI_DESTROY - tear down the virtual controller with the given unit
 *                  number.  Fails with EBUSY while /dev/vhciN is open.
 */
#define	VHCI_CREATE	_IOR('V', 100, int)
#define	VHCI_DESTROY	_IOW('V', 101, int)

#endif /* _NETGRAPH_NG_HCI_VIRT_H_ */
