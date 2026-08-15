/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PCI_E82545_MODEL_H_
#define	_PCI_E82545_MODEL_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * TCTL is writable independently of its enable transition.  Keep the
 * register's implemented bits on every write; callers separately perform
 * the side effects needed when E1000_TCTL_EN changes state.
 */
static inline uint32_t
pci_e82545_tctl_value(uint32_t value)
{

	return (value & UINT32_C(0x017ffffa));
}

/*
 * Validate the lengths supplied by the guest's context descriptor before
 * entering the segmentation loop.  In particular, an MSS of zero would make
 * the loop fail to advance, and the advertised payload must be backed by the
 * packet descriptors collected for this request.
 */
static inline bool
pci_e82545_tso_lengths_valid(uint32_t packet_length,
    uint32_t header_length, uint32_t payload_length, uint32_t mss)
{

	return (mss != 0 && header_length <= packet_length &&
	    payload_length <= packet_length - header_length);
}

/*
 * Check the minimum IP header bytes used by the segmentation path without
 * permitting addition to wrap.  IPv4 needs the total-length and ID fields;
 * IPv6 payload-length calculation requires the complete fixed header.
 */
static inline bool
pci_e82545_tso_ip_header_valid(uint32_t header_length,
    uint32_t ip_start, bool ipv4)
{
	uint32_t required;

	required = ipv4 ? 6U : 40U;
	return (ip_start <= header_length &&
	    required <= header_length - ip_start);
}

/*
 * Number of receive descriptors a packet of 'len' bytes consumes, given the
 * per-descriptor buffer size.  The count is clamped at maxpktdesc, the number
 * of descriptors that were actually mapped into the iovec and verified free.
 *
 * The clamp is load-bearing, not defensive rounding: the receive path derives
 * maxpktdesc from the configured maximum packet size, but re-adding a stripped
 * CRC (or padding a runt up to the minimum Ethernet length) can push the true
 * segment count one descriptor past maxpktdesc.  Consuming that extra segment
 * would read past the mapped iovec and advance RDH beyond RDT.
 */
static inline int
pci_e82545_rx_descriptor_count(uint32_t len, int bufsz, int maxpktdesc)
{
	int n;

	if (bufsz <= 0 || maxpktdesc <= 0 || len == 0)
		return (0);
	n = (int)(((uint64_t)len + (uint32_t)bufsz - 1U) / (uint32_t)bufsz);
	if (n > maxpktdesc)
		n = maxpktdesc;
	return (n);
}

#endif /* _PCI_E82545_MODEL_H_ */
