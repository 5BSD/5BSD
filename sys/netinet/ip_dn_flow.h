/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2002-2009 Luigi Rizzo, Universita` di Pisa
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

#ifndef _NETINET_IP_DN_FLOW_H_
#define _NETINET_IP_DN_FLOW_H_

#include <sys/types.h>
#include <netinet/in.h>

/* Shared Dummynet flow ABI. Preserve its historical name and field layout. */
struct ipfw_flow_id {
	uint32_t	dst_ip;
	uint32_t	src_ip;
	uint16_t	dst_port;
	uint16_t	src_port;
	uint8_t		fib;	/* XXX: must be uint16_t */
	uint8_t		proto;
	uint8_t		_flags;	/* protocol-specific flags */
	uint8_t		addr_type; /* 4=ip4, 6=ip6, 1=ether ? */
	struct in6_addr dst_ip6;
	struct in6_addr src_ip6;
	uint32_t	flow_id6;
	uint32_t	extra; /* queue/pipe or frag_id */
};

#define IS_IP4_FLOW_ID(id) ((id)->addr_type == 4)
#define IS_IP6_FLOW_ID(id) ((id)->addr_type == 6)

#define DN_APPLY_MASK(addr,mask)	do {					\
    (addr)->__u6_addr.__u6_addr32[0] &= (mask)->__u6_addr.__u6_addr32[0]; \
    (addr)->__u6_addr.__u6_addr32[1] &= (mask)->__u6_addr.__u6_addr32[1]; \
    (addr)->__u6_addr.__u6_addr32[2] &= (mask)->__u6_addr.__u6_addr32[2]; \
    (addr)->__u6_addr.__u6_addr32[3] &= (mask)->__u6_addr.__u6_addr32[3]; \
} while (0)

#endif
