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

#ifndef _DN_PACKET_H_
#define _DN_PACKET_H_

/* Shared packet handoff ABI. Retain names and layout for existing consumers. */
/*
 * For platforms that do not have SYSCTL support, we wrap the
 * SYSCTL_* into a function (one per file) to collect the values
 * into an array at module initialization. The wrapping macros,
 * SYSBEGIN() and SYSEND, are empty in the default case.
 */
#ifndef SYSBEGIN
#define SYSBEGIN(x)
#endif
#ifndef SYSEND
#define SYSEND
#endif

/*
 * Structure for collecting parameters to dummynet for ip6_output forwarding
 */
struct _ip6dn_args {
       struct ip6_pktopts *opt_or;
       int flags_or;
       struct ip6_moptions *im6o_or;
       struct ifnet *origifp_or;
       struct ifnet *ifp_or;
       struct sockaddr_in6 dst_or;
       u_long mtu_or;
};

/*
 * Arguments for calling ipfw_chk() and dummynet_io(). We put them
 * all into a structure because this way it is easier and more
 * efficient to pass variables around and extend the interface.
 */
struct ip_fw_args {
	uint32_t		flags;
#define	IPFW_ARGS_ETHER		0x00010000	/* valid ethernet header */
#define	IPFW_ARGS_NH4		0x00020000	/* IPv4 next hop in hopstore */
#define	IPFW_ARGS_NH6		0x00040000	/* IPv6 next hop in hopstore */
#define	IPFW_ARGS_NH4PTR	0x00080000	/* IPv4 next hop in next_hop */
#define	IPFW_ARGS_NH6PTR	0x00100000	/* IPv6 next hop in next_hop6 */
#define	IPFW_ARGS_REF		0x00200000	/* valid ipfw_rule_ref	*/
#define	IPFW_ARGS_IN		0x00400000	/* called on input */
#define	IPFW_ARGS_OUT		0x00800000	/* called on output */
#define	IPFW_ARGS_IP4		0x01000000	/* belongs to v4 ISR */
#define	IPFW_ARGS_IP6		0x02000000	/* belongs to v6 ISR */
#define	IPFW_ARGS_DROP		0x04000000	/* drop it (dummynet) */
#define	IPFW_ARGS_LENMASK	0x0000ffff	/* length of data in *mem */
#define	IPFW_ARGS_LENGTH(f)	((f) & IPFW_ARGS_LENMASK)
	/*
	 * On return, it points to the matching rule.
	 * On entry, rule.slot > 0 means the info is valid and
	 * contains the starting rule for an ipfw search.
	 * If chain_id == chain->id && slot >0 then jump to that slot.
	 * Otherwise, we locate the first rule >= rulenum:rule_id
	 */
	struct ipfw_rule_ref	rule;	/* match/restart info		*/

	struct ifnet		*ifp;	/* input/output interface	*/
	struct inpcb		*inp;
	union {
		/*
		 * next_hop[6] pointers can be used to point to next hop
		 * stored in rule's opcode to avoid copying into hopstore.
		 * Also, it is expected that all 0x1-0x10 flags are mutually
		 * exclusive.
		 */
		struct sockaddr_in	*next_hop;
		struct sockaddr_in6	*next_hop6;
		/* ipfw next hop storage */
		struct sockaddr_in	hopstore;
		struct ip_fw_nh6 {
			struct in6_addr sin6_addr;
			uint32_t	sin6_scope_id;
			uint16_t	sin6_port;
		} hopstore6;
	};
	union {
		struct mbuf	*m;	/* the mbuf chain		*/
		void		*mem;	/* or memory pointer		*/
	};
	struct ipfw_flow_id	f_id;	/* grabbed from IP header	*/
};

/* wrapper for freeing a packet, in case we need to do more work */
#ifndef FREE_PKT
#if defined(__linux__) || defined(_WIN32)
#define FREE_PKT(m)	netisr_dispatch(-1, m)
#else
#define FREE_PKT(m)	m_freem(m)
#endif
#endif /* !FREE_PKT */

static __inline uint16_t
cksum_add(uint16_t sum, uint16_t a)
{
	uint16_t res;

	res = sum + a;
	return (res + (res < a));
}

static __inline uint16_t
cksum_adjust(uint16_t oldsum, uint16_t old, uint16_t new)
{

	return (~cksum_add(cksum_add(~oldsum, ~old), new));
}

#endif
