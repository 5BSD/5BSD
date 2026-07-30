/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Private lwIP configuration for the capability-mode NetworkCmp provider.
 */
#ifndef _LWIPCMP_LWIPOPTS_H_
#define	_LWIPCMP_LWIPOPTS_H_

#define	NO_SYS				1
#define	SYS_LIGHTWEIGHT_PROT		0
#define	LWIP_NETCONN			0
#define	LWIP_SOCKET			0
#define	LWIP_NETIF_API			0

#define	LWIP_IPV4			1
#define	LWIP_IPV6			1
#define	LWIP_ETHERNET			1
#define	LWIP_ARP			1
#define	LWIP_ICMP			1
#define	LWIP_ICMP6			1
#define	LWIP_TCP			1
#define	LWIP_UDP			1
#define	LWIP_DNS			1
#define	LWIP_DHCP			1
#define	LWIP_DHCP6			1

#define	MEM_LIBC_MALLOC			1
#define	MEMP_MEM_MALLOC			1
#define	MEM_ALIGNMENT			(sizeof(void *))
#define	MEM_SIZE			(1024 * 1024)
#define	PBUF_POOL_SIZE			1024
#define	PBUF_POOL_BUFSIZE		2048
#define	MEMP_NUM_TCP_PCB		1024
#define	MEMP_NUM_TCP_PCB_LISTEN		128
#define	MEMP_NUM_UDP_PCB		1024
#define	MEMP_NUM_TCP_SEG		4096
#define	MEMP_NUM_ARP_QUEUE		256
#define	TCP_MSS				1460
#define	TCP_WND				(256 * 1024)
#define	TCP_SND_BUF			(256 * 1024)
#define	TCP_SND_QUEUELEN			(4 * TCP_SND_BUF / TCP_MSS)

#define	LWIP_STATS			1
#define	LWIP_STATS_DISPLAY		0
#define	LWIP_CHECKSUM_CTRL_PER_NETIF	1

#endif /* !_LWIPCMP_LWIPOPTS_H_ */
