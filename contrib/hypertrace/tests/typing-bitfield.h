/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Bit-field layouts shared by the typingbf CTF fixture (C, compiled with
 * cc -g and converted by ctfconvert in typing-inference.py) and by
 * typing-bitfield.cc (C++), whose compiler-generated member accesses are the
 * oracle for the HyperTrace linker's bit-field relocation.
 */
#ifndef _TYPING_BITFIELD_H_
#define _TYPING_BITFIELD_H_

#include <stdint.h>

/* Fields of every signedness and width, some crossing byte boundaries. */
struct tf_bf {
	unsigned int a:3;
	unsigned int e:7;		/* bits 3-9: crosses a byte */
	int b:5;
	unsigned int c:12;		/* bits 15-26: needs a 4-byte load */
	int d:4;
	int one:1;			/* signed, one bit */
	unsigned long long w:40;
	long long sw:23;
	unsigned char g:2;
	signed char sg:3;
	unsigned short h:9;
	unsigned int nb;		/* not a bit-field */
	unsigned long long hi:60;
};

/* An embedded structure inside another, as tcpcb's t_inpcb.inp_inc. */
struct tf_inc {
	uint32_t ie_faddr;
	uint16_t ie_fport;
	uint16_t ie_lport;
};
struct tf_inpcb {
	uint64_t inp_x;
	struct tf_inc inp_inc;
};

/* The word of struct tcpcb that holds t_state (sys/netinet/tcp_var.h). */
struct tf_bftcp {
	struct tf_inpcb t_inpcb;
	char tf_pad[592 - sizeof(struct tf_inpcb)];
	uint32_t t_maxseg:24,
		_t_logstate:8;
	uint32_t t_port:16,
		t_state:4,
		t_idle_reduce:1,
		t_delayed_ack:7,
		t_fin_is_rst:1,
		t_log_state_set:1,
		bits_spare:2;
	unsigned int t_flags;		/* not a bit-field */
};

/* A field that no naturally aligned load of at most eight bytes holds. */
struct __attribute__((packed)) tf_bfpacked {
	char c;
	unsigned long long q:60;
};

#endif
