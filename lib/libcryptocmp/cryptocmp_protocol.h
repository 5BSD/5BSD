/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTOCMP_PROTOCOL_H_
#define _CRYPTOCMP_PROTOCOL_H_
#include <stdint.h>
#define CRYPTOCMP_MAGIC 0x43434d50U
#define CRYPTOCMP_VERSION 3
#define CRYPTOCMP_INTERFACE "system.Crypto"
#define CRYPTOCMP_INTERFACE_VERSION "3.0.0"
#define CRYPTOCMP_OP_GENERATE 1
#define CRYPTOCMP_OP_GENERATE_KEY 2
#define CRYPTOCMP_OP_NAMED_CREATE 3
#define CRYPTOCMP_OP_NAMED_LEASE 4
#define CRYPTOCMP_OP_NAMED_ROTATE 5
#define CRYPTOCMP_OP_NAMED_DELETE 6
#define CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY 0x00000001U
struct cryptocmp_msg { uint32_t magic; uint16_t version, opcode; int32_t status; } __attribute__((aligned(8)));
/* This selects an algorithm profile; it is not a FIPS validation claim. */
struct cryptocmp_generate { uint32_t cipher, mac, keylen, mackeylen, rights, ttl, flags; int32_t crid, ivlen, maclen; };
struct cryptocmp_key_generate { uint32_t type, rights, ttl, flags; };
struct cryptocmp_key_reply { struct cryptocmp_msg msg; uint8_t public_key[32]; };
struct cryptocmp_named_create { char name[64]; struct cryptocmp_generate generate; };
struct cryptocmp_named_lease { char name[64]; uint32_t rights, ttl, flags; };
struct cryptocmp_named_control { char name[64]; uint32_t flags; };
struct cryptocmp_named_reply { struct cryptocmp_msg msg; uint64_t generation; };
#endif
