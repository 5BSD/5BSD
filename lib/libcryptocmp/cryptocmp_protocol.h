/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTOCMP_PROTOCOL_H_
#define _CRYPTOCMP_PROTOCOL_H_
#include <stdint.h>
#define CRYPTOCMP_MAGIC 0x43434d50U
#define CRYPTOCMP_VERSION 1
#define CRYPTOCMP_INTERFACE "org.5bsd.crypto"
#define CRYPTOCMP_INTERFACE_VERSION "1.0.0"
#define CRYPTOCMP_OP_GENERATE 1
struct cryptocmp_msg { uint32_t magic; uint16_t version, opcode; int32_t status; } __attribute__((aligned(8)));
struct cryptocmp_generate { uint32_t cipher, mac, keylen, mackeylen, rights; int32_t crid, ivlen, maclen; };
#endif
