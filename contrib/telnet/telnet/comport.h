/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TELNET_COMPORT_H
#define TELNET_COMPORT_H
#include <stddef.h>
#include <stdint.h>

/* RFC 2217: prefix, four possibly escaped data octets, IAC SE. */
#define TELNET_COMPORT_BAUDRATE_MAX_FRAME (6 + 2 * sizeof(uint32_t))
size_t telnet_comport_baudrate(uint32_t, unsigned char *, size_t);
#endif
