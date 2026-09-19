/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server internal header — shared between att_server.c,
 * att_server_dispatch.c, att_server_notify.c, att_server_hash.c.
 *
 * Not for consumption outside the att_server implementation.
 */

#ifndef _BLUED_ATT_SERVER_INTERNAL_H_
#define _BLUED_ATT_SERVER_INTERNAL_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "att.h"
#include "att_server.h"

/*
 * Response buffer helpers for EATT large-MTU support.
 */
#define ATT_RSP_BUF_DECL(ac)						\
	uint8_t rsp_stack_[ATT_PDU_BUF_SIZE];				\
	uint8_t *rsp = (ac)->mtu > ATT_PDU_BUF_SIZE			\
	    ? malloc((ac)->mtu) : rsp_stack_

#define ATT_RSP_BUF_FREE()						\
	do { if (rsp != rsp_stack_) free(rsp); } while (0)

/* Logged send helper — logs outgoing ATT PDU to BTSnoop */
ssize_t	att_server_send(struct att_conn *ac, const void *buf, size_t len);

/* ATT opcode name for logging */
const char *att_opcode_name(uint8_t op);

/* UUID extraction from ATT PDUs */
int	att_extract_uuid(const uint8_t *data, size_t uuid_len,
	    uint16_t *uuid16_out, uint8_t uuid128_out[16]);

#endif /* _BLUED_ATT_SERVER_INTERNAL_H_ */
