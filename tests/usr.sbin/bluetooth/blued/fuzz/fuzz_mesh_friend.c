/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh friendship control-message parser
 * (lib/libmesh/mesh_friend.c).
 *
 * The Friend* Lower Transport Control messages (Friend Poll/Update/Request/
 * Offer/Clear/Clear Confirm/Subscription List Add/Remove/Confirm, MshPRT_v1.1
 * Section 3.6.5) arrive over the mesh bearer inside a Network PDU: they are
 * fully attacker-controlled bytes that a Friend node or Low Power node must
 * parse before it can trust them.  This harness treats the fuzz input AS one
 * received friendship control PDU and drives every parser against it:
 *
 *   - a dispatch on octet 0 (the Transport Control opcode) into the matching
 *     mesh_friend_*_parse(), exercising the length/field validation each does;
 *   - and, unconditionally, every parser on the same raw bytes, so a parser is
 *     also fed inputs whose leading opcode "belongs" to a different message
 *     (length-field confusion, oversized subscription lists, odd address-list
 *     lengths, prohibited Criteria/Flags/MD values, etc.).
 *
 * The parsers are pure byte-codecs (no crypto), so ASan/UBSan here catch any
 * out-of-bounds read or undefined behaviour on the parse path; there is no MIC
 * to satisfy.  A successful Poll/Request parse is round-tripped through its
 * build to exercise the encoder on parser-derived values as well.
 *
 * Reference: MshPRT_v1.1 Section 3.6.5 (friendship control messages).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_friend.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_friend_poll poll;
	struct mesh_friend_update upd;
	struct mesh_friend_request req;
	struct mesh_friend_offer offer;
	struct mesh_friend_clear clr;
	struct mesh_friend_sublist sub;
	struct mesh_friend_subconfirm scf;
	uint8_t out[MESH_FRIEND_MSG_MAX];
	uint8_t op;
	uint8_t *copy;
	size_t outlen;

	/* A friendship control PDU is small; keep some slack for length paths. */
	if (size > 64)
		size = 64;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/* Dispatch on the opcode in octet 0, mirroring a real receiver. */
	if (size >= 1) {
		switch (copy[0]) {
		case MESH_FRIEND_OP_POLL:
			if (mesh_friend_poll_parse(copy, size, &poll) == 0)
				(void)mesh_friend_poll_build(&poll, out, &outlen);
			break;
		case MESH_FRIEND_OP_UPDATE:
			(void)mesh_friend_update_parse(copy, size, &upd);
			break;
		case MESH_FRIEND_OP_REQUEST:
			if (mesh_friend_request_parse(copy, size, &req) == 0)
				(void)mesh_friend_request_build(&req, out, &outlen);
			break;
		case MESH_FRIEND_OP_OFFER:
			(void)mesh_friend_offer_parse(copy, size, &offer);
			break;
		case MESH_FRIEND_OP_CLEAR:
		case MESH_FRIEND_OP_CLEAR_CONFIRM:
			(void)mesh_friend_clear_parse(copy, size, &clr, &op);
			break;
		case MESH_FRIEND_OP_SUBLIST_ADD:
		case MESH_FRIEND_OP_SUBLIST_REMOVE:
			if (mesh_friend_sublist_parse(copy, size, &sub, &op) == 0)
				(void)mesh_friend_sublist_build(op, &sub, out,
				    &outlen);
			break;
		case MESH_FRIEND_OP_SUBLIST_CONFIRM:
			(void)mesh_friend_subconfirm_parse(copy, size, &scf);
			break;
		default:
			break;
		}
	}

	/* Also feed the raw bytes to every parser (cross opcode / length fuzz). */
	(void)mesh_friend_poll_parse(copy, size, &poll);
	(void)mesh_friend_update_parse(copy, size, &upd);
	(void)mesh_friend_request_parse(copy, size, &req);
	(void)mesh_friend_offer_parse(copy, size, &offer);
	(void)mesh_friend_clear_parse(copy, size, &clr, &op);
	(void)mesh_friend_sublist_parse(copy, size, &sub, &op);
	(void)mesh_friend_subconfirm_parse(copy, size, &scf);

	free(copy);
	return (0);
}
