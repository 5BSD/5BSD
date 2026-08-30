/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
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

#ifndef _VIRTIO_CRYPTO_H
#define _VIRTIO_CRYPTO_H

/*
 * VirtIO crypto (device ID 20) wire definitions.
 *
 * These structures and constants must byte-match the host device model in
 * usr.sbin/bhyve/pci_virtio_crypto.c and the OASIS VirtIO 1.2 specification,
 * section 5.9.  All multi-byte fields are little-endian on the modern
 * transport, which is the only transport this device supports.
 *
 * The header layouts are expressed both as C structures (for documentation
 * and offsetof()) and as explicit byte offsets that the guest driver fills in
 * by hand with the endian codecs, so that the on-wire image is independent of
 * the guest's own byte order and structure padding.
 */

/*
 * Device configuration space (section 5.9.4).  Field order and sizes match the
 * host's struct virtio_crypto_config exactly; the guest reads it through the
 * modern transport which presents each field in guest-native byte order.
 */
struct virtio_crypto_config {
	uint32_t status;
	uint32_t max_dataqueues;
	uint32_t crypto_services;
	uint32_t cipher_algo_l;
	uint32_t cipher_algo_h;
	uint32_t hash_algo;
	uint32_t mac_algo_l;
	uint32_t mac_algo_h;
	uint32_t aead_algo;
	uint32_t max_cipher_key_len;
	uint32_t max_auth_key_len;
	uint32_t akcipher_algo;
	uint64_t max_size;
} __packed;

/* Device configuration status (section 5.9.4). */
#define	VIRTIO_CRYPTO_S_HW_READY	(1u << 0)

/* Services (section 5.9.4), used as bit positions in crypto_services. */
#define	VIRTIO_CRYPTO_SERVICE_CIPHER	0
#define	VIRTIO_CRYPTO_SERVICE_HASH	1
#define	VIRTIO_CRYPTO_SERVICE_MAC	2
#define	VIRTIO_CRYPTO_SERVICE_AEAD	3

#define	VIRTIO_CRYPTO_OPCODE(service, op)	(((service) << 8) | (op))

/* Control queue opcodes (section 5.9.7.1). */
#define	VIRTIO_CRYPTO_CIPHER_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02)
#define	VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03)
#define	VIRTIO_CRYPTO_HASH_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x02)
#define	VIRTIO_CRYPTO_HASH_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x03)
#define	VIRTIO_CRYPTO_MAC_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x02)
#define	VIRTIO_CRYPTO_MAC_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x03)
#define	VIRTIO_CRYPTO_AEAD_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02)
#define	VIRTIO_CRYPTO_AEAD_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03)

/* Data queue opcodes (section 5.9.7.2). */
#define	VIRTIO_CRYPTO_CIPHER_ENCRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00)
#define	VIRTIO_CRYPTO_CIPHER_DECRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01)
#define	VIRTIO_CRYPTO_HASH		\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x00)
#define	VIRTIO_CRYPTO_MAC		\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x00)
#define	VIRTIO_CRYPTO_AEAD_ENCRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00)
#define	VIRTIO_CRYPTO_AEAD_DECRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01)

/* Cipher/AEAD direction. */
#define	VIRTIO_CRYPTO_OP_ENCRYPT	1
#define	VIRTIO_CRYPTO_OP_DECRYPT	2

/* Symmetric session op_type. */
#define	VIRTIO_CRYPTO_SYM_OP_NONE	0
#define	VIRTIO_CRYPTO_SYM_OP_CIPHER	1
#define	VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING	2

/* Cipher algorithms (cipher_algo_l bit positions). */
#define	VIRTIO_CRYPTO_CIPHER_AES_CBC	3

/* Hash algorithms (hash_algo bit positions). */
#define	VIRTIO_CRYPTO_HASH_SHA_256	4

/* MAC algorithms (mac_algo_l bit positions). */
#define	VIRTIO_CRYPTO_MAC_HMAC_SHA_256	4

/* AEAD algorithms (aead_algo bit positions). */
#define	VIRTIO_CRYPTO_AEAD_GCM		1

/* One-byte per-request status codes (virtio_crypto_inhdr). */
#define	VIRTIO_CRYPTO_S_OK		0
#define	VIRTIO_CRYPTO_S_ERR		1
#define	VIRTIO_CRYPTO_S_BADMSG		2
#define	VIRTIO_CRYPTO_S_NOTSUPP		3
#define	VIRTIO_CRYPTO_S_INVSESS		4

/*
 * Fixed wire sizes.  Both the control-request and the data-request headers are
 * 72 bytes in VirtIO 1.2; the session_input reply is 16 bytes.
 */
#define	VTCRYPTO_CTRL_REQ_LEN		72u
#define	VTCRYPTO_DATA_REQ_LEN		72u
#define	VTCRYPTO_SESSION_INPUT_LEN	16u

/*
 * Byte offsets within the 72-byte control request (virtio_crypto_op_ctrl_req).
 * A 16-byte virtio_crypto_ctrl_header precedes a 56-byte op-specific union.
 */
#define	VTC_CTRL_OFF_OPCODE		0	/* le32 header.opcode */
#define	VTC_CTRL_OFF_HDR_ALGO		4	/* le32 header.algo */
#define	VTC_CTRL_OFF_HDR_FLAG		8	/* le32 header.flag */
#define	VTC_CTRL_OFF_HDR_RESERVED	12	/* le32 header.reserved */

/* cipher_session_para (sym create) begins at offset 16; op_type at 64. */
#define	VTC_CTRL_OFF_CIPHER_ALGO	16	/* le32 */
#define	VTC_CTRL_OFF_CIPHER_KEYLEN	20	/* le32 */
#define	VTC_CTRL_OFF_CIPHER_OP		24	/* le32 encrypt/decrypt */
#define	VTC_CTRL_OFF_SYM_OP_TYPE	64	/* le32 op_type */

/* hash_session_para begins at offset 16. */
#define	VTC_CTRL_OFF_HASH_ALGO		16	/* le32 */
#define	VTC_CTRL_OFF_HASH_RESULT_LEN	20	/* le32 */

/* mac_session_para begins at offset 16. */
#define	VTC_CTRL_OFF_MAC_ALGO		16	/* le32 */
#define	VTC_CTRL_OFF_MAC_RESULT_LEN	20	/* le32 */
#define	VTC_CTRL_OFF_MAC_AUTH_KEYLEN	24	/* le32 */

/* aead_session_para begins at offset 16. */
#define	VTC_CTRL_OFF_AEAD_ALGO		16	/* le32 */
#define	VTC_CTRL_OFF_AEAD_KEYLEN	20	/* le32 */
#define	VTC_CTRL_OFF_AEAD_RESULT_LEN	24	/* le32 */
#define	VTC_CTRL_OFF_AEAD_AAD_LEN	28	/* le32 */
#define	VTC_CTRL_OFF_AEAD_OP		32	/* le32 encrypt/decrypt */

/* destroy_session_req: session_id immediately follows the 16-byte header. */
#define	VTC_CTRL_OFF_DESTROY_SESSID	16	/* le64 */

/* session_input reply. */
#define	VTC_SI_OFF_SESSION_ID		0	/* le64 */
#define	VTC_SI_OFF_STATUS		8	/* le32 */

/*
 * Byte offsets within the 72-byte data request.  A 24-byte
 * virtio_crypto_op_header precedes a 48-byte op-specific body.
 */
#define	VTC_DATA_OFF_OPCODE		0	/* le32 header.opcode */
#define	VTC_DATA_OFF_ALGO		4	/* le32 header.algo */
#define	VTC_DATA_OFF_SESSION_ID		8	/* le64 header.session_id */
#define	VTC_DATA_OFF_FLAG		16	/* le32 header.flag */
#define	VTC_DATA_OFF_PADDING		20	/* le32 header.padding */

/* cipher_para begins at offset 24. */
#define	VTC_DATA_OFF_CIPHER_IV_LEN	24	/* le32 */
#define	VTC_DATA_OFF_CIPHER_SRC_LEN	28	/* le32 */
#define	VTC_DATA_OFF_CIPHER_DST_LEN	32	/* le32 */

/* hash_para / mac_para begin at offset 24. */
#define	VTC_DATA_OFF_HASH_SRC_LEN	24	/* le32 */
#define	VTC_DATA_OFF_HASH_RESULT_LEN	28	/* le32 */

/* aead_para begins at offset 24. */
#define	VTC_DATA_OFF_AEAD_IV_LEN	24	/* le32 */
#define	VTC_DATA_OFF_AEAD_AAD_LEN	28	/* le32 */
#define	VTC_DATA_OFF_AEAD_SRC_LEN	32	/* le32 */
#define	VTC_DATA_OFF_AEAD_DST_LEN	36	/* le32 */

#endif /* _VIRTIO_CRYPTO_H */
