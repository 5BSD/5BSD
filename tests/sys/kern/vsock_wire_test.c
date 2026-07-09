/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire-format and ABI conformance tests for AF_VSOCK / virtio-vsock.
 *
 * These lock the on-wire and ABI layouts against silent drift: a stray field
 * edit in <sys/vsock.h> would break interoperability with real Linux/qemu
 * virtio-vsock peers -- the exact class of bug -Werror cannot catch.  Unlike
 * vsock_test.c these run entirely in userspace and need no kernel module.
 */

#include <sys/types.h>
#include <sys/vsock.h>
#include <sys/endian.h>
#include <sys/socket.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

/*
 * virtio 1.4 section 5.10.6: struct virtio_vsock_hdr is a 44-byte, packed,
 * little-endian header.  Assert size and every field offset.
 */
ATF_TC_WITHOUT_HEAD(hdr_layout);
ATF_TC_BODY(hdr_layout, tc)
{
	ATF_CHECK_EQ(44, sizeof(struct virtio_vsock_hdr));
	ATF_CHECK_EQ(0,  offsetof(struct virtio_vsock_hdr, src_cid));
	ATF_CHECK_EQ(8,  offsetof(struct virtio_vsock_hdr, dst_cid));
	ATF_CHECK_EQ(16, offsetof(struct virtio_vsock_hdr, src_port));
	ATF_CHECK_EQ(20, offsetof(struct virtio_vsock_hdr, dst_port));
	ATF_CHECK_EQ(24, offsetof(struct virtio_vsock_hdr, len));
	ATF_CHECK_EQ(28, offsetof(struct virtio_vsock_hdr, type));
	ATF_CHECK_EQ(30, offsetof(struct virtio_vsock_hdr, op));
	ATF_CHECK_EQ(32, offsetof(struct virtio_vsock_hdr, flags));
	ATF_CHECK_EQ(36, offsetof(struct virtio_vsock_hdr, buf_alloc));
	ATF_CHECK_EQ(40, offsetof(struct virtio_vsock_hdr, fwd_cnt));
}

ATF_TC_WITHOUT_HEAD(aux_struct_sizes);
ATF_TC_BODY(aux_struct_sizes, tc)
{
	ATF_CHECK_EQ(8,  sizeof(struct virtio_vsock_config));	/* le64 cid */
	ATF_CHECK_EQ(4,  sizeof(struct virtio_vsock_event));	/* le32 id  */
	ATF_CHECK_EQ(16, sizeof(struct sockaddr_vm));		/* ABI      */
}

/*
 * Encode a header with distinct per-field values and assert the raw bytes are
 * little-endian at the spec offsets.  This exercises the same htole*() the
 * three implementations use, so on a big-endian host it verifies the swap and
 * on a little-endian host it verifies offset/packing.
 */
ATF_TC_WITHOUT_HEAD(hdr_little_endian_encode);
ATF_TC_BODY(hdr_little_endian_encode, tc)
{
	struct virtio_vsock_hdr h;
	uint8_t b[sizeof(h)];

	memset(&h, 0, sizeof(h));
	h.src_cid   = htole64(UINT64_C(0x0102030405060708));
	h.dst_cid   = htole64(UINT64_C(0x1112131415161718));
	h.src_port  = htole32(0x21222324);
	h.dst_port  = htole32(0x31323334);
	h.len       = htole32(0x41424344);
	h.type      = htole16(0x5152);
	h.op        = htole16(0x6162);
	h.flags     = htole32(0x71727374);
	h.buf_alloc = htole32(0x81828384);
	h.fwd_cnt   = htole32(0x91929394);
	memcpy(b, &h, sizeof(b));

	/* src_cid: least-significant byte first at offset 0. */
	ATF_CHECK_EQ(0x08, b[0]);
	ATF_CHECK_EQ(0x01, b[7]);
	/* dst_cid at offset 8. */
	ATF_CHECK_EQ(0x18, b[8]);
	ATF_CHECK_EQ(0x11, b[15]);
	/* src_port at 16, dst_port at 20, len at 24. */
	ATF_CHECK_EQ(0x24, b[16]);
	ATF_CHECK_EQ(0x21, b[19]);
	ATF_CHECK_EQ(0x34, b[20]);
	ATF_CHECK_EQ(0x44, b[24]);
	/* type at 28, op at 30. */
	ATF_CHECK_EQ(0x52, b[28]);
	ATF_CHECK_EQ(0x51, b[29]);
	ATF_CHECK_EQ(0x62, b[30]);
	ATF_CHECK_EQ(0x61, b[31]);
	/* flags at 32, buf_alloc at 36, fwd_cnt at 40. */
	ATF_CHECK_EQ(0x74, b[32]);
	ATF_CHECK_EQ(0x84, b[36]);
	ATF_CHECK_EQ(0x94, b[40]);
	ATF_CHECK_EQ(0x91, b[43]);

	/*
	 * Full-array cross-check against the same golden little-endian bytes
	 * the decode test uses.  The spot checks above document key offsets;
	 * this covers all 44 bytes (every field, no padding) so a packing or
	 * offset regression in any field is caught, not just the sampled ones.
	 */
	{
		static const uint8_t golden[44] = {
			0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,	/* src_cid */
			0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,	/* dst_cid */
			0x24,0x23,0x22,0x21,				/* src_port */
			0x34,0x33,0x32,0x31,				/* dst_port */
			0x44,0x43,0x42,0x41,				/* len */
			0x52,0x51,					/* type */
			0x62,0x61,					/* op */
			0x74,0x73,0x72,0x71,				/* flags */
			0x84,0x83,0x82,0x81,				/* buf_alloc */
			0x94,0x93,0x92,0x91,				/* fwd_cnt */
		};
		ATF_CHECK(sizeof(b) == sizeof(golden));
		ATF_CHECK(memcmp(b, golden, sizeof(golden)) == 0);
	}
}

/* Decode golden little-endian bytes and assert the field values. */
ATF_TC_WITHOUT_HEAD(hdr_little_endian_decode);
ATF_TC_BODY(hdr_little_endian_decode, tc)
{
	static const uint8_t b[44] = {
		0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,	/* src_cid */
		0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,	/* dst_cid */
		0x24,0x23,0x22,0x21,				/* src_port */
		0x34,0x33,0x32,0x31,				/* dst_port */
		0x44,0x43,0x42,0x41,				/* len */
		0x52,0x51,					/* type */
		0x62,0x61,					/* op */
		0x74,0x73,0x72,0x71,				/* flags */
		0x84,0x83,0x82,0x81,				/* buf_alloc */
		0x94,0x93,0x92,0x91,				/* fwd_cnt */
	};
	struct virtio_vsock_hdr h;

	memcpy(&h, b, sizeof(h));
	ATF_CHECK_EQ(UINT64_C(0x0102030405060708), le64toh(h.src_cid));
	ATF_CHECK_EQ(UINT64_C(0x1112131415161718), le64toh(h.dst_cid));
	ATF_CHECK_EQ(0x21222324, le32toh(h.src_port));
	ATF_CHECK_EQ(0x31323334, le32toh(h.dst_port));
	ATF_CHECK_EQ(0x41424344, le32toh(h.len));
	ATF_CHECK_EQ(0x5152, le16toh(h.type));
	ATF_CHECK_EQ(0x6162, le16toh(h.op));
	ATF_CHECK_EQ(0x71727374, le32toh(h.flags));
	ATF_CHECK_EQ(0x81828384, le32toh(h.buf_alloc));
	ATF_CHECK_EQ(0x91929394, le32toh(h.fwd_cnt));
}

/* Protocol constants must match virtio 1.4 section 5.10 exactly. */
ATF_TC_WITHOUT_HEAD(protocol_constants);
ATF_TC_BODY(protocol_constants, tc)
{
	/* Operations (5.10.6). */
	ATF_CHECK_EQ(0, VIRTIO_VSOCK_OP_INVALID);
	ATF_CHECK_EQ(1, VIRTIO_VSOCK_OP_REQUEST);
	ATF_CHECK_EQ(2, VIRTIO_VSOCK_OP_RESPONSE);
	ATF_CHECK_EQ(3, VIRTIO_VSOCK_OP_RST);
	ATF_CHECK_EQ(4, VIRTIO_VSOCK_OP_SHUTDOWN);
	ATF_CHECK_EQ(5, VIRTIO_VSOCK_OP_RW);
	ATF_CHECK_EQ(6, VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	ATF_CHECK_EQ(7, VIRTIO_VSOCK_OP_CREDIT_REQUEST);
	/* Types (5.10.6.2). */
	ATF_CHECK_EQ(1, VIRTIO_VSOCK_TYPE_STREAM);
	ATF_CHECK_EQ(2, VIRTIO_VSOCK_TYPE_SEQPACKET);
	/* Shutdown flags as bit values (5.10.6.5: bit 0 recv, bit 1 send). */
	ATF_CHECK_EQ(1, VIRTIO_VSOCK_SHUTDOWN_RCV);
	ATF_CHECK_EQ(2, VIRTIO_VSOCK_SHUTDOWN_SEND);
	/* Seqpacket flags (5.10.6.6: bit 0 EOM, bit 1 EOR). */
	ATF_CHECK_EQ(1, VIRTIO_VSOCK_SEQ_EOM);
	ATF_CHECK_EQ(2, VIRTIO_VSOCK_SEQ_EOR);
	/* Event id (5.10.6.7). */
	ATF_CHECK_EQ(0, VIRTIO_VSOCK_EVENT_TRANSPORT_RESET);
	/*
	 * Feature bits (virtio 1.4 §5.10.3): F_STREAM(0), F_SEQPACKET(1),
	 * F_NO_IMPLIED_STREAM(2).  Bit 2 was contested while unratified;
	 * virtio 1.4 ratified it as NO_IMPLIED_STREAM, so it is now defined
	 * and must stay pinned to bit 2.
	 */
	ATF_CHECK_EQ(1ULL << 0, VIRTIO_VSOCK_F_STREAM);
	ATF_CHECK_EQ(1ULL << 1, VIRTIO_VSOCK_F_SEQPACKET);
	ATF_CHECK_EQ(1ULL << 2, VIRTIO_VSOCK_F_NO_IMPLIED_STREAM);
}

/* Reserved CIDs (5.10.4) and the Linux-compatible ABI aliases. */
ATF_TC_WITHOUT_HEAD(cid_and_abi_constants);
ATF_TC_BODY(cid_and_abi_constants, tc)
{
	ATF_CHECK_EQ(0, VSOCK_CID_HYPERVISOR);
	ATF_CHECK_EQ(1, VSOCK_CID_LOCAL);
	ATF_CHECK_EQ(2, VSOCK_CID_HOST);
	/* 32-bit wildcard CID (Linux-compatible), not a 64-bit all-ones. */
	ATF_CHECK_EQ(UINT32_C(0xffffffff), VSOCK_CID_ANY);
	ATF_CHECK_EQ(UINT32_C(0xffffffff), VSOCK_PORT_ANY);

	/* Linux source-portability aliases map to the native values. */
	ATF_CHECK_EQ(VSOCK_CID_HYPERVISOR, VMADDR_CID_HYPERVISOR);
	ATF_CHECK_EQ(VSOCK_CID_LOCAL, VMADDR_CID_LOCAL);
	ATF_CHECK_EQ(VSOCK_CID_HOST, VMADDR_CID_HOST);
	ATF_CHECK_EQ(VSOCK_CID_ANY, VMADDR_CID_ANY);
	ATF_CHECK_EQ(VSOCK_PORT_ANY, VMADDR_PORT_ANY);

	/* Linux-matching sockopt namespace. */
	ATF_CHECK_EQ(287, SOL_VSOCK);
	ATF_CHECK_EQ(0, SO_VM_SOCKETS_BUFFER_SIZE);
	ATF_CHECK_EQ(1, SO_VM_SOCKETS_BUFFER_MIN_SIZE);
	ATF_CHECK_EQ(2, SO_VM_SOCKETS_BUFFER_MAX_SIZE);
	ATF_CHECK_EQ(3, SO_VM_SOCKETS_PEER_HOST_VM_ID);	/* == Linux */
	ATF_CHECK_EQ(5, SO_VM_SOCKETS_TRUSTED);		/* == Linux (VMCI-only) */
	ATF_CHECK_EQ(6, SO_VM_SOCKETS_CONNECT_TIMEOUT);
	ATF_CHECK_EQ(7, SO_VM_SOCKETS_NONBLOCK_TXRX);	/* == Linux (VMCI-only) */
	ATF_CHECK_EQ(8, SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW);

	/*
	 * svm_flags bit and the ioctl command encodings are host-local ABI
	 * that Linux-ported code depends on; pin them so a stray edit to the
	 * literal in <sys/vsock.h> fails here rather than silently breaking a
	 * recompiled ported program (which would pick up the new value too).
	 */
	ATF_CHECK_EQ(0x01, VMADDR_FLAG_TO_HOST);
	ATF_CHECK_EQ(_IOR('v', 0xb9, uint32_t), IOCTL_VM_SOCKETS_GET_LOCAL_CID);
	ATF_CHECK_EQ(_IOR('v', 128, int), SIOCOUTQ);
}

/* sockaddr_vm field offsets: svm_family must alias struct sockaddr's family. */
ATF_TC_WITHOUT_HEAD(sockaddr_vm_layout);
ATF_TC_BODY(sockaddr_vm_layout, tc)
{
	ATF_CHECK_EQ(0, offsetof(struct sockaddr_vm, svm_len));
	ATF_CHECK_EQ(offsetof(struct sockaddr, sa_family),
	    offsetof(struct sockaddr_vm, svm_family));
	ATF_CHECK_EQ(4, offsetof(struct sockaddr_vm, svm_port));
	ATF_CHECK_EQ(8, offsetof(struct sockaddr_vm, svm_cid));
	/* Linux-compatible: 32-bit svm_cid followed by an svm_flags byte. */
	ATF_CHECK_EQ(4, sizeof(((struct sockaddr_vm *)0)->svm_cid));
	ATF_CHECK_EQ(12, offsetof(struct sockaddr_vm, svm_flags));
	/* svm_zero[3] pads the ABI struct out to exactly 16 bytes. */
	ATF_CHECK_EQ(13, offsetof(struct sockaddr_vm, svm_zero));
	ATF_CHECK_EQ(3, sizeof(((struct sockaddr_vm *)0)->svm_zero));
	ATF_CHECK_EQ(16, sizeof(struct sockaddr_vm));
}

/*
 * xvsock_pcb is the ABI struct returned by the kern.vsock.pcblist sysctl to
 * userspace tools (sockstat, netstat).  Lock its size and every field offset:
 * a field edit here silently breaks those tools' decoding and can leak
 * differently-sized padding, which -Werror cannot catch.
 */
ATF_TC_WITHOUT_HEAD(xvsock_pcb_abi_layout);
ATF_TC_BODY(xvsock_pcb_abi_layout, tc)
{
	ATF_CHECK_EQ(64, sizeof(struct xvsock_pcb));
	ATF_CHECK_EQ(0,  offsetof(struct xvsock_pcb, xvp_len));
	ATF_CHECK_EQ(4,  offsetof(struct xvsock_pcb, xvp_state));
	ATF_CHECK_EQ(8,  offsetof(struct xvsock_pcb, xvp_local_cid));
	ATF_CHECK_EQ(16, offsetof(struct xvsock_pcb, xvp_remote_cid));
	ATF_CHECK_EQ(24, offsetof(struct xvsock_pcb, xvp_local_port));
	ATF_CHECK_EQ(28, offsetof(struct xvsock_pcb, xvp_remote_port));
	ATF_CHECK_EQ(32, offsetof(struct xvsock_pcb, xvp_type));
	ATF_CHECK_EQ(36, offsetof(struct xvsock_pcb, xvp_buf_alloc));
	ATF_CHECK_EQ(40, offsetof(struct xvsock_pcb, xvp_rx_bytes));
	ATF_CHECK_EQ(44, offsetof(struct xvsock_pcb, xvp_tx_cnt));
	ATF_CHECK_EQ(48, offsetof(struct xvsock_pcb, xvp_peer_buf_alloc));
	ATF_CHECK_EQ(52, offsetof(struct xvsock_pcb, xvp_peer_fwd_cnt));
	ATF_CHECK_EQ(56, offsetof(struct xvsock_pcb, xvp_so_gencnt));
}

/*
 * Connection-state values exported in xvsock_pcb.xvp_state (consumed by
 * userspace).  These MUST match the kernel-internal enum vtvsock_state
 * ordering in kern/uipc_vsock.h.
 */
ATF_TC_WITHOUT_HEAD(connection_state_constants);
ATF_TC_BODY(connection_state_constants, tc)
{
	ATF_CHECK_EQ(0, VSOCK_ST_CLOSED);
	ATF_CHECK_EQ(1, VSOCK_ST_BOUND);
	ATF_CHECK_EQ(2, VSOCK_ST_LISTEN);
	ATF_CHECK_EQ(3, VSOCK_ST_CONNECTING);
	ATF_CHECK_EQ(4, VSOCK_ST_ESTABLISHED);
	ATF_CHECK_EQ(5, VSOCK_ST_CLOSING);
}

/* Device config (5.10.4) and event (5.10.6.7) buffer layouts. */
ATF_TC_WITHOUT_HEAD(config_and_event_layout);
ATF_TC_BODY(config_and_event_layout, tc)
{
	ATF_CHECK_EQ(8, sizeof(struct virtio_vsock_config));
	ATF_CHECK_EQ(0, offsetof(struct virtio_vsock_config, guest_cid));
	ATF_CHECK_EQ(4, sizeof(struct virtio_vsock_event));
	ATF_CHECK_EQ(0, offsetof(struct virtio_vsock_event, id));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hdr_layout);
	ATF_TP_ADD_TC(tp, aux_struct_sizes);
	ATF_TP_ADD_TC(tp, hdr_little_endian_encode);
	ATF_TP_ADD_TC(tp, hdr_little_endian_decode);
	ATF_TP_ADD_TC(tp, protocol_constants);
	ATF_TP_ADD_TC(tp, cid_and_abi_constants);
	ATF_TP_ADD_TC(tp, sockaddr_vm_layout);
	ATF_TP_ADD_TC(tp, xvsock_pcb_abi_layout);
	ATF_TP_ADD_TC(tp, connection_state_constants);
	ATF_TP_ADD_TC(tp, config_and_event_layout);

	return (atf_no_error());
}
