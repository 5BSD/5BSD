/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability -- message-passing capability framework for kernel modules.
 *
 * Shared kernel/userspace ioctl definitions.
 *
 * Userspace:
 *   open("/dev/mac_capability") -> ioctl(MAC_CAPABILITY_CONNECT, &args) -> capability fd
 *
 * Messaging:
 *   ioctl(fd, MAC_CAPABILITY_SENDMSG, &args)    send async message to service
 *   ioctl(fd, MAC_CAPABILITY_RECVMSG, &args)    receive async reply/notification
 *   ioctl(fd, MAC_CAPABILITY_CALL, &args)       synchronous call (caller context)
 *   ioctl(fd, MAC_CAPABILITY_CHANNEL_CALL, &args) send a request and receive
 *                                               its reply in one call
 *
 * A service may expose CALL, SENDMSG/RECVMSG, or both.  kqueue readiness
 * maps to async queue state: EVFILT_READ means RECVMSG can make progress,
 * and EVFILT_WRITE means SENDMSG queue space is available.
 * Service-defined events are delivered as RECVMSG payloads and surfaced
 * through EVFILT_READ readiness.
 *
 * Introspection:
 *   ioctl(fd, MAC_CAPABILITY_GETINFO, &args)    query capability metadata
 *
 * Capability control:
 *   ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) strip send ability (one-way)
 *   ioctl(fd, MAC_CAPABILITY_REVOKE_RECV, NULL) strip recv ability (one-way)
 *   ioctl(fd, MAC_CAPABILITY_REVOKE_CALL, NULL) strip call ability (one-way)
 *   ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL)   kill instance for all holders
 *   close(fd)                        tear down (last close kills)
 *
 * read()/write() are not supported on capabilities.
 *
 * Capsicum integration:
 *   CAP_IOCTL permits ioctl use on the fd, and cap_ioctls_limit()
 *   irreversibly restricts which commands the fd can perform.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_IOCTL_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_IOCTL_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#define	MAC_CAPABILITY_MAXNAME		64
#define	MAC_CAPABILITY_MAX_FDS		32
#define	MAC_CAPABILITY_MAX_MSG		14336	/* usable payload (16384 - 2048 header) */
#define	MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH	256
#define	MAC_CAPABILITY_DEFAULT_TX_LIMIT	MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH


/*
 * Credential trailer -- kernel-stamped, unforgeable.
 */
/*
 * Sender ABI, stamped by the kernel from the sending process's sysentvec
 * next to the credentials.  The values mirror SV_ABI_* from <sys/sysent.h>
 * (3 = Linux, 9 = native FreeBSD); 0 means unknown/unstamped (kernel-
 * originated replies and notifications, or a kernel predating the stamp).
 * ABI is information for the receiver only; it never gates anything.
 */
#define	MAC_CAPABILITY_ABI_UNKNOWN	0
#define	MAC_CAPABILITY_ABI_LINUX	3
#define	MAC_CAPABILITY_ABI_NATIVE	9

struct mac_capability_cred_trailer {
	uint32_t	uid;
	uint32_t	gid;
	int32_t		prison_id;
	uint8_t		abi;		/* MAC_CAPABILITY_ABI_* (sender sysentvec) */
	uint8_t		_pad[3];
	uint64_t	nonce;		/* program identity (inherited on fork, rotates on exec) */
};
/*
 * The ioctl command numbers embed sizeof() of the args structs that embed
 * this trailer; its size must never change.  The abi byte lives in what
 * used to be alignment padding.
 */
_Static_assert(sizeof(struct mac_capability_cred_trailer) == 24,
    "mac_capability_cred_trailer size is part of the ioctl ABI");

/*
 * Connect to a named kernel capability service.
 */
struct mac_capability_connect_args {
	char		name[MAC_CAPABILITY_MAXNAME];
	uint32_t	flags;		/* reserved, must be 0 */
	int		fd;		/* OUT: capability */
	uint32_t	_reserved[4];
};

/*
 * Send a message with optional fd attachment and reply token.
 * Returns EAGAIN when the RX queue is full; wait for EVFILT_WRITE and retry.
 */
struct mac_capability_sendmsg_args {
	const void	*payload;
	uint32_t	payload_len;
	uint32_t	flags;		/* reserved, must be 0 */
	const int	*fds;
	uint32_t	nfds;
	uint64_t	reply_token;
	uint32_t	_reserved[4];
};

/*
 * Receive an async reply or service notification with optional fd
 * extraction and metadata.  Blocks until a message is available
 * (EAGAIN with O_NONBLOCK).
 */
/*
 * Receive status, set on successful return.  RECV_F_STATUS means the kernel
 * reports queue state; RECV_F_EMPTY means no further message was queued when
 * this one was taken, so a dispatch loop can wait instead of issuing a receive
 * that would only fail with EAGAIN.  Older kernels leave flags zero.
 */
#define	MAC_CAPABILITY_RECV_F_STATUS	0x00000001
#define	MAC_CAPABILITY_RECV_F_EMPTY	0x00000002
/*
 * Input: wait for a message even on a non-blocking descriptor, for at most
 * _reserved[0] milliseconds (MAC_CAPABILITY_RECV_WAIT_FOREVER waits without
 * a limit).  A timeout fails with ETIMEDOUT.  One call replaces a readiness
 * wait followed by a receive.  Older kernels reject the flag with EINVAL.
 */
#define	MAC_CAPABILITY_RECV_F_WAIT	0x00000004
#define	MAC_CAPABILITY_RECV_WAIT_FOREVER	0xffffffffu

struct mac_capability_recvmsg_args {
	void		*payload;
	uint32_t	payload_len;	/* IN: buffer size, OUT: actual */
	uint32_t	flags;		/* IN: must be 0; OUT: RECV_F_* */
	int		*fds;		/* OUT: received fds */
	uint32_t	nfds;		/* IN: max, OUT: actual */
	uint64_t	badge;		/* OUT: message badge */
	uint64_t	reply_token;	/* OUT: correlation token */
	struct mac_capability_cred_trailer trailer; /* OUT: sender credentials */
	uint32_t	_reserved[4];
};

#include <sys/cap_authority.h>

/* Versioned receive metadata; the original receive/trailer ABI is unchanged. */
struct mac_capability_process_stamp {
	uint64_t identity;
	uint64_t responsible_identity;
	int32_t pid;
	int32_t responsible_pid;
};
struct mac_capability_recvmsg_v2_args {
	struct mac_capability_recvmsg_args message;
	struct mac_capability_process_stamp process;
};
#define MAC_CAPABILITY_RECVMSG_V2 \
	_IOWR('Y', 13, struct mac_capability_recvmsg_v2_args)

struct mac_capability_recvmsg_v3_args {
	struct mac_capability_recvmsg_args message;
	struct mac_capability_process_stamp process;
	struct cap_authority_stamp authority;
};
#define MAC_CAPABILITY_RECVMSG_V3 \
	_IOWR('Y', 14, struct mac_capability_recvmsg_v3_args)

/*
 * Descriptor handling in one call, for any number of descriptors.
 *
 * MAC_CAPABILITY_SENDMSG_V2 takes an optional expectation per attached
 * descriptor.  The kernel checks every type and rights expectation before
 * the message is accepted (failing with EFTYPE, ENOTCAPABLE or EOPNOTSUPP
 * and consuming no transfer authority), and narrows only the delivered
 * copy to the requested rights; the sender's descriptor keeps its rights.
 * message.flags may add:
 *   SEND_F_MOVE: close the sender's descriptors once the message is
 *	accepted; on failure they are left open and unchanged.
 *   SEND_F_LOCK_INHERIT: deliver with close-on-exec and close-on-fork
 *	locked (CAP_CLOEXEC_LOCKED, CAP_CLOFORK_LOCKED).
 * MAC_CAPABILITY_RECVMSG_V4 additionally reports each received
 * descriptor's type and rights, so a receiver can validate them without
 * further system calls.  Older kernels fail both with ENOTTY.
 */
#define	MAC_CAPABILITY_FD_TYPE_ANY	0	/* spec: no type requirement */
#define	MAC_CAPABILITY_FD_TYPE_SOCKET	1
#define	MAC_CAPABILITY_FD_TYPE_CHANNEL	2	/* a channel bearer endpoint */
#define	MAC_CAPABILITY_FD_TYPE_OTHER	3	/* info only */
#define	MAC_CAPABILITY_FD_RIGHT_READ	0x00000001
#define	MAC_CAPABILITY_FD_RIGHT_WRITE	0x00000002
#define	MAC_CAPABILITY_FD_RIGHT_FSTAT	0x00000004	/* info only */
#define	MAC_CAPABILITY_FD_RIGHTS_ALL	0x40000000	/* info: unrestricted */
#define	MAC_CAPABILITY_FD_RIGHTS_EXACT	0x80000000	/* info: no other rights */
#define	MAC_CAPABILITY_SEND_F_MOVE		0x00000001
#define	MAC_CAPABILITY_SEND_F_LOCK_INHERIT	0x00000002

/* Per-descriptor spec flag: as SEND_F_LOCK_INHERIT, for this one. */
#define	MAC_CAPABILITY_FD_SPEC_LOCK_INHERIT	0x00000001

struct mac_capability_fd_spec {
	uint32_t	type;		/* MAC_CAPABILITY_FD_TYPE_* */
	uint32_t	rights;		/* FD_RIGHT_READ|WRITE; 0 keeps rights */
	uint32_t	flags;		/* MAC_CAPABILITY_FD_SPEC_* */
	uint32_t	_reserved;
};
struct mac_capability_sendmsg_v2_args {
	struct mac_capability_sendmsg_args message;
	const struct mac_capability_fd_spec *fd_specs;	/* NULL or nfds */
	uint64_t	_reserved2[2];
};
#define	MAC_CAPABILITY_SENDMSG_V2 \
	_IOW('Y', 15, struct mac_capability_sendmsg_v2_args)

struct mac_capability_fd_info {
	uint32_t	type;		/* MAC_CAPABILITY_FD_TYPE_* */
	uint32_t	rights;		/* FD_RIGHT_* | FD_RIGHTS_ALL | EXACT */
};
struct mac_capability_recvmsg_v4_args {
	struct mac_capability_recvmsg_v3_args v3;
	struct mac_capability_fd_info *fd_info;	/* NULL or nfds entries */
	uint64_t	_reserved2[2];
};
#define	MAC_CAPABILITY_RECVMSG_V4 \
	_IOWR('Y', 16, struct mac_capability_recvmsg_v4_args)

/*
 * Peer-to-peer synchronous call: send a request and sleep for its reply in
 * one system call.  The request is accepted exactly as MAC_CAPABILITY_SENDMSG_V2
 * would accept it (same queue limits, descriptor expectations, transfer
 * authority and SEND_F_MOVE semantics) and must carry a nonzero reply_token
 * of the caller's choosing.  The caller then sleeps, interruptibly, until a
 * message carrying that token arrives on its own receive side, and receives
 * it as MAC_CAPABILITY_RECVMSG_V4 would, with the same metadata (process and
 * authority stamps, descriptor info).  Only the matching reply is taken;
 * events and other replies that arrive meanwhile stay queued for
 * MAC_CAPABILITY_RECVMSG.  A matched reply is handed to the sleeping caller
 * directly and never occupies the receive queue, so a caller whose queue is
 * full of unread events cannot deadlock its peer's reply.
 *
 * timeout_ms bounds the sleep (MAC_CAPABILITY_RECV_WAIT_FOREVER: none).
 * On ETIMEDOUT the request remains sent; the kernel remembers the token as
 * cancelled (a small per-descriptor ring, oldest entry evicted) and discards
 * its late reply, closing attached descriptors.  On EINTR the request also
 * remains sent, but its reply is delivered through MAC_CAPABILITY_RECVMSG so
 * the caller can still match it.  Peer death completes the call with
 * ECONNRESET.  If the reply does not fit, the call fails with EMSGSIZE, the
 * required sizes are reported as for RECVMSG, and the reply is placed at the
 * head of the receive queue for a larger MAC_CAPABILITY_RECVMSG_V4.
 * reply.v3.message.flags must be zero on input and reports RECV_F_* as for a
 * receive.  MAC_CAPABILITY_REVOKE_SEND or _RECV disable this command
 * (EACCES); kernels without it fail with ENOTTY, and
 * MAC_CAPABILITY_INFO_F_CHANNEL_CALL in GETINFO reports its presence.
 */
struct mac_capability_channel_call_args {
	struct mac_capability_sendmsg_v2_args request;	/* reply_token != 0 */
	struct mac_capability_recvmsg_v4_args reply;	/* OUT as RECVMSG_V4 */
	uint32_t	timeout_ms;	/* MAC_CAPABILITY_RECV_WAIT_FOREVER: none */
	uint32_t	flags;		/* reserved, must be 0 */
	uint64_t	_reserved[4];
};
#define	MAC_CAPABILITY_CHANNEL_CALL \
	_IOWR('Y', 17, struct mac_capability_channel_call_args)
/* Timed-out call tokens remembered per descriptor (late replies discarded). */
#define	MAC_CAPABILITY_CALL_CANCELLED	16

/*
 * Synchronous call — request and reply in one ioctl.
 * The handler runs in the caller's thread context.
 * Only available if the service registered co_call.
 */
/* Atomically set inheritance flags on returned descriptor slots only. */
#define MAC_CAPABILITY_CALL_F_CLOEXEC 0x0001u
#define MAC_CAPABILITY_CALL_F_CLOFORK 0x0002u
struct mac_capability_call_args {
	const void	*req;
	uint32_t	req_len;
	uint32_t	flags;		/* MAC_CAPABILITY_CALL_F_* */
	const int	*req_fds;
	uint32_t	req_nfds;
	void		*reply;
	uint32_t	reply_len;	/* IN: buffer size, OUT: actual */
	int		*reply_fds;	/* OUT: returned fds */
	uint32_t	reply_nfds;	/* IN: max, OUT: actual */
	struct mac_capability_cred_trailer trailer; /* OUT: caller credentials */
	uint32_t	_reserved[2];
};

/*
 * Query capability metadata.
 */
#define	MAC_CAPABILITY_INFO_F_SENDMSG	0x00000001u	/* async SENDMSG path */
#define	MAC_CAPABILITY_INFO_F_CALL	0x00000002u	/* synchronous CALL path */
#define	MAC_CAPABILITY_INFO_F_KQUEUE	0x00000004u	/* kqueue readiness support */
#define	MAC_CAPABILITY_INFO_F_RECVMSG	0x00000008u	/* async RECVMSG path */
#define	MAC_CAPABILITY_INFO_F_CHANNEL_CALL	0x00000010u /* CHANNEL_CALL ioctl */

struct mac_capability_info_args {
	char		name[MAC_CAPABILITY_MAXNAME]; /* OUT: service name */
	uint64_t	badge;		    /* OUT: capability badge */
	uint32_t	msg_limit;	    /* OUT: max payload bytes */
	uint32_t	queue_depth;	    /* OUT: max RX queue depth */
	uint32_t	tx_limit;	    /* OUT: TX notification soft limit */
	uint32_t	max_fds;	    /* OUT: max attached fds per message */
	uint32_t	features;	    /* OUT: MAC_CAPABILITY_INFO_F_* */
	uint32_t	_reserved[1];
};

#define	MAC_CAPABILITY_CONNECT		_IOWR('Y', 1, struct mac_capability_connect_args)
#define	MAC_CAPABILITY_SENDMSG		_IOW('Y', 2, struct mac_capability_sendmsg_args)
#define	MAC_CAPABILITY_RECVMSG		_IOWR('Y', 3, struct mac_capability_recvmsg_args)
#define	MAC_CAPABILITY_CALL		_IOWR('Y', 4, struct mac_capability_call_args)
#define	MAC_CAPABILITY_GETINFO		_IOR('Y', 5, struct mac_capability_info_args)
#define	MAC_CAPABILITY_REVOKE_SEND		_IO('Y', 7)
#define	MAC_CAPABILITY_REVOKE_RECV		_IO('Y', 8)
#define	MAC_CAPABILITY_REVOKE_CALL		_IO('Y', 9)
#define	MAC_CAPABILITY_TERMINATE		_IO('Y', 10)
#define	MAC_CAPABILITY_REVOKE_MINT		_IO('Y', 12)

/*
 * Mint a new instance of the same service from an existing instance.
 * Only available on services created with MAC_CAPABILITY_SVC_MINTABLE.
 * The service's co_connect callback runs to authorize the mint.
 * The caller keeps their original instance.
 */
struct mac_capability_mint_instance_args {
	int		fd;		/* OUT: new instance fd */
	uint32_t	flags;		/* reserved, must be 0 */
	uint32_t	_reserved[2];
};

#define	MAC_CAPABILITY_MINT_INSTANCE	_IOWR('Y', 11, struct mac_capability_mint_instance_args)

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_IOCTL_H_ */
