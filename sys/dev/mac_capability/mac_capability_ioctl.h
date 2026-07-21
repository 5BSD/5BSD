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
struct mac_capability_cred_trailer {
	uint32_t	uid;
	uint32_t	gid;
	int32_t		prison_id;
	uint64_t	nonce;		/* program identity (inherited on fork, rotates on exec) */
};

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
struct mac_capability_recvmsg_args {
	void		*payload;
	uint32_t	payload_len;	/* IN: buffer size, OUT: actual */
	uint32_t	flags;		/* reserved, must be 0 */
	int		*fds;		/* OUT: received fds */
	uint32_t	nfds;		/* IN: max, OUT: actual */
	uint64_t	badge;		/* OUT: message badge */
	uint64_t	reply_token;	/* OUT: correlation token */
	struct mac_capability_cred_trailer trailer; /* OUT: sender credentials */
	uint32_t	_reserved[4];
};

/*
 * Synchronous call — request and reply in one ioctl.
 * The handler runs in the caller's thread context.
 * Only available if the service registered co_call.
 */
struct mac_capability_call_args {
	const void	*req;
	uint32_t	req_len;
	uint32_t	flags;		/* reserved, must be 0 */
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
