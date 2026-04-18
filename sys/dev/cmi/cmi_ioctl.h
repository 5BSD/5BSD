/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi -- message-passing capability framework for kernel modules.
 *
 * Shared kernel/userspace ioctl definitions.
 *
 * Userspace:
 *   open("/dev/cmi") -> ioctl(CMI_CONNECT, &args) -> capability fd
 *
 * Messaging:
 *   ioctl(fd, CMI_SENDMSG, &args)    send async message
 *   ioctl(fd, CMI_RECVMSG, &args)    receive async message (blocks)
 *   ioctl(fd, CMI_CALL, &args)       synchronous call (caller context)
 *
 * Introspection:
 *   ioctl(fd, CMI_GETINFO, &args)    query capability metadata
 *
 * Capability control:
 *   ioctl(fd, CMI_LOCK, NULL)        prevent SCM_RIGHTS delegation
 *   ioctl(fd, CMI_REVOKE_SEND, NULL) strip send ability (one-way)
 *   ioctl(fd, CMI_REVOKE_RECV, NULL) strip recv ability (one-way)
 *   ioctl(fd, CMI_REVOKE_CALL, NULL) strip call ability (one-way)
 *   ioctl(fd, CMI_TERMINATE, NULL)   kill instance for all holders
 *   close(fd)                        tear down (last close kills)
 *
 * read()/write() are not supported on capabilities.
 * Capsicum cap_ioctls_limit() restricts which ioctls a given fd
 * can perform.
 */

#ifndef _DEV_CMI_CMI_IOCTL_H_
#define _DEV_CMI_CMI_IOCTL_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#define	CMI_MAXNAME		64
#define	CMI_MAX_FDS		16
#define	CMI_MAX_MSG		8192
#define	CMI_DEFAULT_QUEUE_DEPTH	256
#define	CMI_DEFAULT_TX_LIMIT	CMI_DEFAULT_QUEUE_DEPTH


/*
 * Credential trailer -- kernel-stamped, unforgeable.
 */
struct cmi_cred_trailer {
	uid_t		uid;
	gid_t		gid;
	pid_t		pid;
	int		prison_id;
};

/*
 * Connect to a named kernel capability service.
 */
struct cmi_connect_args {
	char		name[CMI_MAXNAME];
	uint32_t	flags;		/* reserved, must be 0 */
	int		fd;		/* OUT: capability */
	uint32_t	_reserved[4];
};

/*
 * Send a message with optional fd attachment and reply token.
 */
struct cmi_sendmsg_args {
	const void	*payload;
	uint32_t	payload_len;
	uint32_t	flags;		/* reserved, must be 0 */
	const int	*fds;
	uint32_t	nfds;
	uint64_t	reply_token;
	uint32_t	_reserved[4];
};

/*
 * Receive a message with optional fd extraction and metadata.
 * Blocks until a message is available (EAGAIN with O_NONBLOCK).
 */
struct cmi_recvmsg_args {
	void		*payload;
	uint32_t	payload_len;	/* IN: buffer size, OUT: actual */
	uint32_t	flags;		/* reserved, must be 0 */
	int		*fds;		/* OUT: received fds */
	uint32_t	nfds;		/* IN: max, OUT: actual */
	uint64_t	badge;		/* OUT: message badge */
	uint64_t	reply_token;	/* OUT: correlation token */
	struct cmi_cred_trailer trailer; /* OUT: sender credentials */
	uint32_t	_reserved[4];
};

/*
 * Synchronous call — request and reply in one ioctl.
 * The handler runs in the caller's thread context.
 * Only available if the service registered co_call.
 */
struct cmi_call_args {
	const void	*req;
	uint32_t	req_len;
	uint32_t	flags;		/* reserved, must be 0 */
	const int	*req_fds;
	uint32_t	req_nfds;
	void		*reply;
	uint32_t	reply_len;	/* IN: buffer size, OUT: actual */
	int		*reply_fds;	/* OUT: returned fds */
	uint32_t	reply_nfds;	/* IN: max, OUT: actual */
	uint32_t	_reserved[2];
};

/*
 * Query capability metadata.
 */
#define	CMI_INFO_F_SENDMSG	0x00000001u	/* async SENDMSG path */
#define	CMI_INFO_F_CALL	0x00000002u	/* synchronous CALL path */
#define	CMI_INFO_F_KQUEUE	0x00000004u	/* EVFILT_READ/WRITE support */

struct cmi_info_args {
	char		name[CMI_MAXNAME]; /* OUT: service name */
	uint64_t	badge;		    /* OUT: capability badge */
	uint64_t	id;		    /* OUT: capability ID */
	uint32_t	msg_limit;	    /* OUT: max payload bytes */
	uint32_t	queue_depth;	    /* OUT: max RX queue depth */
	uint32_t	tx_limit;	    /* OUT: TX notification soft limit */
	uint32_t	max_fds;	    /* OUT: max attached fds per message */
	uint32_t	features;	    /* OUT: CMI_INFO_F_* */
	uint32_t	_reserved[1];
};

#define	CMI_CONNECT		_IOWR('Y', 1, struct cmi_connect_args)
#define	CMI_SENDMSG		_IOW('Y', 2, struct cmi_sendmsg_args)
#define	CMI_RECVMSG		_IOWR('Y', 3, struct cmi_recvmsg_args)
#define	CMI_CALL		_IOWR('Y', 4, struct cmi_call_args)
#define	CMI_GETINFO		_IOR('Y', 5, struct cmi_info_args)
#define	CMI_LOCK		_IO('Y', 6)
#define	CMI_REVOKE_SEND		_IO('Y', 7)
#define	CMI_REVOKE_RECV		_IO('Y', 8)
#define	CMI_REVOKE_CALL		_IO('Y', 9)
#define	CMI_TERMINATE		_IO('Y', 10)

#endif /* _DEV_CMI_CMI_IOCTL_H_ */
