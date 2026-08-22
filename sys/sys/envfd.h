/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _SYS_ENVFD_H_
#define	_SYS_ENVFD_H_

#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/types.h>

#define	ENVFD_NAME_MAX		64

/*
 * Object flags.  ENVFD_WRITE_ONCE seals the shared object after its first
 * successful write, not merely the descriptor used for that write.
 */
#define	ENVFD_WRITE_ONCE	0x00000001U
#define	ENVFD_CAPMODE_ONLY	0x00000002U
#define	ENVFD_VALID_FLAGS	(ENVFD_WRITE_ONCE | ENVFD_CAPMODE_ONLY)

/*
 * Public creation options.  eco_size must be initialized to sizeof(*eco).
 * eco_access must be O_RDWR.  Attenuate individual copies with Capsicum
 * rights after creation.  eco_fdflags accepts FD_CLOEXEC and FD_CLOFORK.
 */
struct envfd_create_options {
	uint32_t	eco_size;
	uint32_t	eco_flags;
	uint32_t	eco_access;
	uint32_t	eco_fdflags;
	uint32_t	eco_xfer_state;
	uint32_t	eco_cloexec_state;
	uint32_t	eco_clofork_state;
	uint32_t	eco_reserved0;
	uint64_t	eco_max_value_size;
	uint64_t	eco_reserved[3];
};

#define	ENVFD_CREATE_OPTIONS_INITIALIZER(maxsize)			\
	{								\
		.eco_size = sizeof(struct envfd_create_options),		\
		.eco_access = O_RDWR,					\
		.eco_xfer_state = CAP_XFER_UNLIMITED,			\
		.eco_cloexec_state = CAP_CLOEXEC_UNLOCKED,		\
		.eco_clofork_state = CAP_CLOFORK_UNLOCKED,		\
		.eco_max_value_size = (maxsize),				\
	}

#define	ENVFD_STATE_UNWRITTEN	0
#define	ENVFD_STATE_READY	1
#define	ENVFD_STATE_SEALED	2

struct envfd_info {
	uint32_t	ei_size;
	uint32_t	ei_flags;
	uint32_t	ei_state;
	uint32_t	ei_reserved0;
	uint64_t	ei_value_size;
	uint64_t	ei_max_value_size;
	uint64_t	ei_generation;
	uint64_t	ei_reserved[3];
	char		ei_name[ENVFD_NAME_MAX];
};

#define	ENVFD_GETINFO	_IOR('E', 1, struct envfd_info)

#ifdef _KERNEL
struct file;
struct thread;

int	envfd_create_file(struct thread *td, struct file *fp,
	    const char *name, const struct envfd_create_options *options);
#else
__BEGIN_DECLS
int	envfd_create(const char *name,
	    const struct envfd_create_options *options);
__END_DECLS
#endif /* _KERNEL */

#endif /* !_SYS_ENVFD_H_ */
