/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * libdq: the controller side of a DescriptorQueue (dq(4)).
 *
 * A controller opens a queue, mints descriptors that present an identity of
 * its choosing, reads the events the kernel posts for operations on them
 * and answers by id.  Every function here is a thin, errno-preserving
 * wrapper over the ioctls and read(2) of <dev/dq/dq.h>; the kernel's own
 * errnos pass through unchanged and libdq(3) lists them per function.
 */

#ifndef _LIBDQ_H_
#define	_LIBDQ_H_

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <stdint.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_observe_proto.h>

/* The device node; one open is one queue. */
#define	DQ_DEVICE		"/dev/dq"
/* The mac_capability device dq_observe_connect() opens. */
#define	DQ_MAC_CAPABILITY_DEVICE	"/dev/mac_capability"

__BEGIN_DECLS

/*
 * Queue
 */

/*
 * Open a queue: O_RDWR|O_CLOEXEC|O_CLOFORK, so a forked requester inherits
 * the minted descriptors and not the queue (D86: the EDEADLK rule applies to
 * any process whose table holds the queue).  Returns the queue fd or -1.
 */
int	dq_open(void);

/* Statistics of a queue or of an observer descriptor. */
int	dq_get_stats(int fd, struct dq_stats *st);

/* Lower the queue's depth; 1..kern.dq.queue_depth, never above it. */
int	dq_set_queue_depth(int q, uint32_t depth);

/*
 * Identity and policy
 */

/*
 * The stage 1a policy the kernel accepts (D87): no served writes, locks as
 * events (nothing posts), no ioctls, no exec, no shared writable mappings,
 * the default deadline, no optional events, and CAP_ALL_RIGHTS because
 * that is what open(2) returns.
 */
void	dq_policy_default(struct dq_policy *pol);

/*
 * Fill an identity from a real file: path (absolute and normalized, as the
 * kernel validates it), the stat and statfs the caller took, and the
 * pathconf answers of fd (fpathconf(2) is asked for every dq_pc_names[]
 * entry; a name the filesystem refuses is left out of dp_valid, so the
 * served descriptor refuses it too).  fd may be -1 to present no pathconf.
 * di_blksize is floored at the page size, as the kernel requires.
 */
int	dq_ident_from_stat(struct dq_ident_file *ident, const char *path,
	    const struct stat *st, const struct statfs *sfs, int fd);

/*
 * Objects
 */

/*
 * Mint a DQ_KIND_FILE object.  On success *object is its id and *fd the
 * descriptor installed in the caller (O_CLOEXEC, dp_rights, not
 * transferable over SCM_RIGHTS).  On EINVAL *reason names the refused
 * field (enum dq_reason); reason may be NULL.
 */
int	dq_mint_file(int q, const struct dq_ident_file *ident,
	    const struct dq_policy *pol, uint64_t *object, int *fd,
	    int *reason);

/* Mint an observer descriptor of the queue (DQ_OBS_F_*).  Returns the fd. */
int	dq_mint_observer(int q, uint32_t flags);

int	dq_revoke(int q, uint64_t object);
int	dq_set_ident(int q, uint64_t object, const struct dq_ident_file *ident);
int	dq_set_policy(int q, uint64_t object, const struct dq_policy *pol);

/*
 * Events
 */

/*
 * One read(2) of whole records into buf; *got is the byte count (0 only
 * when an observer's queue has gone away).  EINVAL for len below one
 * header, ENOBUFS when the next record does not fit an empty buffer,
 * EAGAIN on an empty non-blocking queue, ENXIO once the queue closes.
 */
int	dq_read_events(int fd, void *buf, size_t len, ssize_t *got);

/*
 * Walk the records of a buffer.  Each returns NULL when no further whole
 * record (de_size at least a header, within len) follows.
 */
const struct dq_event *dq_event_first(const void *buf, size_t len);
const struct dq_event *dq_event_next(const void *buf, size_t len,
	    const struct dq_event *ev);

/* The body that follows the header; *bodylen may be NULL. */
const void *dq_event_body(const struct dq_event *ev, size_t *bodylen);

/*
 * Answer an event: error is 0 or an errno; data/len the reply body the
 * operation defines (READ: up to the asked length, short means EOF;
 * GETATTR: exactly one struct dq_ident_file when error is 0).
 */
int	dq_reply(int q, uint64_t id, int error, const void *data, size_t len);

/*
 * One read(2) and one handler call per record.  The handler returns 0 to
 * continue or nonzero to stop; dq_dispatch returns the records handed
 * over, or -1 when the read failed.
 */
typedef int (*dq_handler_t)(int q, const struct dq_event *ev,
	    const void *body, size_t bodylen, void *arg);
int	dq_dispatch(int q, dq_handler_t handler, void *arg);

/*
 * The dq.observe service (D90)
 */

/* Connect to dq.observe through /dev/mac_capability.  Returns the fd. */
int	dq_observe_connect(void);

/*
 * List queues (or the objects of one queue) starting at index first into
 * buf[nbuf]; *count is how many were filled, *total how many exist (either
 * may be NULL).
 */
int	dq_observe_list_queues(int svc, uint64_t first,
	    struct dqo_queue_info *buf, size_t nbuf, size_t *count,
	    uint64_t *total);
int	dq_observe_list_objects(int svc, uint64_t queue, uint64_t first,
	    struct dqo_object_info *buf, size_t nbuf, size_t *count,
	    uint64_t *total);

/* A metadata-only observer of queue.  Returns the observer fd. */
int	dq_observe_subscribe(int svc, uint64_t queue);

__END_DECLS

#endif /* !_LIBDQ_H_ */
