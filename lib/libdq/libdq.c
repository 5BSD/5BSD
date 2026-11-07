/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * libdq: the controller side of a DescriptorQueue.  See libdq.h.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The dense pathconf index table is instantiated in this file only. */
#define	DQ_WANT_PC_NAMES
#include "libdq.h"

#include <capability.h>

/*
 * Queue
 */

int
dq_open(void)
{

	return (open(DQ_DEVICE, O_RDWR | O_CLOEXEC | O_CLOFORK));
}

int
dq_get_stats(int fd, struct dq_stats *st)
{

	memset(st, 0, sizeof(*st));
	return (ioctl(fd, DQ_IOC_GET_STATS, st));
}

int
dq_set_queue_depth(int q, uint32_t depth)
{

	return (ioctl(q, DQ_IOC_SET_QUEUE_DEPTH, &depth));
}

/*
 * Identity and policy
 */

void
dq_policy_default(struct dq_policy *pol)
{

	memset(pol, 0, sizeof(*pol));
	pol->dp_cache = DQ_CACHE_NONE;
	pol->dp_write = DQ_DENY;
	pol->dp_exec = DQ_DENY;
	pol->dp_mmap_shared_write = DQ_DENY;
	pol->dp_lock = DQ_EVENT;
	pol->dp_ioctl = DQ_DENY;
	pol->dp_deadline_ms = DQ_DEADLINE_DEFAULT;
	pol->dp_events = 0;
	pol->dp_rights_version = CAP_RIGHTS_VERSION;
	cap_rights_init(&pol->dp_rights);
	CAP_ALL(&pol->dp_rights);
}

static void
dq_timespec_set(struct dq_timespec *dt, const struct timespec *ts)
{

	dt->tv_sec = ts->tv_sec;
	dt->tv_nsec = ts->tv_nsec;
}

int
dq_ident_from_stat(struct dq_ident_file *di, const char *path,
    const struct stat *st, const struct statfs *sfs, int fd)
{
	struct dq_statfs *ds;
	size_t len;
	long pagesize, value;
	int i, saved;

	if (path == NULL || st == NULL || sfs == NULL) {
		errno = EINVAL;
		return (-1);
	}
	len = strlen(path);
	if (len == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (len >= DQ_PATH_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	/* fpathconf(2) below sets errno; a successful call leaves it alone. */
	saved = errno;

	memset(di, 0, sizeof(*di));
	di->di_dev = st->st_dev;
	di->di_ino = st->st_ino;
	di->di_gen = st->st_gen;
	di->di_filerev = st->st_filerev;
	di->di_mode = st->st_mode;
	di->di_nlink = st->st_nlink;
	di->di_uid = st->st_uid;
	di->di_gid = st->st_gid;
	di->di_size = st->st_size;
	di->di_blocks = st->st_blocks;
	/*
	 * vop_stdstat floors st_blksize at PAGE_SIZE and the kernel refuses a
	 * smaller value (DQ_REASON_BLKSIZE); a filesystem that reports less
	 * is floored here the same way.
	 */
	pagesize = getpagesize();
	di->di_blksize = st->st_blksize < (blksize_t)pagesize ?
	    (uint32_t)pagesize : (uint32_t)st->st_blksize;
	di->di_flags = st->st_flags;
	di->di_rdev = st->st_rdev;
	dq_timespec_set(&di->di_atime, &st->st_atim);
	dq_timespec_set(&di->di_mtime, &st->st_mtim);
	dq_timespec_set(&di->di_ctime, &st->st_ctim);
	dq_timespec_set(&di->di_birthtime, &st->st_birthtim);
	di->di_pathlen = (uint32_t)len;
	memcpy(di->di_path, path, len);

	ds = &di->di_statfs;
	ds->ds_type = sfs->f_type;
	ds->ds_flags = sfs->f_flags;
	ds->ds_bsize = sfs->f_bsize;
	ds->ds_iosize = sfs->f_iosize;
	ds->ds_blocks = sfs->f_blocks;
	ds->ds_bfree = sfs->f_bfree;
	ds->ds_bavail = sfs->f_bavail;
	ds->ds_files = sfs->f_files;
	ds->ds_ffree = sfs->f_ffree;
	ds->ds_syncwrites = sfs->f_syncwrites;
	ds->ds_asyncwrites = sfs->f_asyncwrites;
	ds->ds_syncreads = sfs->f_syncreads;
	ds->ds_asyncreads = sfs->f_asyncreads;
	ds->ds_nvnodelistsize = sfs->f_nvnodelistsize;
	ds->ds_namemax = sfs->f_namemax;
	ds->ds_owner = sfs->f_owner;
	ds->ds_fsid[0] = sfs->f_fsid.val[0];
	ds->ds_fsid[1] = sfs->f_fsid.val[1];
	strlcpy(ds->ds_fstypename, sfs->f_fstypename, sizeof(ds->ds_fstypename));
	strlcpy(ds->ds_mntfromname, sfs->f_mntfromname,
	    sizeof(ds->ds_mntfromname));
	strlcpy(ds->ds_mntonname, sfs->f_mntonname, sizeof(ds->ds_mntonname));

	/*
	 * A name the filesystem cannot answer stays out of dp_valid so the
	 * served descriptor refuses it the same way (EINVAL).  fpathconf(2)
	 * returns -1 with errno untouched for a genuine "no limit" answer,
	 * which is a valid value.
	 */
	if (fd >= 0) {
		for (i = 0; i < DQ_PC_NCOUNT; i++) {
			errno = 0;
			value = fpathconf(fd, dq_pc_names[i]);
			if (value == -1 && errno != 0)
				continue;
			di->di_pathconf.dp_valid |= (uint64_t)1 << i;
			di->di_pathconf.dp_value[i] = value;
		}
	}
	errno = saved;
	return (0);
}

/*
 * Objects
 */

int
dq_mint_file(int q, const struct dq_ident_file *ident,
    const struct dq_policy *pol, uint64_t *object, int *fd, int *reason)
{
	struct dq_mint_args *args;
	int error, rv;

	/* 3968 bytes: kept off the stack of callers that mint in threads. */
	args = calloc(1, sizeof(*args));
	if (args == NULL)
		return (-1);
	args->dm_version = DQ_API_VERSION;
	args->dm_kind = DQ_KIND_FILE;
	args->dm_ident = *ident;
	args->dm_policy = *pol;
	/*
	 * A failing ioctl copies its argument back to nobody, so the kernel
	 * stores the reason through this pointer: enum dq_reason on EINVAL,
	 * DQ_REASON_NONE on success.  Any other failure writes nothing, so
	 * the caller's variable is cleared here first.
	 */
	args->dm_reasonp = reason;
	if (reason != NULL)
		*reason = DQ_REASON_NONE;
	rv = ioctl(q, DQ_IOC_MINT, args);
	error = errno;
	if (rv == 0) {
		*object = args->dm_object;
		*fd = args->dm_fd;
	}
	free(args);
	errno = error;
	return (rv);
}

int
dq_mint_observer(int q, uint32_t flags)
{
	struct dq_observer_args args;

	memset(&args, 0, sizeof(args));
	args.do_version = DQ_API_VERSION;
	args.do_flags = flags;
	args.do_fd = -1;
	if (ioctl(q, DQ_IOC_MINT_OBSERVER, &args) == -1)
		return (-1);
	return (args.do_fd);
}

int
dq_revoke(int q, uint64_t object)
{
	struct dq_object_args args;

	memset(&args, 0, sizeof(args));
	args.doa_version = DQ_API_VERSION;
	args.doa_object = object;
	return (ioctl(q, DQ_IOC_REVOKE, &args));
}

int
dq_set_ident(int q, uint64_t object, const struct dq_ident_file *ident)
{
	struct dq_setident_args *args;
	int error, rv;

	args = calloc(1, sizeof(*args));
	if (args == NULL)
		return (-1);
	args->dsi_version = DQ_API_VERSION;
	args->dsi_object = object;
	args->dsi_ident = *ident;
	rv = ioctl(q, DQ_IOC_SETIDENT, args);
	error = errno;
	free(args);
	errno = error;
	return (rv);
}

int
dq_set_policy(int q, uint64_t object, const struct dq_policy *pol)
{
	struct dq_setpolicy_args args;

	memset(&args, 0, sizeof(args));
	args.dsp_version = DQ_API_VERSION;
	args.dsp_object = object;
	args.dsp_policy = *pol;
	return (ioctl(q, DQ_IOC_SETPOLICY, &args));
}

/*
 * Events
 */

int
dq_read_events(int fd, void *buf, size_t len, ssize_t *got)
{
	ssize_t n;

	n = read(fd, buf, len);
	if (n < 0)
		return (-1);
	*got = n;
	return (0);
}

/*
 * A record is whole when its header fits, de_size is at least a header and
 * a multiple of 8 (the ABI invariant), and it ends within the buffer.
 */
static const struct dq_event *
dq_event_at(const char *base, size_t len, size_t off)
{
	const struct dq_event *ev;

	if (off > len || len - off < sizeof(*ev))
		return (NULL);
	ev = (const struct dq_event *)(const void *)(base + off);
	if (ev->de_size < sizeof(*ev) || ev->de_size % 8 != 0 ||
	    ev->de_size > len - off)
		return (NULL);
	return (ev);
}

const struct dq_event *
dq_event_first(const void *buf, size_t len)
{

	return (dq_event_at(buf, len, 0));
}

const struct dq_event *
dq_event_next(const void *buf, size_t len, const struct dq_event *ev)
{
	size_t off;

	off = (size_t)((const char *)(const void *)ev - (const char *)buf);
	return (dq_event_at(buf, len, off + ev->de_size));
}

const void *
dq_event_body(const struct dq_event *ev, size_t *bodylen)
{

	if (bodylen != NULL)
		*bodylen = ev->de_size - sizeof(*ev);
	return ((const char *)(const void *)ev + sizeof(*ev));
}

int
dq_reply(int q, uint64_t id, int error, const void *data, size_t len)
{
	struct dq_reply r;

	if (len > UINT32_MAX || (len != 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&r, 0, sizeof(r));
	r.dr_version = DQ_API_VERSION;
	r.dr_id = id;
	r.dr_errno = error;
	r.dr_len = (uint32_t)len;
	r.dr_data = data;
	return (ioctl(q, DQ_IOC_REPLY, &r));
}

/*
 * The largest record a queue can post is a header plus kern.dq.max_io
 * (a WRITE body in a later stage); the dispatch buffer is sized once from
 * the sysctl so a single read never answers ENOBUFS.
 */
static size_t
dq_dispatch_bufsize(void)
{
	static size_t size;
	u_int max_io;
	size_t len;

	if (size != 0)
		return (size);
	len = sizeof(max_io);
	if (sysctlbyname("kern.dq.max_io", &max_io, &len, NULL, 0) != 0)
		max_io = 131072;
	size = sizeof(struct dq_event) + max_io;
	return (size);
}

int
dq_dispatch(int q, dq_handler_t handler, void *arg)
{
	const struct dq_event *ev;
	const void *body;
	char *buf;
	size_t bodylen, size;
	ssize_t got;
	int error, n;

	size = dq_dispatch_bufsize();
	buf = malloc(size);
	if (buf == NULL)
		return (-1);
	if (dq_read_events(q, buf, size, &got) != 0) {
		error = errno;
		free(buf);
		errno = error;
		return (-1);
	}
	n = 0;
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev)) {
		body = dq_event_body(ev, &bodylen);
		n++;
		if (handler(q, ev, body, bodylen, arg) != 0)
			break;
	}
	free(buf);
	return (n);
}

/*
 * The dq.observe service
 */

int
dq_observe_connect(void)
{
	int dev, error, svc;

	dev = open(DQ_MAC_CAPABILITY_DEVICE, O_RDWR | O_CLOEXEC);
	if (dev == -1)
		return (-1);
	svc = capability_service_connect(dev, DQ_OBSERVE_SERVICE);
	error = errno;
	(void)close(dev);
	errno = error;
	return (svc);
}

/*
 * A list reply is a header followed by whole entries; anything else from
 * the service is EPROTO.  The reply capacity is passed through because the
 * kernel fills as many entries as fit.
 */
static int
dq_observe_list(int svc, uint32_t op, uint64_t queue, uint64_t first,
    void *entries, size_t entrysize, size_t nbuf, size_t *count,
    uint64_t *total)
{
	struct dqo_request req;
	struct dqo_reply_hdr *hdr;
	char *reply;
	size_t capacity, nfds, replylen;
	int error;

	if (nbuf != 0 && entries == NULL) {
		errno = EINVAL;
		return (-1);
	}
	capacity = sizeof(*hdr) + nbuf * entrysize;
	reply = calloc(1, capacity);
	if (reply == NULL)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.dr_version = DQ_OBSERVE_VERSION;
	req.dr_op = op;
	req.dr_queue = queue;
	req.dr_first = first;
	replylen = capacity;
	nfds = 0;
	if (capability_kernel_call(svc, &req, sizeof(req), NULL, 0, reply,
	    &replylen, NULL, &nfds) != 0) {
		error = errno;
		free(reply);
		errno = error;
		return (-1);
	}
	hdr = (struct dqo_reply_hdr *)(void *)reply;
	if (replylen < sizeof(*hdr) || hdr->dh_version != DQ_OBSERVE_VERSION ||
	    hdr->dh_count > nbuf ||
	    replylen != sizeof(*hdr) + (size_t)hdr->dh_count * entrysize) {
		free(reply);
		errno = EPROTO;
		return (-1);
	}
	if (hdr->dh_count != 0)
		memcpy(entries, hdr + 1, (size_t)hdr->dh_count * entrysize);
	if (count != NULL)
		*count = hdr->dh_count;
	if (total != NULL)
		*total = hdr->dh_total;
	free(reply);
	return (0);
}

int
dq_observe_list_queues(int svc, uint64_t first, struct dqo_queue_info *buf,
    size_t nbuf, size_t *count, uint64_t *total)
{

	return (dq_observe_list(svc, DQO_OP_LIST_QUEUES, 0, first, buf,
	    sizeof(*buf), nbuf, count, total));
}

int
dq_observe_list_objects(int svc, uint64_t queue, uint64_t first,
    struct dqo_object_info *buf, size_t nbuf, size_t *count, uint64_t *total)
{

	return (dq_observe_list(svc, DQO_OP_LIST_OBJECTS, queue, first, buf,
	    sizeof(*buf), nbuf, count, total));
}

int
dq_observe_subscribe(int svc, uint64_t queue)
{
	struct dqo_request req;
	struct dqo_subscribe_reply rep;

	memset(&req, 0, sizeof(req));
	req.dr_version = DQ_OBSERVE_VERSION;
	req.dr_op = DQO_OP_SUBSCRIBE;
	req.dr_queue = queue;
	/*
	 * The service installs the observer in the caller itself, rights-
	 * limited and locked like an ioctl-minted one (a framework reply fd
	 * would carry full rights), and names it in the reply body.
	 */
	memset(&rep, 0, sizeof(rep));
	if (capability_service_call(svc, &req, sizeof(req), &rep,
	    sizeof(rep)) != 0)
		return (-1);
	if (rep.sr_hdr.dh_version != DQ_OBSERVE_VERSION || rep.sr_fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	return (rep.sr_fd);
}
