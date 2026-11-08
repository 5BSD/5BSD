/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * libdq: dq_serve_tree(), the controller of the served-tree oracle (D173),
 * stage 1c-iii-a mode: every start stays real.  A directory tree held open
 * at rootfd (the backing tree) is presented at a real-namespace directory
 * (the prefix).  A RESOLVE whose path, made absolute with the event's
 * start hint and normalized, names something under the prefix is answered
 * from the backing tree: open with FD (a served regular file), stat,
 * access and realpath with ATTR, readlink with LINK, chmod, chown,
 * utimes, chflags and truncate with FD of the target (the kernel applies
 * D96; the object's SETATTR follows), and the mutating operations with OK
 * after performing them.  A served object's di_path is the real-namespace
 * name the process resolved, never the backing path (D174's real-root
 * contract).  Everything else is PASSed: names outside the prefix, the
 * kernel's own lookups, non-regular objects, and every event whose accept
 * set lacks the kind the answer would need.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libdq.h"

struct dq_tree_obj {
	uint64_t		 to_id;
	int			 to_fd;		/* the backing file */
	struct dq_ident_file	 to_ident;
};

struct dq_tree {
	int			 t_q;
	int			 t_rootfd;
	uint32_t		 t_flags;
	char			 t_prefix[PATH_MAX];
	size_t			 t_prefixlen;
	struct dq_serve_state	*t_state;
	struct dq_tree_obj	**t_objs;
	size_t			 t_nobjs, t_cap;
};

/* What a resolution found. */
struct dq_tree_res {
	char	 tr_rel[PATH_MAX];	/* backing path, "." for the root */
	char	 tr_name[PATH_MAX];	/* real-namespace name presented */
	bool	 tr_exists;
	struct stat tr_st;		/* lstat of tr_rel when it exists */
};

#define	DQ_TREE_NOTMINE		(-1)	/* not under the prefix: PASS */


/* Lexical normalization of an absolute path: no ".", "..", "//". */
static int
dq_tree_normalize(const char *in, char *out, size_t outlen)
{
	char buf[PATH_MAX], *comp, *next;
	size_t len;

	if (in[0] != '/' || strlcpy(buf, in, sizeof(buf)) >= sizeof(buf))
		return (ENAMETOOLONG);
	len = 0;
	out[0] = '\0';
	for (comp = buf; comp != NULL; comp = next) {
		while (*comp == '/')
			comp++;
		next = strchr(comp, '/');
		if (next != NULL)
			*next++ = '\0';
		if (*comp == '\0' || strcmp(comp, ".") == 0)
			continue;
		if (strcmp(comp, "..") == 0) {
			while (len > 0 && out[len - 1] != '/')
				len--;
			if (len > 0)
				len--;
			out[len] = '\0';
			continue;
		}
		if (len + 1 + strlen(comp) + 1 > outlen)
			return (ENAMETOOLONG);
		out[len++] = '/';
		strcpy(out + len, comp);
		len += strlen(comp);
	}
	if (len == 0)
		strlcpy(out, "/", outlen);
	return (0);
}

/* The backing path below the prefix of an absolute normalized name. */
static const char *
dq_tree_below(const struct dq_tree *t, const char *norm)
{

	if (t->t_prefixlen == 1)
		return (norm + 1);
	if (strncmp(norm, t->t_prefix, t->t_prefixlen) != 0)
		return (NULL);
	if (norm[t->t_prefixlen] == '\0')
		return ("");
	if (norm[t->t_prefixlen] != '/')
		return (NULL);
	return (norm + t->t_prefixlen + 1);
}

/*
 * Resolve name (absolute, normalized) in the backing tree, following
 * symlinks as namei would: every one but a final one under NOFOLLOW.  A
 * symlink whose target leaves the prefix cannot be served in this mode
 * (EACCES, documented).
 */
static int
dq_tree_walk(struct dq_tree *t, const char *name, bool follow,
    struct dq_tree_res *res)
{
	char cur[PATH_MAX], rel[PATH_MAX], tgt[PATH_MAX], tmp[PATH_MAX * 2];
	const char *below, *p, *slash;
	struct stat st;
	ssize_t n;
	int loops, error;
	bool last;

	loops = 0;
	strlcpy(cur, name, sizeof(cur));
restart:
	below = dq_tree_below(t, cur);
	if (below == NULL)
		return (EACCES);
	rel[0] = '\0';
	for (p = below; *p != '\0'; p = slash != NULL ? slash + 1 : "") {
		slash = strchr(p, '/');
		last = slash == NULL;
		if (rel[0] != '\0')
			strlcat(rel, "/", sizeof(rel));
		strncat(rel, p, last ? strlen(p) : (size_t)(slash - p));
		if (fstatat(t->t_rootfd, rel, &st, AT_SYMLINK_NOFOLLOW) != 0) {
			error = errno;
			if (error == ENOENT && last) {
				res->tr_exists = false;
				goto found;
			}
			return (error);
		}
		if (S_ISLNK(st.st_mode) && (!last || follow)) {
			if (++loops > MAXSYMLINKS)
				return (ELOOP);
			n = readlinkat(t->t_rootfd, rel, tgt, sizeof(tgt) - 1);
			if (n < 0)
				return (errno);
			tgt[n] = '\0';
			if (tgt[0] == '/')
				snprintf(tmp, sizeof(tmp), "%s/%s", tgt,
				    last ? "" : slash + 1);
			else {
				/* Relative to the link's directory. */
				char *d = strrchr(rel, '/');

				if (d != NULL)
					*d = '\0';
				else
					rel[0] = '\0';
				snprintf(tmp, sizeof(tmp), "%s/%s%s%s/%s",
				    t->t_prefixlen == 1 ? "" : t->t_prefix,
				    rel, rel[0] != '\0' ? "/" : "", tgt,
				    last ? "" : slash + 1);
			}
			error = dq_tree_normalize(tmp, cur, sizeof(cur));
			if (error != 0)
				return (error);
			goto restart;
		}
		if (!last && !S_ISDIR(st.st_mode))
			return (ENOTDIR);
		if (last) {
			res->tr_exists = true;
			res->tr_st = st;
		}
	}
	if (*below == '\0') {
		if (fstat(t->t_rootfd, &res->tr_st) != 0)
			return (errno);
		res->tr_exists = true;
	}
found:
	strlcpy(res->tr_rel, rel[0] != '\0' ? rel : ".", sizeof(res->tr_rel));
	strlcpy(res->tr_name, cur, sizeof(res->tr_name));
	return (0);
}

/* The absolute name a path of the event names, from its start hint. */
static int
dq_tree_name(struct dq_tree *t, const char *path, const char *start,
    bool startvalid, char *norm, size_t normlen)
{
	char full[PATH_MAX * 2];

	if (path[0] == '/')
		strlcpy(full, path, sizeof(full));
	else if (startvalid)
		snprintf(full, sizeof(full), "%s/%s", start, path);
	else
		return (DQ_TREE_NOTMINE);
	if (dq_tree_normalize(full, norm, normlen) != 0)
		return (DQ_TREE_NOTMINE);
	return (dq_tree_below(t, norm) == NULL ? DQ_TREE_NOTMINE : 0);
}

/* The identity of a backing node, presented under its resolved name. */
static int
dq_tree_ident(struct dq_tree *t, const struct dq_tree_res *res,
    struct dq_ident_file *ident)
{
	struct statfs sfs;
	int fd, error;

	fd = openat(t->t_rootfd, res->tr_rel, O_PATH | O_NOFOLLOW);
	if (fd < 0)
		return (errno);
	error = 0;
	if (fstatfs(fd, &sfs) != 0)
		error = errno;
	else {
		/* The presented mount is "/": a prefix of every name. */
		strlcpy(sfs.f_mntonname, "/", sizeof(sfs.f_mntonname));
		if (dq_ident_from_stat(ident, res->tr_name, &res->tr_st, &sfs,
		    S_ISREG(res->tr_st.st_mode) ? fd : -1) != 0)
			error = errno;
	}
	close(fd);
	return (error);
}

static int
dq_tree_add(struct dq_tree *t, uint64_t id, int fd,
    const struct dq_ident_file *ident)
{
	struct dq_tree_obj **n, *o;

	if (t->t_nobjs == t->t_cap) {
		n = reallocarray(t->t_objs, t->t_cap * 2 + 8, sizeof(*n));
		if (n == NULL)
			return (-1);
		t->t_objs = n;
		t->t_cap = t->t_cap * 2 + 8;
	}
	o = malloc(sizeof(*o));
	if (o == NULL)
		return (-1);
	o->to_id = id;
	o->to_fd = fd;
	o->to_ident = *ident;
	t->t_objs[t->t_nobjs++] = o;
	return (0);
}

static struct dq_tree_obj *
dq_tree_find(struct dq_tree *t, uint64_t id, size_t *ip)
{
	size_t i;

	for (i = 0; i < t->t_nobjs; i++) {
		if (t->t_objs[i]->to_id == id) {
			if (ip != NULL)
				*ip = i;
			return (t->t_objs[i]);
		}
	}
	return (NULL);
}

/*
 * Mint the answer: the backing file open for what the object will need,
 * kept in the table under the id the kernel returned.
 */
static int
dq_tree_reply_fd(struct dq_tree *t, uint64_t evid, const struct dq_tree_res *res,
    bool write, uint32_t mflags)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	uint64_t id;
	int fd, error;

	fd = openat(t->t_rootfd, res->tr_rel,
	    (write ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 && !write)
		fd = openat(t->t_rootfd, res->tr_rel, O_PATH | O_NOFOLLOW |
		    O_CLOEXEC);
	if (fd < 0)
		return (dq_reply_resolve_errno(t->t_q, evid, errno));
	ident = malloc(sizeof(*ident));
	if (ident == NULL) {
		close(fd);
		return (-1);
	}
	error = dq_tree_ident(t, res, ident);
	if (error != 0) {
		free(ident);
		close(fd);
		return (dq_reply_resolve_errno(t->t_q, evid, error));
	}
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if ((t->t_flags & DQ_TREE_F_WRITE) != 0 && write) {
		pol.dp_write = DQ_EVENT;
		mflags |= DQ_MINT_F_WRITE;
	}
	id = 0;
	if (dq_reply_resolve_fd(t->t_q, evid, DQ_KIND_FILE, mflags, ident,
	    &pol, &id, NULL) != 0) {
		error = errno;
		free(ident);
		close(fd);
		/* Never leave the event in flight: the requester gets EIO. */
		if (error == ESRCH)
			return (0);
		return (dq_reply_resolve_errno(t->t_q, evid, EIO));
	}
	if (dq_tree_add(t, id, fd, ident) != 0)
		close(fd);	/* its CLOSE finds nothing */
	free(ident);
	return (0);
}

static int
dq_tree_errno(struct dq_tree *t, uint64_t evid,
    const struct dq_resolve_body *rb, int error)
{

	if (error <= 0 || !dq_resolve_errno_allowed_ev(rb, error))
		error = EIO;
	return (dq_reply_resolve_errno(t->t_q, evid, error));
}

/* A creating or removing operation, performed in the backing tree. */
static int
dq_tree_mutate(struct dq_tree *t, const struct dq_resolve_body *rb,
    const struct dq_tree_res *res, const struct dq_tree_res *res2,
    const char *path2)
{
	int r;

	switch (rb->drs_op) {
	case DQ_ROP_MKDIR:
		r = mkdirat(t->t_rootfd, res->tr_rel, rb->drs_cmode);
		break;
	case DQ_ROP_MKFIFO:
		r = mkfifoat(t->t_rootfd, res->tr_rel, rb->drs_cmode);
		break;
	case DQ_ROP_MKNOD:
		r = mknodat(t->t_rootfd, res->tr_rel,
		    (rb->drs_mode & S_IFMT) | rb->drs_cmode,
		    (dev_t)rb->drs_dev);
		break;
	case DQ_ROP_UNLINK:
		r = unlinkat(t->t_rootfd, res->tr_rel, 0);
		break;
	case DQ_ROP_RMDIR:
		r = unlinkat(t->t_rootfd, res->tr_rel, AT_REMOVEDIR);
		break;
	case DQ_ROP_SYMLINK:
		r = symlinkat(path2, t->t_rootfd, res->tr_rel);
		break;
	case DQ_ROP_RENAME:
		/* drs_mode holds renameat2's flags (AT_RENAME_NOREPLACE). */
		r = renameat2(t->t_rootfd, res->tr_rel, t->t_rootfd,
		    res2->tr_rel, rb->drs_mode);
		break;
	case DQ_ROP_LINK:
		r = linkat(t->t_rootfd, res->tr_rel, t->t_rootfd,
		    res2->tr_rel, 0);
		break;
	default:
		return (EIO);
	}
	return (r != 0 ? errno : 0);
}

static int
dq_tree_resolve(struct dq_tree *t, const struct dq_event *ev)
{
	const struct dq_resolve_body *rb;
	const struct dq_setattr_body *sb;
	const char *path, *path2, *sp, *sp2;
	char norm[PATH_MAX], norm2[PATH_MAX];
	struct dq_tree_res *res, *res2;
	struct dq_ident_file *ident;
	char tgt[PATH_MAX];
	uint32_t want, mflags;
	ssize_t n;
	int error, fd, ret, mine, mine2, flags;
	bool follow, writable;

	if (dq_event_resolve_ext(ev, &rb, &path, &path2, &sp, &sp2, &sb) != 0)
		return (dq_reply_resolve_errno(t->t_q, ev->de_id, EIO));
	/* The kernel's own lookups and every non-path consultation. */
	if (rb->drs_flags != DQ_RCLASS_USER ||
	    (rb->drs_start_kind != DQ_START_REAL_ROOT &&
	    rb->drs_start_kind != DQ_START_REAL_CWD &&
	    rb->drs_start_kind != DQ_START_REAL_DIRFD))
		return (dq_reply_resolve_pass(t->t_q, ev->de_id));
	mine = dq_tree_name(t, path, sp,
	    (rb->drs_rflags & DQ_RF_STARTPATH_VALID) != 0, norm, sizeof(norm));
	if (rb->drs_op == DQ_ROP_RENAME || rb->drs_op == DQ_ROP_LINK) {
		mine2 = path2[0] == '\0' ? DQ_TREE_NOTMINE :
		    dq_tree_name(t, path2, sp2,
		    (rb->drs_rflags & DQ_RF_STARTPATH2_VALID) != 0, norm2,
		    sizeof(norm2));
		if (mine != 0 && mine2 != 0)
			return (dq_reply_resolve_pass(t->t_q, ev->de_id));
		if (mine != mine2)
			return (dq_tree_errno(t, ev->de_id, rb, EXDEV));
	} else if (mine != 0)
		return (dq_reply_resolve_pass(t->t_q, ev->de_id));

	/* The kind this operation is answered with. */
	switch (rb->drs_op) {
	case DQ_ROP_OPEN:
	case DQ_ROP_SETATTR:
	case DQ_ROP_TRUNCATE:
		want = DQ_RESOLVE_FD;
		break;
	case DQ_ROP_STAT:
	case DQ_ROP_ACCESS:
	case DQ_ROP_REALPATH:
		want = DQ_RESOLVE_ATTR;
		break;
	case DQ_ROP_READLINK:
		want = DQ_RESOLVE_LINK;
		break;
	case DQ_ROP_MKDIR: case DQ_ROP_MKNOD: case DQ_ROP_MKFIFO:
	case DQ_ROP_UNLINK: case DQ_ROP_RMDIR: case DQ_ROP_SYMLINK:
	case DQ_ROP_RENAME: case DQ_ROP_LINK:
		want = DQ_RESOLVE_OK;
		break;
	case DQ_ROP_EXEC:
		return (dq_tree_errno(t, ev->de_id, rb, EACCES));
	case DQ_ROP_XATTR:
	case DQ_ROP_ACL:
		return (dq_tree_errno(t, ev->de_id, rb, EOPNOTSUPP));
	default:
		return (dq_reply_resolve_pass(t->t_q, ev->de_id));
	}
	/* A restricted lookup takes PASS only: the real namespace answers. */
	if (!dq_resolve_accepts(rb, want))
		return (dq_reply_resolve_pass(t->t_q, ev->de_id));

	res = calloc(2, sizeof(*res));
	ident = malloc(sizeof(*ident));
	if (res == NULL || ident == NULL) {
		free(res);
		free(ident);
		return (dq_reply_resolve_errno(t->t_q, ev->de_id, EIO));
	}
	res2 = &res[1];
	writable = (t->t_flags & DQ_TREE_F_WRITE) != 0;
	follow = (rb->drs_rflags & DQ_RF_NOFOLLOW) == 0 ||
	    (rb->drs_rflags & DQ_RF_TRAILINGSLASH) != 0;
	error = dq_tree_walk(t, norm, follow, res);
	if (error == 0 && (rb->drs_op == DQ_ROP_RENAME ||
	    rb->drs_op == DQ_ROP_LINK))
		error = dq_tree_walk(t, norm2, false, res2);
	if (error != 0) {
		ret = dq_tree_errno(t, ev->de_id, rb, error);
		goto out;
	}
	ret = 0;
	error = 0;
	switch (rb->drs_op) {
	case DQ_ROP_OPEN:
		flags = (int)rb->drs_mode;
		mflags = 0;
		if (res->tr_exists && (flags & (O_CREAT | O_EXCL)) ==
		    (O_CREAT | O_EXCL)) {
			error = EEXIST;
			break;
		}
		if (!res->tr_exists) {
			if ((flags & O_CREAT) == 0) {
				error = ENOENT;
				break;
			}
			if (!writable) {
				error = EROFS;
				break;
			}
			fd = openat(t->t_rootfd, res->tr_rel, O_CREAT | O_EXCL |
			    O_WRONLY | O_CLOEXEC, rb->drs_cmode);
			if (fd < 0) {
				error = errno;
				break;
			}
			close(fd);
			if (fstatat(t->t_rootfd, res->tr_rel, &res->tr_st,
			    AT_SYMLINK_NOFOLLOW) != 0) {
				error = errno;
				break;
			}
			res->tr_exists = true;
			mflags |= DQ_MINT_F_CREATED;
		}
		if (!S_ISREG(res->tr_st.st_mode)) {
			/* A directory, device, FIFO or socket: iii-b. */
			ret = dq_reply_resolve_pass(t->t_q, ev->de_id);
			goto out;
		}
		/*
		 * O_TRUNC is applied by the kernel through the object after
		 * its access check (a SETATTR); the backing file opens for
		 * writing when the open writes or truncates.
		 */
		if (!writable && ((flags & O_ACCMODE) != O_RDONLY ||
		    (flags & O_TRUNC) != 0)) {
			error = EROFS;
			break;
		}
		ret = dq_tree_reply_fd(t, ev->de_id, res,
		    (flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC) != 0,
		    mflags);
		goto out;
	case DQ_ROP_SETATTR:
	case DQ_ROP_TRUNCATE:
		if (!res->tr_exists) {
			error = ENOENT;
			break;
		}
		if (!S_ISREG(res->tr_st.st_mode)) {
			ret = dq_reply_resolve_pass(t->t_q, ev->de_id);
			goto out;
		}
		if (!writable) {
			error = EROFS;
			break;
		}
		/* The kernel applies D96 through the FD and posts SETATTR. */
		ret = dq_tree_reply_fd(t, ev->de_id, res,
		    rb->drs_op == DQ_ROP_TRUNCATE, 0);
		goto out;
	case DQ_ROP_STAT:
	case DQ_ROP_ACCESS:
	case DQ_ROP_REALPATH:
		if (!res->tr_exists) {
			error = ENOENT;
			break;
		}
		error = dq_tree_ident(t, res, ident);
		if (error == 0)
			ret = dq_reply_resolve_attr(t->t_q, ev->de_id, ident);
		break;
	case DQ_ROP_READLINK:
		if (!res->tr_exists) {
			error = ENOENT;
			break;
		}
		if (!S_ISLNK(res->tr_st.st_mode)) {
			error = EINVAL;
			break;
		}
		n = readlinkat(t->t_rootfd, res->tr_rel, tgt, sizeof(tgt) - 1);
		if (n <= 0) {
			error = n < 0 ? errno : EINVAL;
			break;
		}
		tgt[n] = '\0';
		error = dq_tree_ident(t, res, ident);
		if (error == 0) {
			ident->di_size = (uint64_t)n;
			ret = dq_reply_resolve_link(t->t_q, ev->de_id, ident,
			    tgt);
		}
		break;
	default:
		/* The creating and removing operations: OK once done. */
		error = writable ? dq_tree_mutate(t, rb, res, res2, path2) :
		    EROFS;
		break;
	}
	if (error != 0)
		ret = dq_tree_errno(t, ev->de_id, rb, error);
	else if (want == DQ_RESOLVE_OK)
		ret = dq_reply_resolve_ok(t->t_q, ev->de_id);
out:
	free(res);
	free(ident);
	return (ret);
}

struct dq_tree *
dq_tree_create(int q, int rootfd, const char *prefix, uint32_t flags)
{
	struct dq_tree *t;

	if (prefix == NULL || prefix[0] != '/' ||
	    (flags & ~DQ_TREE_F_WRITE) != 0) {
		errno = EINVAL;
		return (NULL);
	}
	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return (NULL);
	if (dq_tree_normalize(prefix, t->t_prefix, sizeof(t->t_prefix)) != 0) {
		free(t);
		errno = ENAMETOOLONG;
		return (NULL);
	}
	t->t_prefixlen = strlen(t->t_prefix);
	t->t_q = q;
	t->t_rootfd = rootfd;
	t->t_flags = flags;
	t->t_state = dq_serve_state_create();
	return (t);
}

void
dq_tree_destroy(struct dq_tree *t)
{
	size_t i;

	if (t == NULL)
		return;
	for (i = 0; i < t->t_nobjs; i++) {
		close(t->t_objs[i]->to_fd);
		free(t->t_objs[i]);
	}
	free(t->t_objs);
	if (t->t_state != NULL)
		dq_serve_state_destroy(t->t_state);
	free(t);
}

int
dq_tree_objects(const struct dq_tree *t)
{

	return ((int)t->t_nobjs);
}

int
dq_serve_tree(struct dq_tree *t, const struct dq_event *ev, const void *body,
    size_t bodylen)
{
	struct dq_serve_opts opts;
	struct dq_tree_obj *o;
	size_t i;
	int ret;

	if (ev->de_op == DQ_OP_RESOLVE)
		return (dq_tree_resolve(t, ev));
	if (ev->de_object == 0)
		return (dq_serve_file(t->t_q, ev, body, bodylen, -1, NULL));
	o = dq_tree_find(t, ev->de_object, &i);
	if (o == NULL) {
		/* An object this tree never minted (or lost): EIO. */
		if (ev->de_id == 0)
			return (0);
		return (dq_reply(t->t_q, ev->de_id, EIO, NULL, 0));
	}
	memset(&opts, 0, sizeof(opts));
	opts.so_state = t->t_state;
	opts.so_ident = &o->to_ident;
	ret = dq_serve_file(t->t_q, ev, body, bodylen, o->to_fd, &opts);
	if (ev->de_op == DQ_OP_CLOSE) {
		close(o->to_fd);
		free(o);
		t->t_objs[i] = t->t_objs[--t->t_nobjs];
	}
	return (ret);
}
