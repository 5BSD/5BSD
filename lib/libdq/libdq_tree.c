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
 *
 * Stage 1c-iii-b mode (DQ_TREE_F_SERVED): dq_tree_root() mints the tree's
 * root as a served directory, a lookup start for the attached processes
 * that inherit it.  A lookup from a served start (DQ_START_SERVED, whose
 * hint is the start's presented path) is answered as above, never PASS:
 * directories are served (FD of a DIR, READDIR from getdirentries(2) of
 * the backing directory, cookies being its offsets), a final symbolic
 * link under O_PATH | O_NOFOLLOW is a served SYMLINK, and a device, FIFO
 * or socket node, an AF_UNIX connect or bind, a name outside the prefix,
 * and the operations the tree does not serve are answered REAL with the
 * real path (the backing path for names under the prefix), when the
 * event accepts it.  A symbolic link in the backing tree leading out of
 * the prefix is followed by REAL too.  DQ_TREE_F_EXEC_REAL answers exec
 * REAL as well.
 *
 * Stage 1c-iii-c (DQ_TREE_F_ROOT, with DQ_TREE_F_SERVED): the attached
 * processes' served roots are directories of the tree (ATTACH's
 * da_rootfd, or a chroot answered with one).  Each event names the
 * process's own root (drs_root and its path, D184), possibly nested
 * inside the tree.  A lookup from a served start is walked inside the
 * tree as chroot(2) walks it from that root: absolute names and a backing
 * symbolic link's absolute target start at it, and ".." stops at it (the
 * controller clamps; the kernel's guard refuses any answer outside it,
 * D174).  A root outside the tree, or a served start whose hint is
 * missing or not its own path, is EIO, never walked from the real "/".
 * CHDIR and CHROOT of a directory are answered FD of a served DIR
 * (ENOTDIR for anything else), and the exec interpreter's consultation at
 * the served root (EXEC_INTERP, D175) REAL of the backing interpreter, so
 * the interpreter comes from the tree.  A real-start name outside the
 * tree is EACCES unless DQ_TREE_F_OUTSIDE_PASS PASSes it.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

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
	uint32_t		 to_kind;	/* DQ_KIND_* */
	struct dq_ident_file	 to_ident;
};

struct dq_tree {
	int			 t_q;
	int			 t_rootfd;
	uint32_t		 t_flags;
	char			 t_prefix[PATH_MAX];
	size_t			 t_prefixlen;
	char			 t_realroot[PATH_MAX]; /* rootfd's real path */
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
 * An absolute normalized name under the prefix as a tree-relative
 * absolute name ("/" for the prefix itself; it points into norm or is a
 * literal), or NULL when it is not under the prefix.
 */
static const char *
dq_tree_vname(const struct dq_tree *t, const char *norm)
{
	const char *below;

	if (norm[0] != '/' || (below = dq_tree_below(t, norm)) == NULL)
		return (NULL);
	/* A non-empty below follows the '/' that ends the prefix. */
	return (below[0] == '\0' ? "/" : below - 1);
}

/* Drop the last component of an absolute normalized name ("/" stays). */
static void
dq_tree_pop(char *name)
{
	char *s;

	s = strrchr(name, '/');
	if (s == NULL || s == name)
		strcpy(name, "/");
	else
		*s = '\0';
}

/* The backing tree, confined: every *at below rootfd resolves beneath it. */
#define	DQ_TREE_AT	AT_RESOLVE_BENEATH
#define	DQ_TREE_O	(O_RESOLVE_BENEATH | O_CLOEXEC)

/* readlinkat(2) of a backing node through a confined O_PATH open. */
static ssize_t
dq_tree_readlink(struct dq_tree *t, const char *rel, char *buf, size_t len)
{
	ssize_t n;
	int error, fd;

	fd = openat(t->t_rootfd, rel, O_PATH | O_NOFOLLOW | DQ_TREE_O);
	if (fd < 0)
		return (-1);
	n = readlinkat(fd, "", buf, len);
	error = errno;
	close(fd);
	errno = error;
	return (n);
}

/*
 * The directory holding a backing path and its last component, for the
 * operations with no confining flag (mkdirat, mkfifoat, mknodat,
 * symlinkat, renameat, linkat's second path): the parent is opened
 * O_RESOLVE_BENEATH, and the name has no '/' (tr_rel never holds "..").
 */
static int
dq_tree_parent(struct dq_tree *t, const char *rel, int *dfdp,
    const char **namep)
{
	char parent[PATH_MAX];
	const char *slash;

	slash = strrchr(rel, '/');
	if (slash == NULL) {
		strlcpy(parent, ".", sizeof(parent));
		*namep = rel;
	} else {
		if ((size_t)(slash - rel) >= sizeof(parent))
			return (ENAMETOOLONG);
		memcpy(parent, rel, slash - rel);
		parent[slash - rel] = '\0';
		*namep = slash + 1;
	}
	*dfdp = openat(t->t_rootfd, parent, O_RDONLY | O_DIRECTORY |
	    DQ_TREE_O);
	return (*dfdp < 0 ? errno : 0);
}

/* vfs.lookup_cap_dotdot{,_nonlocal}, as namei reads them. */
static bool
dq_tree_sysctl_on(const char *name)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (true);
	return (v != 0);
}

static bool
dq_tree_cap_dotdot(void)
{

	return (dq_tree_sysctl_on("vfs.lookup_cap_dotdot"));
}

/*
 * Is the directory a ".." leaves on a local file system?  Inside the
 * prefix the backing directory reached (confined), outside the real one
 * (nameicap_check_dotdot's MNT_LOCAL test, round 4).
 */
static bool
dq_tree_dir_local(struct dq_tree *t, bool inside, const char *rel,
    const char *cur)
{
	struct statfs sfs;
	int fd, rv;

	if (inside) {
		fd = openat(t->t_rootfd, rel[0] != '\0' ? rel : ".",
		    O_PATH | O_DIRECTORY | DQ_TREE_O);
		if (fd < 0)
			return (true);	/* the lookup itself will fail */
		rv = fstatfs(fd, &sfs);
		close(fd);
	} else
		rv = statfs(cur, &sfs);
	return (rv != 0 || (sfs.f_flags & MNT_LOCAL) != 0);
}

/*
 * Resolve a path of an event as namei would (1c-iii-b, review rounds 2
 * and 3): from the event's start (its hint) or the root, component by
 * component.  Inside the prefix through the backing tree (lstat per
 * component, confined beneath rootfd, symbolic links spliced in, at most
 * MAXSYMLINKS, ".." the parent of the directory actually reached, ".." at
 * the tree's root leaving it).  Outside the prefix the names are real:
 * before a ".." the directory reached is made canonical with realpath(3),
 * and so is the parent of the final name, so names after an absolute
 * symbolic link match the real file system.
 *
 * rf restricts the lookup as the kernel restricts it (DQ_RF_STRICTREL,
 * DQ_RF_BENEATH, DQ_RF_RINROOT of this path): below the start, a ".."
 * that would leave it, an absolute path or symbolic link target, and
 * under STRICTREL any ".." while vfs.lookup_cap_dotdot is 0, are
 * ENOTCAPABLE; under RINROOT an absolute name restarts at the start and
 * ".." stays there.
 *
 * *minep says the result is inside; res->tr_name is the resolved
 * real-namespace name either way (empty without a hint), and inside
 * res->tr_rel is the backing path.  In iii-a mode a backing symbolic link
 * leading out of the prefix is EACCES.
 */
static int
dq_tree_lookup(struct dq_tree *t, const char *path, const char *start,
    bool startvalid, bool follow, uint32_t rf, const char *rootv,
    struct dq_tree_res *res, bool *minep)
{
	char *work, *tmp, cur[PATH_MAX], rel[PATH_MAX], tgt[PATH_MAX];
	char cur0[PATH_MAX], rel0[PATH_MAX], canon[PATH_MAX];
	const char *p, *q, *r;
	struct stat st;
	ssize_t n;
	size_t clen;
	int error, loops, depth, phase;
	bool inside, inside0, last, trailing, viasym, restricted, rinroot;
	bool strict, capdotdot, nonlocal, vroot, dotlast;
	const char *rootrel;

	*minep = false;
	res->tr_exists = false;
	res->tr_name[0] = '\0';
	res->tr_rel[0] = '\0';
	restricted = (rf & (DQ_RF_STRICTREL | DQ_RF_BENEATH |
	    DQ_RF_RINROOT)) != 0;
	rinroot = (rf & DQ_RF_RINROOT) != 0;
	strict = (rf & DQ_RF_STRICTREL) != 0;
	capdotdot = !strict || dq_tree_cap_dotdot();
	/*
	 * namei folds O_RESOLVE_BENEATH into STRICTREL with CAP_DOTDOT, so
	 * nameicap_check_dotdot's non-local refusal applies to BENEATH too;
	 * the lookup_cap_dotdot refusal applies only under STRICTREL proper.
	 */
	nonlocal = (rf & (DQ_RF_STRICTREL | DQ_RF_BENEATH)) == 0 ||
	    dq_tree_sysctl_on("vfs.lookup_cap_dotdot_nonlocal");
	work = malloc(PATH_MAX * 2);
	tmp = malloc(PATH_MAX * 2);
	if (work == NULL || tmp == NULL) {
		free(work);
		free(tmp);
		return (ENOMEM);
	}
	error = 0;
	loops = 0;
	viasym = false;
	dotlast = false;
	depth = 0;
	inside0 = false;
	cur0[0] = rel0[0] = '\0';
	/*
	 * Under a served root inside the tree (iii-c), names are walked in
	 * the tree as chroot(2) walks them: from the tree's root, with the
	 * process's root rootv ("/" or "/d", relative to the tree) the place
	 * absolute names and absolute link targets start and ".." stops.
	 * The start hint (a served directory's real-namespace name, checked
	 * by the caller to be the start's own) becomes tree-relative; a
	 * start outside the tree is never walked from the real "/" (EIO).
	 */
	vroot = rootv != NULL;
	rootrel = vroot ? rootv + 1 : "";
	if (vroot) {
		if (!startvalid || start == NULL ||
		    (start = dq_tree_vname(t, start)) == NULL) {
			error = EIO;
			goto done;
		}
	}
	if (restricted) {
		/* Phase 0 walks the start, phase 1 the path from it. */
		if (!startvalid || start == NULL || start[0] != '/')
			goto done;
		if (path[0] == '/' && !rinroot) {
			error = ENOTCAPABLE;
			goto done;
		}
		strlcpy(work, start, PATH_MAX * 2);
	} else if (path[0] == '/' && vroot)
		/* An absolute name starts at the process's root. */
		snprintf(work, PATH_MAX * 2, "%s/%s", rootv, path);
	else if (path[0] == '/')
		strlcpy(work, path, PATH_MAX * 2);
	else if (startvalid && start != NULL && start[0] == '/')
		snprintf(work, PATH_MAX * 2, "%s/%s", start, path);
	else
		goto done;		/* no hint: not this tree's */
	phase = restricted ? 0 : 1;
restart:
	if (vroot) {
		/* The tree's root is "/": cur keeps real-namespace names. */
		strlcpy(cur, t->t_prefix, sizeof(cur));
		inside = true;
	} else {
		strlcpy(cur, "/", sizeof(cur));
		inside = t->t_prefixlen == 1;
	}
	rel[0] = '\0';
	p = work;
	for (;;) {
		while (*p == '/')
			p++;
		if (*p == '\0') {
			if (phase == 0) {
				/* The start reached: the path from here. */
				phase = 1;
				depth = 0;
				strlcpy(cur0, cur, sizeof(cur0));
				strlcpy(rel0, rel, sizeof(rel0));
				inside0 = inside;
				strlcpy(work, path, PATH_MAX * 2);
				p = work;
				continue;
			}
			break;
		}
		for (q = p; *q != '\0' && *q != '/'; q++)
			;
		clen = (size_t)(q - p);
		for (r = q; *r == '/'; r++)
			;
		last = *r == '\0' && phase == 1;
		trailing = last && *q == '/';
		/*
		 * A "." or ".." names the directory reached, which no named
		 * component's lstat describes: stat it after the walk.
		 */
		dotlast = (clen == 1 && p[0] == '.') ||
		    (clen == 2 && p[0] == '.' && p[1] == '.');
		if (clen == 1 && p[0] == '.') {
			p = q;
			continue;
		}
		if (clen == 2 && p[0] == '.' && p[1] == '.') {
			if (phase == 1 && restricted) {
				if (!capdotdot || (!nonlocal &&
				    !dq_tree_dir_local(t, inside, rel, cur))) {
					error = ENOTCAPABLE;
					goto done;
				}
				if (depth == 0) {
					if (rinroot) {
						p = q;	/* clamped */
						continue;
					}
					error = ENOTCAPABLE;
					goto done;
				}
				depth--;
			}
			if (vroot && inside && (rel[0] == '\0' ||
			    strcmp(rel, rootrel) == 0)) {
				/* ".." at the root stays, as chroot(2). */
				p = q;
				continue;
			}
			if (inside && rel[0] != '\0') {
				/* The parent of the backing directory reached. */
				if (strchr(rel, '/') != NULL)
					*strrchr(rel, '/') = '\0';
				else
					rel[0] = '\0';
				dq_tree_pop(cur);
			} else if (inside && t->t_prefixlen > 1) {
				/* Out of the tree's root, into the real parent. */
				inside = false;
				dq_tree_pop(cur);
			} else if (!inside) {
				/* A real directory: its canonical parent. */
				if (realpath(cur, canon) != NULL)
					strlcpy(cur, canon, sizeof(cur));
				dq_tree_pop(cur);
			}
			p = q;
			continue;
		}
		if (clen >= NAME_MAX + 1 ||
		    strlen(cur) + 1 + clen + 1 > sizeof(cur)) {
			error = ENAMETOOLONG;
			goto done;
		}
		if (strcmp(cur, "/") != 0)
			strlcat(cur, "/", sizeof(cur));
		strncat(cur, p, clen);
		if (phase == 1 && restricted)
			depth++;
		if (!inside) {
			/* Down a real directory; entering the prefix. */
			if (strcmp(cur, t->t_prefix) == 0)
				inside = true;
			p = q;
			continue;
		}
		if (rel[0] != '\0')
			strlcat(rel, "/", sizeof(rel));
		strncat(rel, p, clen);
		if (fstatat(t->t_rootfd, rel, &st, AT_SYMLINK_NOFOLLOW |
		    DQ_TREE_AT) != 0) {
			error = errno;
			if (error == ENOENT && last) {
				error = 0;
				break;		/* found: does not exist */
			}
			goto done;
		}
		if (S_ISLNK(st.st_mode) && (!last || follow || trailing)) {
			if (++loops > MAXSYMLINKS) {
				error = ELOOP;
				goto done;
			}
			n = dq_tree_readlink(t, rel, tgt, sizeof(tgt) - 1);
			if (n <= 0) {
				error = n < 0 ? errno : ENOENT;
				goto done;
			}
			tgt[n] = '\0';
			viasym = true;
			if ((size_t)n + strlen(q) + 1 > MAXPATHLEN) {
				error = ENAMETOOLONG;
				goto done;
			}
			/* An absolute target starts at the process's root. */
			snprintf(tmp, PATH_MAX * 2, "%s%s%s",
			    vroot && tgt[0] == '/' ? rootv : "", tgt, q);
			strlcpy(work, tmp, PATH_MAX * 2);
			if (tgt[0] == '/') {
				if (phase == 1 && restricted) {
					if (!rinroot) {
						error = ENOTCAPABLE;
						goto done;
					}
					/* RINROOT: from the start again. */
					strlcpy(cur, cur0, sizeof(cur));
					strlcpy(rel, rel0, sizeof(rel));
					inside = inside0;
					depth = 0;
					p = work;
					continue;
				}
				goto restart;
			}
			/* Relative: from the link's directory. */
			if (phase == 1 && restricted)
				depth--;
			dq_tree_pop(cur);
			if (strchr(rel, '/') != NULL)
				*strrchr(rel, '/') = '\0';
			else
				rel[0] = '\0';
			p = work;
			continue;
		}
		if (!last && !S_ISDIR(st.st_mode)) {
			error = ENOTDIR;
			goto done;
		}
		if (last) {
			if (trailing && !S_ISDIR(st.st_mode)) {
				error = ENOTDIR;
				goto done;
			}
			res->tr_exists = true;
			res->tr_st = st;
		}
		p = q;
	}
	if (!inside) {
		/* A backing symlink out of the prefix: iii-a cannot follow. */
		if (viasym && (t->t_flags & DQ_TREE_F_SERVED) == 0) {
			error = EACCES;
			goto done;
		}
		/* The real parent, canonical; the last name as given. */
		strlcpy(tmp, cur, PATH_MAX * 2);
		if (strcmp(cur, "/") != 0) {
			dq_tree_pop(tmp);
			if (realpath(tmp, canon) != NULL) {
				snprintf(tmp, PATH_MAX * 2, "%s%s%s", canon,
				    strcmp(canon, "/") == 0 ? "" : "/",
				    strrchr(cur, '/') + 1);
				strlcpy(cur, tmp, sizeof(cur));
			}
		}
		strlcpy(res->tr_name, cur, sizeof(res->tr_name));
		goto done;
	}
	strlcpy(res->tr_name, cur, sizeof(res->tr_name));
	if (rel[0] == '\0') {
		if (fstat(t->t_rootfd, &res->tr_st) != 0) {
			error = errno;
			goto done;
		}
		res->tr_exists = true;
	} else if (dotlast) {
		/* "d/." or "d/e/..": the directory reached exists. */
		if (fstatat(t->t_rootfd, rel, &res->tr_st, AT_SYMLINK_NOFOLLOW |
		    DQ_TREE_AT) != 0) {
			error = errno;
			goto done;
		}
		res->tr_exists = true;
	}
	strlcpy(res->tr_rel, rel[0] != '\0' ? rel : ".", sizeof(res->tr_rel));
	*minep = true;
done:
	free(work);
	free(tmp);
	return (error);
}

/* The identity of a backing node, presented under its resolved name. */
static int
dq_tree_ident(struct dq_tree *t, const struct dq_tree_res *res,
    struct dq_ident_file *ident)
{
	struct statfs sfs;
	int fd, error;

	fd = openat(t->t_rootfd, res->tr_rel, O_PATH | O_NOFOLLOW | DQ_TREE_O);
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
dq_tree_add(struct dq_tree *t, uint64_t id, int fd, uint32_t kind,
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
	o->to_kind = kind;
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
 * kept in the table under the id the kernel returned.  A directory's
 * backing descriptor reads its entries; a symbolic link's is O_PATH and
 * the answer carries its target.
 */
static int
dq_tree_reply_fd(struct dq_tree *t, uint64_t evid, const struct dq_tree_res *res,
    bool write, uint32_t mflags)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	char tgt[PATH_MAX];
	uint64_t id;
	ssize_t n;
	uint32_t kind;
	int fd, error;

	kind = S_ISDIR(res->tr_st.st_mode) ? DQ_KIND_DIR :
	    S_ISLNK(res->tr_st.st_mode) ? DQ_KIND_SYMLINK : DQ_KIND_FILE;
	if (kind == DQ_KIND_DIR)
		fd = openat(t->t_rootfd, res->tr_rel, O_RDONLY | O_DIRECTORY |
		    O_NOFOLLOW | DQ_TREE_O);
	else if (kind == DQ_KIND_SYMLINK) {
		fd = openat(t->t_rootfd, res->tr_rel, O_PATH | O_NOFOLLOW |
		    DQ_TREE_O);
		n = fd < 0 ? -1 : readlinkat(fd, "", tgt, sizeof(tgt) - 1);
		if (n <= 0) {
			error = n < 0 ? errno : EINVAL;
			if (fd >= 0)
				close(fd);
			return (dq_reply_resolve_errno(t->t_q, evid, error));
		}
		tgt[n] = '\0';
	} else {
		fd = openat(t->t_rootfd, res->tr_rel,
		    (write ? O_RDWR : O_RDONLY) | O_NOFOLLOW | DQ_TREE_O);
		if (fd < 0 && !write)
			fd = openat(t->t_rootfd, res->tr_rel, O_RESOLVE_BENEATH |
			    O_PATH |
			    O_NOFOLLOW | O_CLOEXEC);
	}
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
	if (kind == DQ_KIND_FILE)
		dq_policy_default(&pol);
	else
		dq_policy_default_dir(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if ((t->t_flags & DQ_TREE_F_WRITE) != 0 && write &&
	    kind == DQ_KIND_FILE) {
		pol.dp_write = DQ_EVENT;
		mflags |= DQ_MINT_F_WRITE;
	}
	id = 0;
	if ((kind == DQ_KIND_SYMLINK ?
	    dq_reply_resolve_fd_symlink(t->t_q, evid, ident, &pol, tgt, &id,
	    NULL) :
	    dq_reply_resolve_fd(t->t_q, evid, kind, mflags, ident, &pol, &id,
	    NULL)) != 0) {
		error = errno;
		free(ident);
		close(fd);
		/* Never leave the event in flight: the requester gets EIO. */
		if (error == ESRCH)
			return (0);
		return (dq_reply_resolve_errno(t->t_q, evid, EIO));
	}
	if (dq_tree_add(t, id, fd, kind, ident) != 0)
		close(fd);	/* its CLOSE finds nothing */
	free(ident);
	return (0);
}

/*
 * The real path of a normalized name (iii-b): under the prefix, the
 * backing node's (rootfd's real path and the backing path); outside it,
 * the name itself, which is a real-namespace name.
 */
static int
dq_tree_realpath(const struct dq_tree *t, const char *norm, char *out,
    size_t outlen)
{
	const char *below;
	char tmp[PATH_MAX * 2];

	below = dq_tree_below(t, norm);
	if (below == NULL)
		return (strlcpy(out, norm, outlen) >= outlen ? ENAMETOOLONG : 0);
	if (t->t_realroot[0] == '\0')
		return (EIO);
	snprintf(tmp, sizeof(tmp), "%s/%s", t->t_realroot, below);
	return (dq_tree_normalize(tmp, out, outlen));
}

/*
 * What a name the tree does not serve gets (iii-b): PASS when the event
 * takes it (a real start), else REAL of the real path when it takes that,
 * else the errno (ENOTCAPABLE for a restricted lookup, where the real
 * namespace cannot be reached).
 */
static int
dq_tree_unserved(struct dq_tree *t, uint64_t evid,
    const struct dq_resolve_body *rb, const char *norm, int error)
{
	char real[PATH_MAX];

	if (dq_resolve_accepts(rb, DQ_RESOLVE_PASS))
		return (dq_reply_resolve_pass(t->t_q, evid));
	if (norm != NULL && dq_resolve_accepts(rb, DQ_RESOLVE_REAL) &&
	    dq_tree_realpath(t, norm, real, sizeof(real)) == 0)
		return (dq_reply_resolve_real(t->t_q, evid, real));
	if ((rb->drs_rflags & (DQ_RF_STRICTREL | DQ_RF_BENEATH |
	    DQ_RF_RINROOT)) != 0)
		error = ENOTCAPABLE;
	if (error <= 0 || !dq_resolve_errno_allowed_ev(rb, error))
		error = EIO;
	return (dq_reply_resolve_errno(t->t_q, evid, error));
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
	const char *name, *name2;
	int dfd, dfd2, error, r;

	/* Each name through its confined parent directory (round 3). */
	error = dq_tree_parent(t, res->tr_rel, &dfd, &name);
	if (error != 0)
		return (error);
	dfd2 = -1;
	name2 = NULL;
	if (rb->drs_op == DQ_ROP_RENAME || rb->drs_op == DQ_ROP_LINK) {
		error = dq_tree_parent(t, res2->tr_rel, &dfd2, &name2);
		if (error != 0) {
			close(dfd);
			return (error);
		}
	}
	switch (rb->drs_op) {
	case DQ_ROP_MKDIR:
		r = mkdirat(dfd, name, rb->drs_cmode);
		break;
	case DQ_ROP_MKFIFO:
		r = mkfifoat(dfd, name, rb->drs_cmode);
		break;
	case DQ_ROP_MKNOD:
		r = mknodat(dfd, name, (rb->drs_mode & S_IFMT) | rb->drs_cmode,
		    (dev_t)rb->drs_dev);
		break;
	case DQ_ROP_UNLINK:
		r = unlinkat(dfd, name, 0);
		break;
	case DQ_ROP_RMDIR:
		r = unlinkat(dfd, name, AT_REMOVEDIR);
		break;
	case DQ_ROP_SYMLINK:
		r = symlinkat(path2, dfd, name);
		break;
	case DQ_ROP_RENAME:
		/* drs_mode holds renameat2's flags (AT_RENAME_NOREPLACE). */
		r = renameat2(dfd, name, dfd2, name2, rb->drs_mode);
		break;
	case DQ_ROP_LINK:
		r = linkat(dfd, name, dfd2, name2, 0);
		break;
	default:
		r = -1;
		errno = EIO;
		break;
	}
	error = r != 0 ? errno : 0;
	close(dfd);
	if (dfd2 >= 0)
		close(dfd2);
	return (error);
}

/* REAL of a name's real path when the event takes it, else unserved. */
static int
dq_tree_real(struct dq_tree *t, uint64_t evid,
    const struct dq_resolve_body *rb, const char *norm)
{
	char real[PATH_MAX];

	if (norm != NULL && norm[0] != '\0' &&
	    dq_resolve_accepts(rb, DQ_RESOLVE_REAL) &&
	    dq_tree_realpath(t, norm, real, sizeof(real)) == 0)
		return (dq_reply_resolve_real(t->t_q, evid, real));
	return (dq_tree_unserved(t, evid, rb, norm, EACCES));
}

/*
 * The process's served root relative to the tree, from the event (D184):
 * 0 and rootv when the root is one of the tree's directories; ENOENT when
 * the root is real or the tree is not served as a root; EIO for a root
 * outside the tree (never walked from the real "/").
 */
static int
dq_tree_rootv(struct dq_tree *t, const struct dq_event *ev,
    char *rootv, size_t len)
{
	const struct dq_resolve_body *rb;
	const char *rp, *v;
	uint64_t root;

	if ((t->t_flags & DQ_TREE_F_ROOT) == 0 ||
	    dq_event_resolve_root(ev, &rb, &root, &rp) != 0 || root == 0)
		return (ENOENT);
	if (dq_tree_find(t, root, NULL) == NULL ||
	    (v = dq_tree_vname(t, rp)) == NULL)
		return (EIO);
	strlcpy(rootv, v, len);
	return (0);
}

/*
 * A served start's hint must be that object's own presented path (D184):
 * a missing or different one is EIO, never a walk from "/".
 */
static bool
dq_tree_start_ok(struct dq_tree *t, uint32_t kind, uint64_t start,
    bool valid, const char *hint)
{
	struct dq_tree_obj *o;

	if (kind != DQ_START_SERVED)
		return (true);
	o = dq_tree_find(t, start, NULL);
	return (o != NULL && valid && strcmp(o->to_ident.di_path, hint) == 0);
}

/*
 * A name outside the tree from a real start, under the tree as root
 * (D184): EACCES unless DQ_TREE_F_OUTSIDE_PASS lets it through as an
 * unserved name (PASS from a real start).
 */
static int
dq_tree_outside(struct dq_tree *t, uint64_t evid,
    const struct dq_resolve_body *rb, const char *norm, int error)
{

	if ((t->t_flags & (DQ_TREE_F_ROOT | DQ_TREE_F_OUTSIDE_PASS)) ==
	    DQ_TREE_F_ROOT && rb->drs_start_kind != DQ_START_SERVED)
		return (dq_tree_errno(t, evid, rb, EACCES));
	return (dq_tree_unserved(t, evid, rb, norm, error));
}

/* EXEC_INTERP at the served root: the backing interpreter (iii-c). */
static int
dq_tree_interp(struct dq_tree *t, uint64_t evid,
    const struct dq_resolve_body *rb, const char *path, const char *sp,
    bool spvalid, const char *rootv)
{
	struct dq_tree_res *res;
	bool mine;
	int error, ret;

	res = calloc(1, sizeof(*res));
	if (res == NULL)
		return (dq_reply_resolve_errno(t->t_q, evid, EIO));
	error = dq_tree_lookup(t, path, sp, spvalid, true, 0,
	    rootv != NULL ? rootv : "/", res, &mine);
	if (error == 0 && (!mine || !res->tr_exists))
		error = ENOENT;
	if (error == 0)
		ret = dq_tree_real(t, evid, rb, res->tr_name);
	else
		ret = dq_tree_errno(t, evid, rb, error);
	free(res);
	return (ret);
}

static int
dq_tree_resolve(struct dq_tree *t, const struct dq_event *ev)
{
	const struct dq_resolve_body *rb;
	const struct dq_setattr_body *sb;
	const char *path, *path2, *sp, *sp2;
	const char *norm;
	struct dq_tree_res *res, *res2;
	struct dq_ident_file *ident;
	char tgt[PATH_MAX];
	uint32_t want, mflags, rf2;
	ssize_t n;
	int error, fd, ret, flags;
	char rootv[PATH_MAX];
	bool follow, mine, mine2, served, writable;

	if (dq_event_resolve_ext(ev, &rb, &path, &path2, &sp, &sp2, &sb) != 0)
		return (dq_reply_resolve_errno(t->t_q, ev->de_id, EIO));
	error = dq_tree_rootv(t, ev, rootv, sizeof(rootv));
	if (error == EIO)
		return (dq_tree_errno(t, ev->de_id, rb, EIO));
	if (error != 0)
		rootv[0] = '\0';
	if (!dq_tree_start_ok(t, rb->drs_start_kind, rb->drs_start,
	    (rb->drs_rflags & DQ_RF_STARTPATH_VALID) != 0, sp) ||
	    !dq_tree_start_ok(t, rb->drs_start2_kind, rb->drs_start2,
	    (rb->drs_rflags & DQ_RF_STARTPATH2_VALID) != 0, sp2))
		return (dq_tree_errno(t, ev->de_id, rb, EIO));
	/*
	 * The exec interpreter at the served root (iii-c, D175): REAL of the
	 * tree's own interpreter, so it comes from the tree.
	 */
	if (rb->drs_op == DQ_ROP_EXEC_INTERP &&
	    rb->drs_start_kind == DQ_START_SERVED &&
	    (t->t_flags & DQ_TREE_F_ROOT) != 0 &&
	    dq_tree_find(t, rb->drs_start, NULL) != NULL)
		return (dq_tree_interp(t, ev->de_id, rb, path, sp,
		    (rb->drs_rflags & DQ_RF_STARTPATH_VALID) != 0,
		    rootv[0] != '\0' ? rootv : NULL));
	/*
	 * The kernel's own lookups and every non-path consultation.  A
	 * served start (iii-b) must be one of this tree's directories; its
	 * hint is that directory's presented path.  A symlink
	 * re-consultation of a relative target starts at the link's
	 * directory (REAL_SYMDIR), whose real path is the hint.
	 */
	if (rb->drs_flags != DQ_RCLASS_USER ||
	    (rb->drs_start_kind != DQ_START_REAL_ROOT &&
	    rb->drs_start_kind != DQ_START_REAL_CWD &&
	    rb->drs_start_kind != DQ_START_REAL_DIRFD &&
	    rb->drs_start_kind != DQ_START_REAL_SYMDIR &&
	    rb->drs_start_kind != DQ_START_SERVED))
		return (dq_tree_unserved(t, ev->de_id, rb, NULL, EACCES));
	if (rb->drs_start_kind == DQ_START_SERVED &&
	    dq_tree_find(t, rb->drs_start, NULL) == NULL)
		return (dq_tree_errno(t, ev->de_id, rb, EIO));
	res = calloc(2, sizeof(*res));
	ident = malloc(sizeof(*ident));
	if (res == NULL || ident == NULL) {
		free(res);
		free(ident);
		return (dq_reply_resolve_errno(t->t_q, ev->de_id, EIO));
	}
	res2 = &res[1];
	/*
	 * Resolve the path(s) as namei would, through the backing tree
	 * inside the prefix (round 2: no lexical "..").
	 */
	follow = (rb->drs_rflags & DQ_RF_NOFOLLOW) == 0 ||
	    (rb->drs_rflags & DQ_RF_TRAILINGSLASH) != 0;
	mine2 = false;
	/*
	 * A restricted real lookup takes PASS only: the kernel's own walk
	 * holds it inside its start (no walk here).
	 */
	if (dq_resolve_accepts(rb, DQ_RESOLVE_PASS) &&
	    (rb->drs_accept & ~DQ_RACCEPT(DQ_RESOLVE_PASS)) == 0) {
		ret = dq_tree_outside(t, ev->de_id, rb, NULL, EACCES);
		goto out;
	}
	/* Each path under its own restrictions (round 3). */
	rf2 = ((rb->drs_rflags & DQ_RF_STRICTREL2) != 0 ? DQ_RF_STRICTREL :
	    0) | ((rb->drs_rflags & DQ_RF_BENEATH2) != 0 ? DQ_RF_BENEATH : 0);
	error = dq_tree_lookup(t, path, sp,
	    (rb->drs_rflags & DQ_RF_STARTPATH_VALID) != 0, follow,
	    rb->drs_rflags & (DQ_RF_STRICTREL | DQ_RF_BENEATH | DQ_RF_RINROOT),
	    rootv[0] != '\0' && rb->drs_start_kind == DQ_START_SERVED ?
	    rootv : NULL, res, &mine);
	if (error == 0 && (rb->drs_op == DQ_ROP_RENAME ||
	    rb->drs_op == DQ_ROP_LINK) && path2[0] != '\0')
		error = dq_tree_lookup(t, path2, sp2,
		    (rb->drs_rflags & DQ_RF_STARTPATH2_VALID) != 0, false, rf2,
		    rootv[0] != '\0' && rb->drs_start2_kind == DQ_START_SERVED ?
		    rootv : NULL, res2, &mine2);
	if (error != 0) {
		ret = dq_tree_errno(t, ev->de_id, rb, error);
		goto out;
	}
	norm = res->tr_name[0] != '\0' ? res->tr_name : NULL;
	if (rb->drs_op == DQ_ROP_RENAME || rb->drs_op == DQ_ROP_LINK) {
		if (!mine && !mine2) {
			ret = dq_tree_outside(t, ev->de_id, rb, NULL, EXDEV);
			goto out;
		}
		if (mine != mine2) {
			ret = dq_tree_errno(t, ev->de_id, rb, EXDEV);
			goto out;
		}
	} else if (!mine) {
		ret = dq_tree_outside(t, ev->de_id, rb, norm, EACCES);
		goto out;
	}

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
		/* DQ_TREE_F_EXEC_REAL: the backing binary runs (D167). */
		if ((t->t_flags & DQ_TREE_F_EXEC_REAL) != 0 &&
		    dq_resolve_accepts(rb, DQ_RESOLVE_REAL))
			ret = dq_tree_real(t, ev->de_id, rb, norm);
		else
			ret = dq_tree_errno(t, ev->de_id, rb, EACCES);
		goto out;
	case DQ_ROP_XATTR:
	case DQ_ROP_ACL:
		ret = dq_tree_errno(t, ev->de_id, rb, EOPNOTSUPP);
		goto out;
	case DQ_ROP_CHDIR:
	case DQ_ROP_CHROOT:
		/* A served directory becomes the cwd or root (iii-c). */
		if ((t->t_flags & DQ_TREE_F_SERVED) == 0 ||
		    !dq_resolve_accepts(rb, DQ_RESOLVE_FD)) {
			ret = dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
			goto out;
		}
		if (!res->tr_exists)
			ret = dq_tree_errno(t, ev->de_id, rb, ENOENT);
		else if (!S_ISDIR(res->tr_st.st_mode))
			ret = dq_tree_errno(t, ev->de_id, rb, ENOTDIR);
		else
			ret = dq_tree_reply_fd(t, ev->de_id, res, false, 0);
		goto out;
	case DQ_ROP_CONNECT:
	case DQ_ROP_BIND:
		/* A socket node is the backing one (iii-b). */
		if ((t->t_flags & DQ_TREE_F_SERVED) != 0)
			ret = dq_tree_real(t, ev->de_id, rb, norm);
		else
			ret = dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
		goto out;
	default:
		ret = dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
		goto out;
	}
	/* A restricted real lookup takes PASS only: the real namespace. */
	if (!dq_resolve_accepts(rb, want)) {
		ret = dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
		goto out;
	}
	writable = (t->t_flags & DQ_TREE_F_WRITE) != 0;

	served = (t->t_flags & DQ_TREE_F_SERVED) != 0;
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
			    O_WRONLY | DQ_TREE_O, rb->drs_cmode);
			if (fd < 0) {
				error = errno;
				break;
			}
			close(fd);
			if (fstatat(t->t_rootfd, res->tr_rel, &res->tr_st,
			    AT_SYMLINK_NOFOLLOW | DQ_TREE_AT) != 0) {
				error = errno;
				break;
			}
			res->tr_exists = true;
			mflags |= DQ_MINT_F_CREATED;
		}
		if (served && S_ISDIR(res->tr_st.st_mode)) {
			/* A served directory; the kernel applies EISDIR. */
			ret = dq_tree_reply_fd(t, ev->de_id, res, false, 0);
			goto out;
		}
		if (served && S_ISLNK(res->tr_st.st_mode)) {
			/* A final symlink, not followed: O_PATH only. */
			if ((flags & O_PATH) == 0) {
				error = EMLINK;
				break;
			}
			ret = dq_tree_reply_fd(t, ev->de_id, res, false, 0);
			goto out;
		}
		if (!S_ISREG(res->tr_st.st_mode)) {
			/* A device, FIFO or socket: the backing node. */
			ret = served ? dq_tree_real(t, ev->de_id, rb, norm) :
			    dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
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
		if (served && rb->drs_op == DQ_ROP_TRUNCATE &&
		    S_ISDIR(res->tr_st.st_mode)) {
			error = EISDIR;
			break;
		}
		if (!S_ISREG(res->tr_st.st_mode) && !(served &&
		    (S_ISDIR(res->tr_st.st_mode) ||
		    S_ISLNK(res->tr_st.st_mode)))) {
			ret = served ? dq_tree_real(t, ev->de_id, rb, norm) :
			    dq_tree_unserved(t, ev->de_id, rb, norm, EACCES);
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
		n = dq_tree_readlink(t, res->tr_rel, tgt, sizeof(tgt) - 1);
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
	struct kinfo_file kif;
	struct dq_tree *t;

	if (prefix == NULL || prefix[0] != '/' ||
	    (flags & ~(DQ_TREE_F_WRITE | DQ_TREE_F_SERVED |
	    DQ_TREE_F_EXEC_REAL | DQ_TREE_F_ROOT |
	    DQ_TREE_F_OUTSIDE_PASS)) != 0 ||
	    ((flags & DQ_TREE_F_ROOT) != 0 &&
	    (flags & DQ_TREE_F_SERVED) == 0)) {
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
	/* The backing tree's real path, for REAL answers (iii-b). */
	kif.kf_structsize = sizeof(kif);
	if (fcntl(rootfd, F_KINFO, &kif) == 0 && kif.kf_path[0] == '/' &&
	    dq_tree_normalize(kif.kf_path, t->t_realroot,
	    sizeof(t->t_realroot)) != 0)
		t->t_realroot[0] = '\0';
	return (t);
}

/*
 * iii-b: mint the tree's root as a served directory presented at the
 * prefix, owned by the tree (its backing descriptor reads the entries).
 * The returned descriptor is the controller's; an attached child that
 * inherits it starts lookups there.
 */
int
dq_tree_root(struct dq_tree *t, int *fdp, uint64_t *objectp)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	uint64_t id;
	int bfd, error, fd;

	if ((t->t_flags & DQ_TREE_F_SERVED) == 0) {
		errno = EINVAL;
		return (-1);
	}
	ident = malloc(sizeof(*ident));
	if (ident == NULL)
		return (-1);
	bfd = openat(t->t_rootfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (bfd < 0 || dq_ident_from_lstat(ident, t->t_prefix, t->t_rootfd,
	    ".") != 0) {
		error = errno;
		goto fail;
	}
	/* The presented mount is "/": a prefix of every name. */
	strlcpy(ident->di_statfs.ds_mntonname, "/",
	    sizeof(ident->di_statfs.ds_mntonname));
	dq_policy_default_dir(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if (dq_mint_dir(t->t_q, ident, &pol, &id, &fd, NULL) != 0 ||
	    dq_tree_add(t, id, bfd, DQ_KIND_DIR, ident) != 0) {
		error = errno;
		goto fail;
	}
	free(ident);
	*fdp = fd;
	if (objectp != NULL)
		*objectp = id;
	return (0);
fail:
	if (bfd >= 0)
		close(bfd);
	free(ident);
	errno = error;
	return (-1);
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
