/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * A supervisor that restricts itself after it opened the queue (dq(4),
 * "The substituted file and the restricted Capability Broker"): it
 * gives up root, enters a jail, enters capability mode, or all three,
 * and keeps serving, SWAP included.  A swapped file is handed over as it
 * is, with the credential of the open that made it, so what a restricted
 * supervisor can hand over is what it can still open.
 *
 * Three processes per scene:
 *   T  the ATF test process: files, jails, every check;
 *   S  the supervisor, a fork() child of T.  S opens its own queue (a
 *      queue is not inherited across fork), creates P, attaches it,
 *      restricts itself, serves, and writes one struct cf_res to T;
 *   P  the program, a pdfork() child of S, attached while it waits.  It
 *      opens t0, t1, ... in its working directory and reports to S.
 * S and P never call ATF or the dqt_* harness: they record what happened
 * and _exit.
 *
 * Rows U-root and J7 pin kept behaviour (a root supervisor's file keeps
 * set-ID bits on write; a descriptor opened before the jail entry is
 * still handed over); J0 pins jail_attach's open-directory refusal.  A
 * later opt-in credential check would change U-root only when asked for.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	CF_NROW		12
#define	CF_UID_S	65533		/* the supervisor after its drop */
#define	CF_UID_P	65534		/* the program (nobody) */
#define	CF_BUFSIZE	(256 * 1024)
#define	CF_JAIL_A	"dq_cf_a"
#define	CF_JAIL_B	"dq_cf_b"
#define	CF_PROXY	"proxy\n"

struct cf_row {			/* one row: what S saw and what P saw */
	int32_t		s_open_rv;	/* S's own open/openat: fd or -1 */
	int32_t		s_open_errno;
	int32_t		s_reply_rv;	/* the reply call: 0 or -1 */
	int32_t		s_reply_errno;
	uint32_t	s_accept;	/* drs_accept of the event */
	int32_t		p_open_rv;	/* P's open: >= 0 or -1 */
	int32_t		p_open_errno;
	int32_t		p_op_rv;	/* P's extra operation, per row */
	int32_t		p_op_errno;
	uint64_t	p_ino;		/* fstat of P's descriptor */
	uint32_t	p_mode;		/* st_mode & 07777, after the extra op */
	uint32_t	p_uid;		/* st_uid */
	char		p_data[32];	/* first bytes P read, NUL padded */
};

struct cf_res {
	int32_t		setup_rv[8];	/* S's setup steps, in order: 0 or -1 */
	int32_t		setup_errno[8];
	int32_t		extra_rv[8];	/* per-scene extra calls of S */
	int32_t		extra_errno[8];
	int32_t		p_status;	/* P's wait status */
	uint32_t	nrows;
	struct cf_row	row[CF_NROW];
};

/* setup_rv[] slots, the same in every scene. */
enum {
	CF_S_OPEN, CF_S_PDFORK, CF_S_ATTACH, CF_S_JAIL, CF_S_DROP, CF_S_DIRS,
	CF_S_CAPENTER, CF_S_READ
};

/* The scenes; each is one run of S. */
enum cf_kind {
	CF_UID,		/* restricted_uid: S drops to CF_UID_S */
	CF_UID_ROOT,	/* restricted_uid, row U-root: S keeps root */
	CF_JAIL,	/* restricted_jail: S enters jail A */
	CF_JAIL_B6,	/* restricted_jail, row J6: P in jail B, S in jail A */
	CF_CAPMODE,	/* restricted_capmode: S root in capability mode */
	CF_ALL		/* restricted_all: jail A, CF_UID_S, capability mode */
};

/* What P does with each name, after its open. */
enum cf_op {
	CF_OP_NONE,	/* the open only */
	CF_OP_READ,	/* read into p_data, fstat */
	CF_OP_WRITE,	/* write one byte (p_op), fstat */
	CF_OP_OPENAT,	/* openat(fd, arg, O_RDONLY) (p_op), fstat */
	CF_OP_OPENAT_PREV, /* no open: openat(previous row's fd, arg) */
	CF_OP_CAPS	/* read, fchmod (p_op), rights equal CF_LIMRIGHTS (p_mode) */
};

struct cf_prow {
	int		flags;		/* 0 and op NONE: no row */
	enum cf_op	op;
	const char	*arg;
};

struct cf_scene {
	enum cf_kind	kind;
	char		cwd[PATH_MAX];
	int		jid_a;
	int		jid_b;
	struct cf_prow	prow[CF_NROW];
	uint32_t	nrows;
};

/* What P sends back to S: the P half of each row. */
struct cf_pres {
	int32_t		open_rv, open_errno, op_rv, op_errno;
	uint64_t	ino;
	uint32_t	mode, uid;
	char		data[32];
};

/* S's state while it serves. */
struct cf_srv {
	const struct cf_scene *sc;
	struct cf_res	*res;
	int		q;
	int		dfull;		/* directory descriptors, or -1 */
	int		dlim;
	int		prefd;		/* J7: opened before the jail entry */
	bool		got_events;
	bool		seen[CF_NROW];
	char		*buf;
};

#define	CF_RR(rv, err, call) do {					\
	errno = 0;							\
	(rv) = (int32_t)(call);						\
	(err) = (rv) == -1 ? errno : 0;					\
} while (0)

static void
cf_limrights(cap_rights_t *r)
{

	cap_rights_init(r, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_SEEK);
}

/* setgroups, setgid, setuid to uid (the gid has the uid's number). */
static int
cf_drop(uid_t uid)
{
	gid_t gid;

	gid = (gid_t)uid;
	if (setgroups(1, &gid) == -1 || setgid(gid) == -1 ||
	    setuid(uid) == -1)
		return (-1);
	if (getuid() != uid || geteuid() != uid || getgid() != gid ||
	    getegid() != gid) {
		errno = EPERM;
		return (-1);
	}
	return (0);
}

static bool
cf_name_is(const char *path, int k)
{
	char name[8];
	size_t nl, pl;

	snprintf(name, sizeof(name), "t%d", k);
	nl = strlen(name);
	pl = strlen(path);
	return (pl >= nl && strcmp(path + pl - nl, name) == 0 &&
	    (pl == nl || path[pl - nl - 1] == '/'));
}

/*
 * P: open each name, act on it, report.  Every descriptor stays open
 * until P exits (row J6 acts on the previous row's).
 */
static void __dead2
cf_program(const struct cf_scene *sc, int readyw, int gor, int resw)
{
	struct cf_pres pr[CF_NROW];
	const struct cf_prow *r;
	struct cf_pres *o;
	cap_rights_t want, got;
	struct stat st;
	char name[8], b;
	int fd, fds[CF_NROW], k, x;

	memset(pr, 0, sizeof(pr));
	if (sc->kind == CF_JAIL_B6 && jail_attach(sc->jid_b) == -1)
		_exit(120);
	if ((sc->kind == CF_UID || sc->kind == CF_UID_ROOT ||
	    sc->kind == CF_ALL) && cf_drop(CF_UID_P) == -1)
		_exit(121);
	b = 'r';
	if (write(readyw, &b, 1) != 1 || read(gor, &b, 1) != 1)
		_exit(122);
	for (k = 0; k < CF_NROW; k++)
		fds[k] = -1;
	for (k = 0; k < (int)sc->nrows; k++) {
		r = &sc->prow[k];
		o = &pr[k];
		if (r->op == CF_OP_OPENAT_PREV) {
			fd = k > 0 ? fds[k - 1] : -1;
			o->open_rv = fd;
		} else {
			snprintf(name, sizeof(name), "t%d", k);
			CF_RR(o->open_rv, o->open_errno,
			    fd = open(name, r->flags | O_CLOEXEC));
			fds[k] = fd;
		}
		if (fd == -1)
			continue;
		switch (r->op) {
		case CF_OP_NONE:
			break;
		case CF_OP_READ:
		case CF_OP_CAPS:
			CF_RR(o->op_rv, o->op_errno,
			    read(fd, o->data, sizeof(o->data) - 1));
			break;
		case CF_OP_WRITE:
			CF_RR(o->op_rv, o->op_errno, write(fd, "y", 1));
			break;
		case CF_OP_OPENAT:
		case CF_OP_OPENAT_PREV:
			CF_RR(o->op_rv, o->op_errno,
			    x = openat(fd, r->arg, O_RDONLY | O_CLOEXEC));
			if (x != -1)
				(void)close(x);
			break;
		}
		if (fstat(fd, &st) == 0) {
			o->ino = st.st_ino;
			o->mode = st.st_mode & 07777;
			o->uid = st.st_uid;
		}
		if (r->op == CF_OP_CAPS) {
			/* The read is the data; the operation is fchmod. */
			CF_RR(o->op_rv, o->op_errno, fchmod(fd, 0644));
			cf_limrights(&want);
			o->mode = cap_rights_get(fd, &got) == 0 &&
			    cap_rights_contains(&got, &want) &&
			    cap_rights_contains(&want, &got) ? 1 : 0;
		}
	}
	if (write(resw, pr, sizeof(pr)) != (ssize_t)sizeof(pr))
		_exit(123);
	_exit(0);
}

/* A file descriptor answer whose READs come from S's memory. */
static void
cf_answer_proxy(struct cf_srv *s, uint64_t id, int fd, const char *path,
    struct cf_row *row)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	uint64_t object;
	int32_t reason;

	ident = calloc(1, sizeof(*ident));
	if (ident == NULL || fstat(fd, &st) == -1 ||
	    fstatfs(fd, &sfs) == -1 ||
	    dq_ident_from_stat(ident, path, &st, &sfs, fd) == -1) {
		row->s_reply_rv = -1;
		row->s_reply_errno = errno != 0 ? errno : EIO;
		(void)dq_reply_resolve_errno(s->q, id, EIO);
		free(ident);
		return;
	}
	ident->di_size = sizeof(CF_PROXY) - 1;
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	reason = 0;
	CF_RR(row->s_reply_rv, row->s_reply_errno,
	    dq_reply_resolve_fd(s->q, id, DQ_KIND_FILE, 0, ident, &pol,
	    &object, &reason));
	free(ident);
}

/* Swap fd (S's own descriptor) and close it, as dq(4) asks. */
static void
cf_answer_swap(struct cf_srv *s, uint64_t id, int fd, struct cf_row *row)
{

	CF_RR(row->s_reply_rv, row->s_reply_errno,
	    dq_reply_resolve_swap(s->q, id, fd, 0));
	if (row->s_reply_rv != 0 && row->s_reply_errno != ESRCH)
		(void)dq_reply_resolve_errno(s->q, id, EIO);
	(void)close(fd);
}

/*
 * S's own open for row k failed or succeeded: answer with the swap, or
 * with its errno (EACCES for one an open may not return).
 */
static void
cf_answer_open(struct cf_srv *s, uint64_t id, const struct dq_resolve_body *rb,
    int fd, struct cf_row *row)
{
	int error;

	row->s_open_rv = fd;
	row->s_open_errno = fd == -1 ? errno : 0;
	if (fd != -1) {
		cf_answer_swap(s, id, fd, row);
		return;
	}
	error = row->s_open_errno;
	if (!dq_resolve_errno_allowed_ev(rb, error))
		error = EACCES;
	CF_RR(row->s_reply_rv, row->s_reply_errno,
	    dq_reply_resolve_errno(s->q, id, error));
}

static void
cf_answer_rv(struct cf_row *row, int rv)
{

	row->s_reply_rv = rv;
	row->s_reply_errno = rv == -1 ? errno : 0;
}

#define	CF_SO	(O_CLOEXEC | O_CLOFORK)

/* Row k of the scene: S's answer. */
static void
cf_answer(struct cf_srv *s, int k, uint64_t id,
    const struct dq_resolve_body *rb)
{
	struct cf_row *row;
	struct cf_res *res;
	char path[PATH_MAX];
	int fd, x;

	res = s->res;
	row = &res->row[k];
	row->s_accept = rb->drs_accept;
	switch (s->sc->kind) {
	case CF_UID:
		switch (k) {
		case 0:		/* U1 */
			cf_answer_rv(row, dq_reply_resolve_pass(s->q, id));
			return;
		case 1:		/* U2 */
			cf_answer_rv(row,
			    dq_reply_resolve_errno(s->q, id, EPERM));
			return;
		case 2:		/* U3 */
			cf_answer_open(s, id, rb, open("pub", O_RDONLY | CF_SO),
			    row);
			return;
		case 3:		/* U4 */
			fd = open("pub", O_RDONLY | O_CLOEXEC);
			row->s_open_rv = fd;
			row->s_open_errno = fd == -1 ? errno : 0;
			if (fd == -1) {
				(void)dq_reply_resolve_errno(s->q, id, EIO);
				return;
			}
			snprintf(path, sizeof(path), "%s/pub", s->sc->cwd);
			cf_answer_proxy(s, id, fd, path, row);
			(void)close(fd);
			return;
		case 4:		/* U5 */
			cf_answer_open(s, id, rb,
			    open("suid", O_WRONLY | CF_SO), row);
			return;
		case 5:		/* U6 */
			cf_answer_open(s, id, rb,
			    open("priv", O_RDONLY | CF_SO), row);
			return;
		}
		break;
	case CF_UID_ROOT:
		if (k == 0) {	/* U-root: row U5 with a root supervisor */
			cf_answer_open(s, id, rb,
			    open("suid", O_WRONLY | CF_SO), row);
			return;
		}
		break;
	case CF_JAIL:
		switch (k) {
		case 0:		/* J3 */
			cf_answer_open(s, id, rb,
			    open("/in/ok", O_RDONLY | CF_SO), row);
			return;
		case 1:		/* J4: the host's path, and up from the root */
			snprintf(path, sizeof(path), "%s/outside",
			    s->sc->cwd);
			CF_RR(res->extra_rv[1], res->extra_errno[1],
			    x = open("/../outside", O_RDONLY | CF_SO));
			if (x != -1)
				(void)close(x);
			cf_answer_open(s, id, rb, open(path, O_RDONLY | CF_SO),
			    row);
			return;
		case 2:		/* J5 */
			cf_answer_open(s, id, rb, open("/in/sub",
			    O_RDONLY | O_DIRECTORY | CF_SO), row);
			return;
		case 3:		/* J7 (pin) */
			row->s_open_rv = s->prefd;
			cf_answer_swap(s, id, s->prefd, row);
			s->prefd = -1;
			return;
		}
		break;
	case CF_JAIL_B6:
		if (k == 0) {	/* J6 */
			cf_answer_open(s, id, rb, open("/in",
			    O_RDONLY | O_DIRECTORY | CF_SO), row);
			return;
		}
		break;
	case CF_CAPMODE:
		switch (k) {
		case 0:		/* C2 */
			cf_answer_rv(row, dq_reply_resolve_pass(s->q, id));
			return;
		case 1:		/* C3 */
			cf_answer_rv(row,
			    dq_reply_resolve_errno(s->q, id, EPERM));
			return;
		case 2:		/* C4 */
			cf_answer_open(s, id, rb,
			    openat(s->dfull, "ok", O_RDONLY | CF_SO), row);
			return;
		case 3:		/* C5 */
			cf_answer_open(s, id, rb,
			    openat(s->dlim, "ok", O_RDONLY | CF_SO), row);
			return;
		case 4:		/* C6 */
			fd = openat(s->dfull, "ok", O_RDONLY | O_CLOEXEC);
			row->s_open_rv = fd;
			row->s_open_errno = fd == -1 ? errno : 0;
			if (fd == -1) {
				(void)dq_reply_resolve_errno(s->q, id, EIO);
				return;
			}
			snprintf(path, sizeof(path), "%s/in/ok", s->sc->cwd);
			cf_answer_proxy(s, id, fd, path, row);
			(void)close(fd);
			return;
		case 5:		/* C-out */
			CF_RR(res->extra_rv[1], res->extra_errno[1],
			    x = openat(s->dfull, "../outside", O_RDONLY |
			    CF_SO));
			if (x != -1)
				(void)close(x);
			snprintf(path, sizeof(path), "%s/outside",
			    s->sc->cwd);
			fd = open(path, O_RDONLY | CF_SO);
			row->s_open_rv = fd;
			row->s_open_errno = fd == -1 ? errno : 0;
			if (fd != -1)
				(void)close(fd);
			CF_RR(row->s_reply_rv, row->s_reply_errno,
			    dq_reply_resolve_errno(s->q, id, EACCES));
			return;
		}
		break;
	case CF_ALL:
		switch (k) {
		case 0:		/* A1 */
			cf_answer_open(s, id, rb,
			    openat(s->dfull, "ok", O_RDONLY | CF_SO), row);
			return;
		case 1:		/* A2 */
			cf_answer_open(s, id, rb,
			    openat(s->dfull, "suid", O_WRONLY | CF_SO), row);
			return;
		case 2:		/* A3 */
			cf_answer_open(s, id, rb, openat(s->dfull,
			    "../../outside", O_RDONLY | CF_SO), row);
			return;
		}
		break;
	}
	/* Not a row of this scene. */
	(void)dq_reply_resolve_errno(s->q, id, EIO);
}

static void
cf_handle(struct cf_srv *s, const struct dq_event *ev)
{
	const struct dq_resolve_body *rb;
	const void *body;
	const struct dq_read_body *rd;
	const char *path;
	size_t bodylen, n, off;
	int k;

	if (ev->de_op == DQ_OP_READ) {
		/* A READ of a proxy (rows U4, C6). */
		body = dq_event_body(ev, &bodylen);
		if (body == NULL || bodylen < sizeof(*rd)) {
			(void)dq_reply(s->q, ev->de_id, EIO, NULL, 0);
			return;
		}
		rd = body;
		off = rd->dr_offset;
		n = off >= sizeof(CF_PROXY) - 1 ? 0 :
		    sizeof(CF_PROXY) - 1 - off;
		if (n > rd->dr_len)
			n = rd->dr_len;
		(void)dq_reply(s->q, ev->de_id, 0, &CF_PROXY[off], n);
		return;
	}
	if (ev->de_op != DQ_OP_RESOLVE) {
		if (ev->de_id != 0)
			(void)dq_reply(s->q, ev->de_id, EIO, NULL, 0);
		return;
	}
	if (dq_event_resolve(ev, &rb, &path, NULL, NULL, NULL) != 0) {
		(void)dq_reply_resolve_pass(s->q, ev->de_id);
		return;
	}
	if (rb->drs_op == DQ_ROP_OPEN) {
		for (k = 0; k < (int)s->sc->nrows; k++) {
			if (!cf_name_is(path, k) || s->seen[k])
				continue;
			s->seen[k] = true;
			cf_answer(s, k, ev->de_id, rb);
			return;
		}
	}
	(void)dq_reply_resolve_pass(s->q, ev->de_id);
}

/* Serve until P has exited. */
static void
cf_serve(struct cf_srv *s, int pd)
{
	struct pollfd pfd[2];
	const struct dq_event *ev;
	ssize_t got;
	int rv;
	bool hup;

	for (hup = false; !hup;) {
		pfd[0].fd = s->q;
		pfd[0].events = POLLIN;
		pfd[1].fd = pd;
		pfd[1].events = POLLHUP;
		pfd[0].revents = pfd[1].revents = 0;
		if (poll(pfd, 2, 60000) <= 0) {
			/* P neither asked nor exited: stop it. */
			(void)pdkill(pd, SIGKILL);
			hup = true;
		} else
			hup = (pfd[1].revents & POLLHUP) != 0;
		for (;;) {
			rv = dq_read_events(s->q, s->buf, CF_BUFSIZE, &got);
			if (rv == -1 || got <= 0) {
				if (rv == -1 && errno != EAGAIN &&
				    !s->got_events) {
					s->res->setup_rv[CF_S_READ] = -1;
					s->res->setup_errno[CF_S_READ] = errno;
				}
				break;
			}
			if (!s->got_events) {
				s->got_events = true;
				s->res->setup_rv[CF_S_READ] = 0;
				s->res->setup_errno[CF_S_READ] = 0;
			}
			for (ev = dq_event_first(s->buf, (size_t)got);
			    ev != NULL;
			    ev = dq_event_next(s->buf, (size_t)got, ev))
				cf_handle(s, ev);
		}
	}
}

/*
 * A second child of S that waits, for the ATTACH rows that follow P
 * (U7, J8, C7): attach it, record the result, kill and reap it.  With
 * probe (C7), an attached child opens "ok" beneath the directory
 * descriptor it inherited; extra_rv[probe] is 1 when no event offering
 * SWAP came (none, or one without it), 0 when SWAP was offered, and
 * extra_errno[probe] the accept word seen (0 for no event).
 */
static void
cf_attach_another(struct cf_srv *s, int slot, int probe)
{
	struct pollfd pfd[2];
	const struct dq_resolve_body *rb;
	const struct dq_event *ev;
	const char *path;
	ssize_t got;
	int fd, i, pd, status, w[2];
	pid_t pid;
	char b;

	if (pipe2(w, O_CLOEXEC) == -1) {
		s->res->extra_rv[slot] = -2;
		s->res->extra_errno[slot] = errno;
		return;
	}
	pid = pdfork(&pd, PD_CLOEXEC);
	if (pid == -1) {
		s->res->extra_rv[slot] = -2;
		s->res->extra_errno[slot] = errno;
		return;
	}
	if (pid == 0) {
		(void)close(w[1]);
		if (read(w[0], &b, 1) == 1 && b == 'o') {
			fd = openat(s->dfull, "ok", O_RDONLY | O_CLOEXEC);
			_exit(fd == -1 ? 1 : 0);
		}
		_exit(0);
	}
	(void)close(w[0]);
	CF_RR(s->res->extra_rv[slot], s->res->extra_errno[slot],
	    dq_attach(s->q, pd));
	if (probe >= 0) {
		s->res->extra_rv[probe] = 1;
		s->res->extra_errno[probe] = 0;
		b = 'o';
		(void)write(w[1], &b, 1);
		/* Serve until the child exits; record its open's accept word. */
		for (i = 0; i < 100; i++) {
			pfd[0].fd = s->q;
			pfd[0].events = POLLIN;
			pfd[1].fd = pd;
			pfd[1].events = POLLHUP;
			pfd[0].revents = pfd[1].revents = 0;
			(void)poll(pfd, 2, 100);
			while (dq_read_events(s->q, s->buf, CF_BUFSIZE,
			    &got) == 0 && got > 0) {
				for (ev = dq_event_first(s->buf, (size_t)got);
				    ev != NULL; ev = dq_event_next(s->buf,
				    (size_t)got, ev)) {
					if (ev->de_op != DQ_OP_RESOLVE) {
						if (ev->de_id != 0)
							(void)dq_reply(s->q,
							    ev->de_id, EIO,
							    NULL, 0);
						continue;
					}
					if (dq_event_resolve(ev, &rb, &path,
					    NULL, NULL, NULL) == 0 &&
					    rb->drs_op == DQ_ROP_OPEN) {
						s->res->extra_errno[probe] =
						    (int32_t)rb->drs_accept;
						if ((rb->drs_accept &
						    DQ_RACCEPT(DQ_RESOLVE_SWAP))
						    != 0)
							s->res->extra_rv[probe] =
							    0;
					}
					(void)dq_reply_resolve_pass(s->q,
					    ev->de_id);
				}
			}
			if ((pfd[1].revents & POLLHUP) != 0)
				break;
		}
	}
	(void)pdkill(pd, SIGKILL);
	(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	(void)close(pd);
	(void)close(w[1]);
}

static void
cf_step(struct cf_res *res, int slot, int rv)
{

	res->setup_rv[slot] = rv == -1 ? -1 : 0;
	res->setup_errno[slot] = rv == -1 ? errno : 0;
}

/*
 * S.  Runs in a fork() child of T; writes one struct cf_res to fd 3.
 */
static void __dead2
cf_supervisor(const struct cf_scene *sc, int resfd)
{
	struct cf_res res;
	struct cf_srv s;
	struct cf_pres pr[CF_NROW];
	struct dq_stats st;
	cap_rights_t r;
	unsigned long cmds[2];
	u_int m;
	int go[2], hpd, k, pd, pres[2], ready[2], rv, status, x;
	pid_t pid;
	char b;

	if (dup2(resfd, 3) == -1)
		_exit(110);
	/* No directory descriptor inherited from the runner (jail_attach). */
	closefrom(4);
	memset(&res, 0, sizeof(res));
	memset(&s, 0, sizeof(s));
	s.sc = sc;
	s.res = &res;
	s.dfull = s.dlim = s.prefd = -1;
	res.nrows = sc->nrows;
	res.setup_rv[CF_S_READ] = -1;
	res.setup_errno[CF_S_READ] = EAGAIN;	/* no event read yet */
	hpd = -1;
	s.buf = malloc(CF_BUFSIZE);
	if (s.buf == NULL)
		_exit(111);

	CF_RR(rv, x, s.q = dq_open());
	cf_step(&res, CF_S_OPEN, rv);
	if (s.q == -1 || fcntl(s.q, F_SETFL, O_NONBLOCK) == -1)
		goto out;

	if (sc->kind == CF_JAIL) {
		/* J0 (pin): an open directory refuses the jail entry. */
		x = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		CF_RR(res.extra_rv[0], res.extra_errno[0],
		    jail_attach(sc->jid_a));
		if (x != -1)
			(void)close(x);
		/* J7: a regular file does not block the jail entry. */
		s.prefd = open("outside", O_RDONLY | CF_SO);
	}

	if (pipe2(go, O_CLOEXEC) == -1 || pipe2(ready, O_CLOEXEC) == -1 ||
	    pipe2(pres, O_CLOEXEC) == -1)
		_exit(112);
	CF_RR(rv, x, pid = pdfork(&pd, PD_CLOEXEC));
	cf_step(&res, CF_S_PDFORK, rv);
	if (pid == -1)
		goto out;
	if (pid == 0) {
		(void)close(go[1]);
		(void)close(ready[0]);
		(void)close(pres[0]);
		cf_program(sc, ready[1], go[0], pres[1]);
	}
	(void)close(go[0]);
	(void)close(ready[1]);
	(void)close(pres[1]);
	if (sc->kind == CF_JAIL) {
		/* H: on the host, root, never attached by P's setup (J9). */
		pid = pdfork(&hpd, PD_CLOEXEC);
		if (pid == 0) {
			/* Hold no end of P's pipes: P must see S close. */
			(void)close(go[1]);
			(void)close(ready[0]);
			(void)close(pres[0]);
			for (;;)
				(void)pause();
		}
	}
	if (read(ready[0], &b, 1) != 1) {
		res.setup_rv[CF_S_ATTACH] = -1;
		res.setup_errno[CF_S_ATTACH] = ECHILD;
		goto reap;
	}
	CF_RR(rv, x, dq_attach(s.q, pd));
	cf_step(&res, CF_S_ATTACH, rv);
	if (rv == -1)
		goto reap;

	/* Restriction, in the order of dq(4). */
	if (sc->kind == CF_JAIL || sc->kind == CF_JAIL_B6 ||
	    sc->kind == CF_ALL) {
		CF_RR(rv, x, jail_attach(sc->jid_a));
		cf_step(&res, CF_S_JAIL, rv);
		if (rv == -1)
			goto reap;
	}
	if (sc->kind == CF_UID || sc->kind == CF_ALL) {
		CF_RR(rv, x, cf_drop(CF_UID_S));
		cf_step(&res, CF_S_DROP, rv);
		if (rv == -1)
			goto reap;
	}
	if (sc->kind == CF_CAPMODE) {
		s.dfull = open("in", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		s.dlim = open("in", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		cf_limrights(&r);
		rv = s.dfull == -1 || s.dlim == -1 ||
		    cap_rights_limit(s.dlim, &r) == -1 ? -1 : 0;
		cf_step(&res, CF_S_DIRS, rv);
		if (rv == -1)
			goto reap;
	} else if (sc->kind == CF_ALL) {
		CF_RR(rv, x, s.dfull = open("/in",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		cf_step(&res, CF_S_DIRS, rv);
		if (rv == -1)
			goto reap;
	}
	if (sc->kind == CF_CAPMODE || sc->kind == CF_ALL) {
		CF_RR(rv, x, cap_enter());
		cf_step(&res, CF_S_CAPENTER, rv);
		if (rv == -1)
			goto reap;
		/* C1 */
		m = 0;
		CF_RR(rv, x, cap_getmode(&m));
		res.extra_rv[0] = rv == -1 ? -1 : (int32_t)m;
		res.extra_errno[0] = rv == -1 ? x : 0;
	}

	/* Release P and serve. */
	b = 'g';
	if (write(go[1], &b, 1) != 1)
		_exit(113);
	cf_serve(&s, pd);

reap:
	(void)close(go[1]);
	if (pdwait(pd, &status, WEXITED, NULL, NULL) == 0)
		res.p_status = status;
	else
		res.p_status = -1;
	memset(pr, 0, sizeof(pr));
	if (read(pres[0], pr, sizeof(pr)) == (ssize_t)sizeof(pr)) {
		for (k = 0; k < CF_NROW; k++) {
			res.row[k].p_open_rv = pr[k].open_rv;
			res.row[k].p_open_errno = pr[k].open_errno;
			res.row[k].p_op_rv = pr[k].op_rv;
			res.row[k].p_op_errno = pr[k].op_errno;
			res.row[k].p_ino = pr[k].ino;
			res.row[k].p_mode = pr[k].mode;
			res.row[k].p_uid = pr[k].uid;
			memcpy(res.row[k].p_data, pr[k].data,
			    sizeof(res.row[k].p_data));
		}
	}

	/* The extra calls, after P exited. */
	switch (sc->kind) {
	case CF_UID:
		cf_attach_another(&s, 0, -1);			/* U7 */
		CF_RR(res.extra_rv[1], res.extra_errno[1], setuid(0)); /* U8 */
		CF_RR(res.extra_rv[2], res.extra_errno[2],
		    ioctl(s.q, DQ_IOC_GET_STATS, &st));		/* U9 */
		break;
	case CF_JAIL:
		cf_attach_another(&s, 2, -1);		/* J8 */
		if (hpd != -1) {				/* J9 */
			CF_RR(res.extra_rv[3], res.extra_errno[3],
			    dq_attach(s.q, hpd));
			(void)pdkill(hpd, SIGKILL);
			(void)pdwait(hpd, &status, WEXITED, NULL, NULL);
		} else {
			res.extra_rv[3] = -2;
		}
		break;
	case CF_CAPMODE:
		cf_attach_another(&s, 2, 5);		/* C7 */
		/* C8, last: it limits the queue descriptor for good. */
		cap_rights_init(&r, CAP_READ, CAP_EVENT, CAP_IOCTL);
		cmds[0] = DQ_IOC_REPLY;
		cmds[1] = DQ_IOC_GET_STATS;
		if (cap_rights_limit(s.q, &r) == -1 ||
		    cap_ioctls_limit(s.q, cmds, nitems(cmds)) == -1) {
			res.extra_rv[3] = -2;
			res.extra_errno[3] = errno;
			break;
		}
		CF_RR(res.extra_rv[3], res.extra_errno[3],
		    ioctl(s.q, DQ_IOC_GET_STATS, &st));
		{
			struct dq_mint_args ma;

			memset(&ma, 0, sizeof(ma));
			CF_RR(res.extra_rv[4], res.extra_errno[4],
			    ioctl(s.q, DQ_IOC_MINT, &ma));
		}
		break;
	default:
		break;
	}

out:
	if (write(3, &res, sizeof(res)) != (ssize_t)sizeof(res))
		_exit(114);
	_exit(0);
}

/*
 * T: run one scene's S and collect its result.
 */
static void
cf_run(struct cf_scene *sc, struct cf_res *res)
{
	ssize_t n;
	pid_t pid;
	int p[2], status;

	ATF_REQUIRE_EQ(0, pipe2(p, O_CLOEXEC));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)close(p[0]);
		cf_supervisor(sc, p[1]);
	}
	(void)close(p[1]);
	memset(res, 0, sizeof(*res));
	n = read(p[0], res, sizeof(*res));
	(void)close(p[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the supervisor failed: status %#x", status);
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(*res), n,
	    "short result from the supervisor: %zd", n);
}

static void
cf_require_setup(const struct cf_res *res)
{
	static const char *const what[8] = { "dq_open", "pdfork",
	    "dq_attach", "jail_attach", "privilege drop", "directory opens",
	    "cap_enter", "first read of the queue after the restriction" };
	int i;

	for (i = 0; i < 8; i++)
		ATF_REQUIRE_MSG(res->setup_rv[i] == 0,
		    "supervisor setup step %d (%s): rv %d errno %d (%s)", i,
		    what[i], res->setup_rv[i], res->setup_errno[i],
		    strerror(res->setup_errno[i]));
	ATF_REQUIRE_MSG(WIFEXITED(res->p_status) &&
	    WEXITSTATUS(res->p_status) == 0, "the program failed: status %#x",
	    res->p_status);
}

#define	CF_CHECK_ERR(name, rv, err, want) ATF_CHECK_MSG((rv) == -1 &&	\
	(err) == (want), "%s: rv %d errno %d, want errno %d (%s)", name,	\
	(int)(rv), (int)(err), (want), strerror(want))
#define	CF_CHECK_OK(name, rv, err) ATF_CHECK_MSG((rv) >= 0,		\
	"%s: rv %d errno %d (%s)", name, (int)(rv), (int)(err),		\
	strerror(err))
/* The supervisor's reply call succeeded. */
#define	CF_CHECK_REPLY(name, row) CF_CHECK_OK(name " reply",		\
	(row)->s_reply_rv, (row)->s_reply_errno)
#define	CF_CHECK_SWAPPED(name, row) do {				\
	CF_CHECK_OK(name " supervisor open", (row)->s_open_rv,		\
	    (row)->s_open_errno);					\
	ATF_CHECK_MSG(((row)->s_accept & DQ_RACCEPT(DQ_RESOLVE_SWAP)) != 0, \
	    name ": SWAP was not offered (accept %#x)", (row)->s_accept); \
	CF_CHECK_REPLY(name, row);					\
	CF_CHECK_OK(name " program open", (row)->p_open_rv,		\
	    (row)->p_open_errno);					\
} while (0)

static void
cf_write_file(const char *path, const char *text, uid_t uid, mode_t mode)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(fd, text, strlen(text)));
	ATF_REQUIRE_EQ(0, fchown(fd, uid, (gid_t)uid));
	/* After the chown, which would clear set-ID bits. */
	ATF_REQUIRE_EQ(0, fchmod(fd, mode));
	ATF_REQUIRE_EQ(0, close(fd));
}

static ino_t
cf_ino(const char *path)
{
	struct stat st;

	ATF_REQUIRE_EQ_MSG(0, stat(path, &st), "%s: %s", path,
	    strerror(errno));
	return (st.st_ino);
}

static int
cf_make_jail(const char *dir, const char *name)
{
	char path[PATH_MAX];
	int jid;

	ATF_REQUIRE(realpath(dir, path) != NULL);
	jid = jail_setv(JAIL_CREATE, "path", path, "name", name, "persist",
	    NULL, NULL);
	ATF_REQUIRE_MSG(jid != -1, "jail_setv %s: %s", name, jail_errmsg);
	return (jid);
}

static void
cf_init(struct cf_scene *sc, enum cf_kind kind)
{

	dqt_require_plane();
	dqt_require_test_access();
	memset(sc, 0, sizeof(*sc));
	sc->kind = kind;
	ATF_REQUIRE(getcwd(sc->cwd, sizeof(sc->cwd)) != NULL);
	/* S and P may be other users: let them search the work directory. */
	ATF_REQUIRE_EQ(0, chmod(".", 0755));
}

static void
cf_prow(struct cf_scene *sc, int flags, enum cf_op op, const char *arg)
{

	ATF_REQUIRE(sc->nrows < CF_NROW);
	sc->prow[sc->nrows].flags = flags;
	sc->prow[sc->nrows].op = op;
	sc->prow[sc->nrows].arg = arg;
	sc->nrows++;
}

/*
 * restricted_uid: the supervisor gives up root after the ATTACH and keeps
 * serving every kind of answer; what it hands over is what it can open.
 */
ATF_TC(restricted_uid);
ATF_TC_HEAD(restricted_uid, tc)
{

	atf_tc_set_md_var(tc, "descr", "a supervisor that gave up root "
	    "serves PASS, errno, SWAP and FD answers; its swapped file has "
	    "an unprivileged credential; a root supervisor's keeps set-ID "
	    "bits (pin)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(restricted_uid, tc)
{
	struct cf_scene sc;
	struct cf_res res;
	struct statfs sfs;
	struct stat st;
	const struct cf_row *r;

	cf_init(&sc, CF_UID);
	cf_write_file("pub", "inside\n", CF_UID_S, 0644);
	cf_write_file("priv", "secret\n", 0, 0600);
	/* Others may write, so that S as CF_UID_S can open it to write. */
	cf_write_file("suid", "x\n", CF_UID_P, 04757);
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* U1 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* U2 */
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* U3 */
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* U4 */
	cf_prow(&sc, O_WRONLY, CF_OP_WRITE, NULL);	/* U5 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* U6 */
	cf_run(&sc, &res);
	cf_require_setup(&res);

	r = &res.row[0];	/* U1: PASS, the program's own lookup */
	CF_CHECK_REPLY("U1", r);
	CF_CHECK_ERR("U1 program open", r->p_open_rv, r->p_open_errno, ENOENT);
	r = &res.row[1];	/* U2 */
	CF_CHECK_REPLY("U2", r);
	CF_CHECK_ERR("U2 program open", r->p_open_rv, r->p_open_errno, EPERM);
	r = &res.row[2];	/* U3: another user's file, swapped */
	CF_CHECK_SWAPPED("U3", r);
	ATF_CHECK_STREQ("inside\n", r->p_data);
	ATF_CHECK_EQ((uint64_t)cf_ino("pub"), r->p_ino);
	ATF_CHECK_EQ((uint32_t)CF_UID_S, r->p_uid);
	r = &res.row[3];	/* U4: the mint works without privilege */
	CF_CHECK_OK("U4 supervisor open", r->s_open_rv, r->s_open_errno);
	CF_CHECK_REPLY("U4", r);
	CF_CHECK_OK("U4 program open", r->p_open_rv, r->p_open_errno);
	ATF_CHECK_STREQ(CF_PROXY, r->p_data);
	r = &res.row[4];	/* U5: the file's credential is unprivileged */
	CF_CHECK_SWAPPED("U5", r);
	ATF_CHECK_EQ_MSG(1, r->p_op_rv, "U5 write: errno %d", r->p_op_errno);
	ATF_CHECK_EQ_MSG(0757, r->p_mode, "U5: mode %#o, want 0757 (set-uid "
	    "cleared)", r->p_mode);
	r = &res.row[5];	/* U6: cannot reach */
	CF_CHECK_ERR("U6 supervisor open", r->s_open_rv, r->s_open_errno,
	    EACCES);
	CF_CHECK_REPLY("U6", r);
	CF_CHECK_ERR("U6 program open", r->p_open_rv, r->p_open_errno, EACCES);
	/* U7: an unprivileged supervisor may not debug a set-id child. */
	CF_CHECK_ERR("U7 dq_attach", res.extra_rv[0], res.extra_errno[0],
	    EPERM);
	CF_CHECK_ERR("U8 setuid(0)", res.extra_rv[1], res.extra_errno[1],
	    EPERM);
	CF_CHECK_OK("U9 DQ_IOC_GET_STATS", res.extra_rv[2],
	    res.extra_errno[2]);

	/*
	 * U-root (pin): the same row with a supervisor that kept root.  Its
	 * file has root's credential, and the program's write keeps set-uid.
	 */
	ATF_REQUIRE_EQ(0, chmod("suid", 04757));
	ATF_REQUIRE_EQ(0, stat("suid", &st));
	ATF_REQUIRE_EQ(04757, st.st_mode & 07777);
	ATF_REQUIRE_EQ(0, statfs(".", &sfs));
	printf("U-root: work directory on %s\n", sfs.f_fstypename);
	cf_init(&sc, CF_UID_ROOT);
	cf_prow(&sc, O_WRONLY, CF_OP_WRITE, NULL);	/* t0: U5 again */
	cf_run(&sc, &res);
	cf_require_setup(&res);
	r = &res.row[0];
	CF_CHECK_SWAPPED("U-root", r);
	ATF_CHECK_EQ_MSG(1, r->p_op_rv, "U-root write: errno %d",
	    r->p_op_errno);
	ATF_CHECK_EQ_MSG(04757, r->p_mode, "U-root: mode %#o, want 04757 "
	    "(set-uid kept: the file's credential is root)", r->p_mode);
}

/*
 * restricted_jail: the supervisor enters a jail after the ATTACH; it hands
 * over what is under the jail's root, and what it held from before.
 */
ATF_TC_WITH_CLEANUP(restricted_jail);
ATF_TC_HEAD(restricted_jail, tc)
{

	atf_tc_set_md_var(tc, "descr", "a supervisor in a jail serves SWAP "
	    "from under the jail's root; an open directory refuses the "
	    "jail entry (pin); a descriptor from before the entry is still "
	    "handed over (pin); ATTACH reaches only its own jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(restricted_jail, tc)
{
	struct cf_scene sc;
	struct cf_res res;
	const struct cf_row *r;
	int jid_a, jid_b;

	cf_init(&sc, CF_JAIL);
	ATF_REQUIRE_EQ(0, mkdir("ja", 0755));
	ATF_REQUIRE_EQ(0, mkdir("jb", 0755));
	ATF_REQUIRE_EQ(0, mkdir("ja/in", 0755));
	ATF_REQUIRE_EQ(0, mkdir("ja/in/sub", 0755));
	cf_write_file("ja/in/ok", "inside\n", 0, 0644);
	cf_write_file("outside", "outside\n", 0, 0644);
	jid_a = cf_make_jail("ja", CF_JAIL_A);
	jid_b = cf_make_jail("jb", CF_JAIL_B);
	sc.jid_a = jid_a;
	sc.jid_b = jid_b;
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* J3 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* J4 */
	cf_prow(&sc, O_RDONLY | O_DIRECTORY, CF_OP_OPENAT,
	    "../../../outside");			/* J5 */
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* J7 */
	cf_run(&sc, &res);
	/* J0 (pin) */
	CF_CHECK_ERR("J0 jail_attach with a directory open", res.extra_rv[0],
	    res.extra_errno[0], EPERM);
	/* J1, J2 */
	cf_require_setup(&res);

	r = &res.row[0];	/* J3 */
	CF_CHECK_SWAPPED("J3", r);
	ATF_CHECK_STREQ("inside\n", r->p_data);
	ATF_CHECK_EQ((uint64_t)cf_ino("ja/in/ok"), r->p_ino);
	r = &res.row[1];	/* J4: the host is out of reach */
	CF_CHECK_ERR("J4 supervisor open of the host path", r->s_open_rv,
	    r->s_open_errno, ENOENT);
	CF_CHECK_ERR("J4 supervisor open of /../outside", res.extra_rv[1],
	    res.extra_errno[1], ENOENT);
	CF_CHECK_REPLY("J4", r);
	CF_CHECK_ERR("J4 program open", r->p_open_rv, r->p_open_errno, ENOENT);
	r = &res.row[2];	/* J5: a host program is not bounded */
	CF_CHECK_SWAPPED("J5", r);
	CF_CHECK_OK("J5 openat(../../../outside)", r->p_op_rv, r->p_op_errno);
	r = &res.row[3];	/* J7 (pin) */
	CF_CHECK_REPLY("J7", r);
	CF_CHECK_OK("J7 program open", r->p_open_rv, r->p_open_errno);
	ATF_CHECK_STREQ("outside\n", r->p_data);
	CF_CHECK_OK("J8 dq_attach of a child in the jail", res.extra_rv[2],
	    res.extra_errno[2]);
	CF_CHECK_ERR("J9 dq_attach of a host process", res.extra_rv[3],
	    res.extra_errno[3], ESRCH);

	/* J6: the program in jail B, the supervisor in jail A. */
	cf_init(&sc, CF_JAIL_B6);
	sc.jid_a = jid_a;
	sc.jid_b = jid_b;
	cf_prow(&sc, O_RDONLY | O_DIRECTORY, CF_OP_OPENAT, "ok");
	cf_prow(&sc, 0, CF_OP_OPENAT_PREV, "..");
	cf_run(&sc, &res);
	cf_require_setup(&res);
	r = &res.row[0];
	CF_CHECK_SWAPPED("J6", r);
	CF_CHECK_OK("J6 openat(ok)", r->p_op_rv, r->p_op_errno);
	r = &res.row[1];
	CF_CHECK_ERR("J6 openat(..)", r->p_op_rv, r->p_op_errno, ENOTCAPABLE);

	ATF_CHECK_EQ(0, jail_remove(jid_a));
	ATF_CHECK_EQ(0, jail_remove(jid_b));
}
ATF_TC_CLEANUP(restricted_jail, tc)
{

	(void)jail_remove(jail_getid(CF_JAIL_A));
	(void)jail_remove(jail_getid(CF_JAIL_B));
}

/*
 * restricted_capmode: a root supervisor in capability mode.  The queue
 * serves; what it hands over has the rights of the directory it was
 * opened beneath.
 */
ATF_TC(restricted_capmode);
ATF_TC_HEAD(restricted_capmode, tc)
{

	atf_tc_set_md_var(tc, "descr", "a supervisor in capability mode "
	    "serves PASS, errno, SWAP and FD answers; a swapped file has "
	    "the rights of the directory descriptor it was opened beneath");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(restricted_capmode, tc)
{
	struct cf_scene sc;
	struct cf_res res;
	const struct cf_row *r;

	cf_init(&sc, CF_CAPMODE);
	ATF_REQUIRE_EQ(0, mkdir("in", 0755));
	cf_write_file("in/ok", "inside\n", 0, 0644);
	cf_write_file("outside", "outside\n", 0, 0644);
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* C2 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* C3 */
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* C4 */
	cf_prow(&sc, O_RDONLY, CF_OP_CAPS, NULL);	/* C5 */
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* C6 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* C-out */
	cf_run(&sc, &res);
	cf_require_setup(&res);

	ATF_CHECK_EQ_MSG(1, res.extra_rv[0], "C1 cap_getmode: %d errno %d",
	    res.extra_rv[0], res.extra_errno[0]);
	r = &res.row[0];	/* C2 */
	CF_CHECK_REPLY("C2", r);
	CF_CHECK_ERR("C2 program open", r->p_open_rv, r->p_open_errno, ENOENT);
	r = &res.row[1];	/* C3 */
	CF_CHECK_REPLY("C3", r);
	CF_CHECK_ERR("C3 program open", r->p_open_rv, r->p_open_errno, EPERM);
	r = &res.row[2];	/* C4 */
	CF_CHECK_SWAPPED("C4", r);
	ATF_CHECK_STREQ("inside\n", r->p_data);
	r = &res.row[3];	/* C5: the directory's rights are the file's */
	CF_CHECK_SWAPPED("C5", r);
	ATF_CHECK_STREQ("inside\n", r->p_data);
	CF_CHECK_ERR("C5 fchmod", r->p_op_rv, r->p_op_errno, ENOTCAPABLE);
	ATF_CHECK_EQ_MSG(1, r->p_mode, "C5: the program's rights are not "
	    "exactly CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_SEEK");
	r = &res.row[4];	/* C6 */
	CF_CHECK_OK("C6 supervisor openat", r->s_open_rv, r->s_open_errno);
	CF_CHECK_REPLY("C6", r);
	CF_CHECK_OK("C6 program open", r->p_open_rv, r->p_open_errno);
	ATF_CHECK_STREQ(CF_PROXY, r->p_data);
	r = &res.row[5];	/* C-out */
	CF_CHECK_ERR("C-out supervisor open by path", r->s_open_rv,
	    r->s_open_errno, ECAPMODE);
	CF_CHECK_ERR("C-out supervisor openat(../outside)", res.extra_rv[1],
	    res.extra_errno[1], ENOTCAPABLE);
	CF_CHECK_REPLY("C-out", r);
	CF_CHECK_ERR("C-out program open", r->p_open_rv, r->p_open_errno,
	    EACCES);
	CF_CHECK_OK("C7 dq_attach in capability mode", res.extra_rv[2],
	    res.extra_errno[2]);
	/* A program created in capability mode is never offered a swap. */
	ATF_CHECK_MSG(res.extra_rv[5] == 1, "C7: a capability-mode program's "
	    "open was offered SWAP (accept %#x)", (u_int)res.extra_errno[5]);
	printf("C7: the capability-mode program's open: accept %#x\n",
	    (u_int)res.extra_errno[5]);
	CF_CHECK_OK("C8 DQ_IOC_GET_STATS on the limited queue",
	    res.extra_rv[3], res.extra_errno[3]);
	CF_CHECK_ERR("C8 DQ_IOC_MINT outside the ioctl list", res.extra_rv[4],
	    res.extra_errno[4], ENOTCAPABLE);
}

/*
 * restricted_all: dq(4)'s order: open, attach, jail, drop, directory,
 * capability mode, serve.
 */
ATF_TC_WITH_CLEANUP(restricted_all);
ATF_TC_HEAD(restricted_all, tc)
{

	atf_tc_set_md_var(tc, "descr", "a supervisor restricted in the order "
	    "of dq(4) (jail, unprivileged user, capability mode) serves "
	    "SWAP; a write through its file clears set-ID bits");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(restricted_all, tc)
{
	struct cf_scene sc;
	struct cf_res res;
	const struct cf_row *r;
	int jid_a;

	cf_init(&sc, CF_ALL);
	ATF_REQUIRE_EQ(0, mkdir("ja", 0755));
	ATF_REQUIRE_EQ(0, mkdir("ja/in", 0755));
	cf_write_file("ja/in/ok", "inside\n", CF_UID_S, 0644);
	cf_write_file("ja/in/suid", "x\n", CF_UID_P, 04757);
	cf_write_file("outside", "outside\n", 0, 0644);
	jid_a = cf_make_jail("ja", CF_JAIL_A);
	sc.jid_a = jid_a;
	cf_prow(&sc, O_RDONLY, CF_OP_READ, NULL);	/* A1 */
	cf_prow(&sc, O_WRONLY, CF_OP_WRITE, NULL);	/* A2 */
	cf_prow(&sc, O_RDONLY, CF_OP_NONE, NULL);	/* A3 */
	cf_run(&sc, &res);
	cf_require_setup(&res);
	ATF_CHECK_EQ_MSG(1, res.extra_rv[0], "cap_getmode: %d errno %d",
	    res.extra_rv[0], res.extra_errno[0]);

	r = &res.row[0];	/* A1 */
	CF_CHECK_SWAPPED("A1", r);
	ATF_CHECK_STREQ("inside\n", r->p_data);
	ATF_CHECK_EQ((uint32_t)CF_UID_S, r->p_uid);
	r = &res.row[1];	/* A2 */
	CF_CHECK_SWAPPED("A2", r);
	ATF_CHECK_EQ_MSG(1, r->p_op_rv, "A2 write: errno %d", r->p_op_errno);
	ATF_CHECK_EQ_MSG(0757, r->p_mode, "A2: mode %#o, want 0757",
	    r->p_mode);
	r = &res.row[2];	/* A3 */
	CF_CHECK_ERR("A3 supervisor openat(../../outside)", r->s_open_rv,
	    r->s_open_errno, ENOTCAPABLE);
	CF_CHECK_REPLY("A3", r);
	ATF_CHECK_MSG(r->p_open_rv == -1, "A3: the program opened outside");

	ATF_CHECK_EQ(0, jail_remove(jid_a));
}
ATF_TC_CLEANUP(restricted_all, tc)
{

	(void)jail_remove(jail_getid(CF_JAIL_A));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, restricted_uid);
	ATF_TP_ADD_TC(tp, restricted_jail);
	ATF_TP_ADD_TC(tp, restricted_capmode);
	ATF_TP_ADD_TC(tp, restricted_all);
	return (atf_no_error());
}
