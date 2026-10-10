/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test ideas from Fuchsia Starnix inotify_test.cc at
 * 8a938a3224e768f6254ee12d240b6492361ebccf. Run in an empty writable directory.
 */
#include "linux_test.h"

#if !defined(__x86_64__)
#error This probe currently targets Linux x86-64.
#endif
#define SYS_link 86
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
#define SYS_inotify_init1 294
#define IN_ATTRIB 0x4
#define IN_CREATE 0x100
#define IN_DELETE 0x200
#define IN_DELETE_SELF 0x400
#define IN_IGNORED 0x8000
#define IN_ISDIR 0x40000000

struct in_event { int wd; u32 mask, cookie, len; };
_Static_assert(sizeof(struct in_event) == 16, "inotify event ABI");

#define CHECK(c) do { if (!(c)) { \
	msgnum("inotify check line ", __LINE__); rc = 1; goto out; \
} } while (0)

static int
self_events(long fd, int wd, const u32 *masks, int count)
{
	struct in_event events[4];
	long n;
	int i;

	n = sys3(SYS_read, fd, events, sizeof(events));
	if (n != (long)(count * sizeof(events[0]))) {
		msgnum("event bytes ", n);
		return (0);
	}
	for (i = 0; i < count; i++) {
		if (events[i].wd != wd || events[i].mask != masks[i] ||
		    events[i].cookie != 0 || events[i].len != 0) {
			msgnum("event mask ", events[i].mask);
			return (0);
		}
	}
	return (sys3(SYS_read, fd, events, sizeof(events)) == -EAGAIN);
}

static int
delete_directory(int requested, int parent, int held)
{
	union { struct in_event align; char bytes[256]; } buf;
	struct in_event *ev;
	u32 masks[] = { IN_DELETE_SELF, IN_IGNORED };
	long fd = -1, dirfd = -1, wd, pwd = -1, n;
	size_t off;
	int rc = 0, made = 0;

	CHECK(sys2(SYS_mkdir, "watched", 0700) == 0);
	made = 1;
	fd = sys1(SYS_inotify_init1, O_NONBLOCK | O_CLOEXEC);
	CHECK(fd >= 0);
	if (parent) {
		pwd = sys3(SYS_inotify_add_watch, fd, ".", IN_DELETE);
		CHECK(pwd >= 0);
	}
	wd = sys3(SYS_inotify_add_watch, fd, "watched",
	    IN_CREATE | (requested ? IN_DELETE_SELF : IN_DELETE));
	CHECK(wd >= 0);
	if (held) {
		dirfd = sys3(SYS_open, "watched", O_RDONLY | O_DIRECTORY, 0);
		CHECK(dirfd >= 0);
	}
	CHECK(sys1(SYS_rmdir, "watched") == 0);
	made = 0;
	if (held) {
		if (parent) {
			n = sys3(SYS_read, fd, buf.bytes, sizeof(buf.bytes));
			CHECK(n >= (long)(sizeof(*ev) + sizeof("watched")));
			ev = (struct in_event *)buf.bytes;
			CHECK(ev->wd == pwd && ev->mask == (IN_DELETE | IN_ISDIR) &&
			    ev->cookie == 0 && sizeof(*ev) + ev->len == (size_t)n);
			CHECK(xstreq((char *)(ev + 1), "watched"));
			parent = 0; /* Only child terminal events may follow close. */
		}
		CHECK(sys3(SYS_read, fd, buf.bytes, sizeof(buf.bytes)) == -EAGAIN);
		CHECK(sys1(SYS_close, dirfd) == 0);
		dirfd = -1;
	}
	if (!parent) {
		CHECK(self_events(fd, (int)wd, masks + !requested,
		    requested ? 2 : 1));
	} else {
		n = sys3(SYS_read, fd, buf.bytes, sizeof(buf.bytes));
		CHECK(n >= 3 * (long)sizeof(*ev));
		off = 0;
		for (int i = 0; i < 2; i++) {
			ev = (struct in_event *)(buf.bytes + off);
			if (ev->wd != wd || ev->mask != masks[i]) {
				msgnum("child event index ", i);
				msgnum("actual wd ", ev->wd);
				msgnum("actual mask ", ev->mask);
			}
			CHECK(ev->wd == wd && ev->mask == masks[i] &&
			    ev->cookie == 0 && ev->len == 0);
			off += sizeof(*ev);
		}
		ev = (struct in_event *)(buf.bytes + off);
		CHECK(ev->wd == pwd && ev->mask == (IN_DELETE | IN_ISDIR) &&
		    ev->cookie == 0 && ev->len >= sizeof("watched") &&
		    off + sizeof(*ev) + ev->len == (size_t)n);
		CHECK(xstreq((char *)(ev + 1), "watched"));
		CHECK(sys3(SYS_read, fd, buf.bytes, sizeof(buf.bytes)) == -EAGAIN);
	}
	CHECK(sys2(SYS_inotify_rm_watch, fd, wd) == -EINVAL);
out:
	if (dirfd >= 0)
		(void)sys1(SYS_close, dirfd);
	if (fd >= 0)
		(void)sys1(SYS_close, fd);
	if (made)
		(void)sys1(SYS_rmdir, "watched");
	return (rc);
}

static int
hardlinks(int watch_first)
{
	u32 attrib[] = { IN_ATTRIB };
	u32 terminal[] = { IN_ATTRIB, IN_DELETE_SELF, IN_IGNORED };
	long file = -1, fd = -1, wd;
	int rc = 0, first = 0, second = 0;

	file = sys3(SYS_open, "first", O_CREAT | O_EXCL | O_RDWR, 0600);
	CHECK(file >= 0);
	first = 1;
	CHECK(sys1(SYS_close, file) == 0);
	file = -1;
	CHECK(sys2(SYS_link, "first", "second") == 0);
	second = 1;
	fd = sys1(SYS_inotify_init1, O_NONBLOCK | O_CLOEXEC);
	CHECK(fd >= 0);
	wd = sys3(SYS_inotify_add_watch, fd, watch_first ? "first" : "second",
	    IN_ATTRIB | IN_DELETE_SELF);
	CHECK(wd >= 0);
	CHECK(sys1(SYS_unlink, "first") == 0);
	first = 0;
	CHECK(self_events(fd, (int)wd, attrib, 1));
	CHECK(sys1(SYS_unlink, "second") == 0);
	second = 0;
	CHECK(self_events(fd, (int)wd, terminal, 3));
	CHECK(sys2(SYS_inotify_rm_watch, fd, wd) == -EINVAL);
out:
	if (file >= 0)
		(void)sys1(SYS_close, file);
	if (fd >= 0)
		(void)sys1(SYS_close, fd);
	if (first)
		(void)sys1(SYS_unlink, "first");
	if (second)
		(void)sys1(SYS_unlink, "second");
	return (rc);
}

/* A cwd reference must defer self-deletion even without an open child fd. */
static int
cwd_directory(void)
{
	long parent = -1, fd = -1, wd;
	struct in_event event;
	u32 masks[] = { IN_DELETE_SELF, IN_IGNORED };
	int rc = 0, made = 0;

	parent = sys3(SYS_open, ".", O_RDONLY | O_DIRECTORY, 0);
	CHECK(parent >= 0);
	CHECK(sys2(SYS_mkdir, "watched", 0700) == 0);
	made = 1;
	fd = sys1(SYS_inotify_init1, O_NONBLOCK | O_CLOEXEC);
	CHECK(fd >= 0);
	wd = sys3(SYS_inotify_add_watch, fd, "watched", IN_DELETE_SELF);
	CHECK(wd >= 0);
	CHECK(sys1(SYS_chdir, "watched") == 0);
	CHECK(sys3(SYS_unlinkat, parent, "watched", 0x200 /* AT_REMOVEDIR */) == 0);
	made = 0;
	CHECK(sys3(SYS_read, fd, &event, sizeof(event)) == -EAGAIN);
	CHECK(sys1(SYS_fchdir, parent) == 0);
	CHECK(self_events(fd, wd, masks, 2));
	CHECK(sys2(SYS_inotify_rm_watch, fd, wd) == -EINVAL);
out:
	if (parent >= 0) {
		(void)sys1(SYS_fchdir, parent);
		(void)sys1(SYS_close, parent);
	}
	if (fd >= 0)
		(void)sys1(SYS_close, fd);
	if (made)
		(void)sys1(SYS_rmdir, "watched");
	return (rc);
}

static int ignored_only(void) { return (delete_directory(0, 0, 0)); }
static int delete_self(void) { return (delete_directory(1, 0, 0)); }
static int child_before_parent(void) { return (delete_directory(1, 1, 0)); }
static int open_directory_parent(void) { return (delete_directory(1, 1, 1)); }
static int open_directory(void) { return (delete_directory(1, 0, 1)); }
static int watched_link_first(void) { return (hardlinks(1)); }
static int watched_link_last(void) { return (hardlinks(0)); }

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "ignored_without_delete_self", ignored_only },
		{ "delete_self_then_ignored", delete_self },
		{ "child_before_parent", child_before_parent },
		{ "open_directory_defers_self", open_directory },
		{ "open_directory_parent_first", open_directory_parent },
		{ "cwd_defers_self", cwd_directory },
		{ "watched_link_first", watched_link_first },
		{ "watched_link_last", watched_link_last },
	};

	(void)envp;
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
