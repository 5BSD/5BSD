/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 open-description ownership by mappings. Disposable guests only. */
#define _GNU_SOURCE
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "%s:%d: %s errno=%d\n", __func__, __LINE__, #x, errno); \
 exit(1); } } while (0)

static void
empty(int fd)
{
	char buf[4096];

	CHECK(read(fd, buf, sizeof(buf)) == -1 && errno == EAGAIN);
}

static void
event(int fd, int wd, unsigned mask)
{
	struct inotify_event ev;

	CHECK(read(fd, &ev, sizeof(ev)) == sizeof(ev));
	if (ev.wd != wd || ev.mask != mask || ev.cookie != 0 || ev.len != 0) {
		fprintf(stderr, "wd=%d mask=%x expected wd=%d mask=%x\n",
		    ev.wd, ev.mask, wd, mask);
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	char dir[] = "/tmp/mapping-life-XXXXXX", path[256], token;
	const char *mode;
	unsigned close_event;
	long page;
	size_t size;
	char *map, *other;
	int fd, notify, wd, flags, readonly, control[2], status;
	pid_t child;

	CHECK(argc >= 2);
	mode = argv[1];
	if (!strcmp(mode, "exec-child"))
		return (0);
	alarm(45);
	if (argc > 2 && !strcmp(argv[2], "unprivileged")) {
		CHECK(setgid(65534) == 0);
		CHECK(setuid(65534) == 0);
	}
	page = sysconf(_SC_PAGESIZE);
	CHECK(page > 0);
	size = 3 * page;
	CHECK(mkdtemp(dir) != NULL);
	snprintf(path, sizeof(path), "%s/file", dir);
	fd = open(path, O_CREAT | O_RDWR, 0600);
	CHECK(fd >= 0);
	CHECK(ftruncate(fd, size) == 0);
	CHECK(pwrite(fd, "A", 1, 0) == 1);
	CHECK(pwrite(fd, "B", 1, page) == 1);
	readonly = !strcmp(mode, "readonly");
	if (readonly) {
		CHECK(close(fd) == 0);
		fd = open(path, O_RDONLY);
		CHECK(fd >= 0);
	}
	close_event = readonly ? IN_CLOSE_NOWRITE : IN_CLOSE_WRITE;
	notify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	CHECK(notify >= 0);
	wd = inotify_add_watch(notify, path, IN_CLOSE | IN_DELETE_SELF);
	CHECK(wd >= 0);
	flags = (!strcmp(mode, "shared") || !strcmp(mode, "remap-pages") ||
	    !strcmp(mode, "remap-merge")) ?
	    MAP_SHARED : MAP_PRIVATE;
	map = mmap(NULL, size, PROT_READ | (readonly ? 0 : PROT_WRITE), flags, fd, 0);
	CHECK(map != MAP_FAILED);
	if (!strcmp(mode, "remap-merge")) {
		CHECK(mmap(map + page, page, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_FIXED, fd, page) == map + page);
	}
	other = MAP_FAILED;
	if (!strcmp(mode, "two-maps")) {
		other = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
		CHECK(other != MAP_FAILED);
	} else if (!strcmp(mode, "two-opens")) {
		int second = open(path, O_RDWR);
		CHECK(second >= 0);
		other = mmap(NULL, size, PROT_READ, MAP_PRIVATE, second, 0);
		CHECK(other != MAP_FAILED);
		CHECK(close(second) == 0);
		empty(notify);
	}
	CHECK(unlink(path) == 0);
	CHECK(close(fd) == 0);
	empty(notify);
	CHECK(map[0] == 'A');
	if (!strcmp(mode, "merge")) {
		CHECK(mprotect(map + page, page, PROT_READ) == 0);
		CHECK(mprotect(map + page, page, PROT_READ | PROT_WRITE) == 0);
		empty(notify);
		CHECK(munmap(map, size) == 0);
	} else if (!strcmp(mode, "shrink")) {
		CHECK(mremap(map, size, page, 0) == map);
		empty(notify);
		CHECK(munmap(map, page) == 0);
	} else if (!strcmp(mode, "split")) {
		CHECK(mprotect(map + page, page, PROT_READ) == 0);
		CHECK(munmap(map + page, page) == 0);
		empty(notify);
		CHECK(munmap(map + 2 * page, page) == 0);
		empty(notify);
		CHECK(munmap(map, page) == 0);
	} else if (!strcmp(mode, "fork-unmap") || !strcmp(mode, "fork-exit") ||
	    !strcmp(mode, "fork-exec") || !strcmp(mode, "fork-wired")) {
		if (!strcmp(mode, "fork-wired"))
			CHECK(mlock(map, size) == 0);
		CHECK(pipe(control) == 0);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			close(control[1]);
			CHECK(read(control[0], &token, 1) == 1);
			CHECK(map[0] == 'A');
			if (!strcmp(mode, "fork-unmap"))
				CHECK(munmap(map, size) == 0);
			else if (!strcmp(mode, "fork-exec")) {
				execl(argv[0], argv[0], "exec-child", (char *)NULL);
				_exit(2);
			}
			_exit(0);
		}
		close(control[0]);
		CHECK(munmap(map, size) == 0);
		empty(notify);
		CHECK(write(control[1], "x", 1) == 1);
		close(control[1]);
		CHECK(waitpid(child, &status, 0) == child);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	} else if (!strcmp(mode, "fixed")) {
		CHECK(mmap(map, size, PROT_READ, MAP_FIXED | MAP_PRIVATE |
		    MAP_ANONYMOUS, -1, 0) == map);
		CHECK(map[0] == 0);
		CHECK(munmap(map, size) == 0);
	} else {
		if (!strcmp(mode, "remap-merge")) {
			CHECK(syscall(SYS_remap_file_pages, map, size, 0, 0, 0) == 0);
			CHECK(map[0] == 'A' && map[page] == 'B');
			empty(notify);
		} else if (!strcmp(mode, "remap-pages")) {
			CHECK(syscall(SYS_remap_file_pages, map, page, 0, 1, 0) == 0);
			CHECK(map[0] == 'B');
			empty(notify);
		} else if (!strcmp(mode, "dontneed")) {
			map[0] = 'C';
			CHECK(madvise(map, size, MADV_DONTNEED) == 0);
			CHECK(map[0] == 'A');
			empty(notify);
		} else if (!strcmp(mode, "noreplace")) {
			CHECK(mmap(map, size, PROT_READ, MAP_FIXED_NOREPLACE |
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED);
			CHECK(errno == EEXIST);
			CHECK(map[0] == 'A');
			empty(notify);
		} else if (!strcmp(mode, "failed-fixed")) {
			CHECK(mmap(map, size, PROT_READ, MAP_FIXED | MAP_PRIVATE,
			    -1, 0) == MAP_FAILED);
			CHECK(map[0] == 'A');
			empty(notify);
		}
		CHECK(munmap(map, size) == 0);
		if (other != MAP_FAILED) {
			if (!strcmp(mode, "two-opens"))
				event(notify, wd, IN_CLOSE_WRITE);
			empty(notify);
			CHECK(munmap(other, size) == 0);
		}
	}
	event(notify, wd, close_event);
	event(notify, wd, IN_DELETE_SELF);
	event(notify, wd, IN_IGNORED);
	empty(notify);
	CHECK(close(notify) == 0);
	CHECK(rmdir(dir) == 0);
	printf("MAPPING_CASE %s PASS\n", mode);
	return (0);
}
