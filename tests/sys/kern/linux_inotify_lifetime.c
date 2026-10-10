/* SPDX-License-Identifier: BSD-2-Clause */
/* Native and Linux64 lifetime regression probe. Disposable VMs only. */
#define _GNU_SOURCE
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifndef __linux__
#include <sys/mount.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); \
 exit(1); } } while (0)
static void empty_at(int fd, int line)
{
 struct inotify_event ev;
 ssize_t n = read(fd, &ev, sizeof(ev));
 if (n == -1 && errno == EAGAIN) return;
 fprintf(stderr, "empty at line %d: read=%zd errno=%d", line, n, errno);
 if (n == sizeof(ev))
  fprintf(stderr, " wd=%d mask=%x cookie=%u len=%u", ev.wd, ev.mask,
   ev.cookie, ev.len);
 fputc('\n', stderr);
 exit(1);
}
#define empty(fd) empty_at((fd), __LINE__)
static void event(int fd, int wd, unsigned mask)
{
 struct inotify_event ev;
 CHECK(read(fd, &ev, sizeof(ev)) == sizeof(ev));
 if (ev.wd != wd || ev.mask != mask || ev.cookie != 0 || ev.len != 0) {
  fprintf(stderr,"event: wd=%d mask=%x expected wd=%d mask=%x\n",
   ev.wd, ev.mask, wd, mask); exit(1);
 }
}
static void deleted(int fd, int wd, int directory)
{
 unsigned flags = 0;
#ifndef __linux__
 if (directory) flags = IN_ISDIR;
#else
 (void)directory;
#endif
 event(fd, wd, IN_DELETE_SELF | flags);
 event(fd, wd, IN_IGNORED);
 empty(fd);
 CHECK(inotify_rm_watch(fd, wd) == -1 && errno == EINVAL);
}
static int instance(void)
{
 int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
 CHECK(fd >= 0); return fd;
}
static int watch(int fd, const char *path, unsigned mask)
{
 int wd = inotify_add_watch(fd, path, mask);
 CHECK(wd >= 0); return wd;
}
int main(int argc, char **argv)
{
 const char *tmpdir = getenv("TMPDIR");
 int length;
 char dir[PATH_MAX], path[PATH_MAX], other[PATH_MAX];
 CHECK(argc >= 2);
 alarm(60);
 if (argc > 2 && !strcmp(argv[2], "unprivileged")) {
  CHECK(setgid(65534) == 0); CHECK(setuid(65534) == 0);
 }
 if (tmpdir == NULL || tmpdir[0] == '\0') tmpdir = "/tmp";
 CHECK(tmpdir[0] == '/');
 length = snprintf(dir, sizeof(dir), "%s/inotify-life-XXXXXX", tmpdir);
 CHECK(length > 0 && (size_t)length < sizeof(dir));
 CHECK(mkdtemp(dir) != NULL);
 length = snprintf(path, sizeof(path), "%s/file", dir);
 CHECK(length > 0 && (size_t)length < sizeof(path));
 length = snprintf(other, sizeof(other), "%s/other", dir);
 CHECK(length > 0 && (size_t)length < sizeof(other));
 int directory = !strcmp(argv[1], "directory");
 if (directory) CHECK(mkdir(path, 0700) == 0);
 int file = open(path, directory ? O_RDONLY | O_DIRECTORY : O_CREAT | O_RDWR, 0600);
 CHECK(file >= 0);
 int fd = instance(), wd;
 if (!strcmp(argv[1], "dup") || !strcmp(argv[1], "opens")) {
  int shared = !strcmp(argv[1], "dup");
  int alias = shared ? dup(file) : open(path, O_RDWR);
  CHECK(alias >= 0);
  int second = instance();
  unsigned mask = IN_ATTRIB | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF;
  wd = watch(fd, path, mask);
  int wd2 = watch(second, path, mask);
  CHECK(unlink(path) == 0);
  event(fd, wd, IN_ATTRIB); event(second, wd2, IN_ATTRIB);
  empty(fd); empty(second);
  CHECK(close(file) == 0);
  if (!shared) { event(fd, wd, IN_CLOSE_WRITE); event(second, wd2, IN_CLOSE_WRITE); }
  empty(fd); empty(second);
  CHECK(write(alias, "a", 1) == 1);
  event(fd, wd, IN_MODIFY); event(second, wd2, IN_MODIFY);
  CHECK(close(alias) == 0);
  event(fd, wd, IN_CLOSE_WRITE); event(second, wd2, IN_CLOSE_WRITE);
  deleted(fd, wd, 0); deleted(second, wd2, 0);
  CHECK(close(second) == 0);
 } else if (directory) {
  unsigned mask = IN_ACCESS | IN_CLOSE_NOWRITE | IN_DELETE_SELF;
  wd = watch(fd, path, mask);
  int second = instance(), wd2 = watch(second, path, mask);
  /* Installing a watch must not notify another watcher of an internal read. */
  empty(fd); empty(second);
  CHECK(rmdir(path) == 0); empty(fd); empty(second);
  CHECK(close(file) == 0);
  event(fd, wd, IN_CLOSE_NOWRITE | IN_ISDIR);
  event(second, wd2, IN_CLOSE_NOWRITE | IN_ISDIR);
  deleted(fd, wd, 1); deleted(second, wd2, 1);
  CHECK(close(second) == 0);
 } else if (!strcmp(argv[1], "shared-map") || !strcmp(argv[1], "private-map")) {
  CHECK(ftruncate(file, 4096) == 0);
  CHECK(pwrite(file, "x", 1, 0) == 1);
  int flags = !strcmp(argv[1], "shared-map") ? MAP_SHARED : MAP_PRIVATE;
  int native_tmpfs_private = 0;
#ifndef __linux__
  struct statfs fs;
  CHECK(fstatfs(file, &fs) == 0);
  /* Native tmpfs private mappings hold the VM object, not the vnode.
   * Linux64 mappings separately retain the open description through unmap. */
  native_tmpfs_private = flags == MAP_PRIVATE &&
   strcmp(fs.f_fstypename, "tmpfs") == 0;
#endif
  void *map = mmap(NULL, 4096, PROT_READ, flags, file, 0);
  CHECK(map != MAP_FAILED);
  /* This case tests watch deletion, independently of close-event timing. */
  wd = watch(fd, path, IN_DELETE_SELF);
  CHECK(unlink(path) == 0); empty(fd);
  CHECK(close(file) == 0);
  if (native_tmpfs_private) deleted(fd, wd, 0); else empty(fd);
  /* The mapped data must survive unlink/close even if the vnode is inactive. */
  CHECK(*(volatile const char *)map == 'x');
  CHECK(munmap(map, 4096) == 0);
  if (native_tmpfs_private) empty(fd); else deleted(fd, wd, 0);
 } else if (!strcmp(argv[1], "late-watch")) {
  CHECK(unlink(path) == 0);
#ifdef __linux__
  const char *fdroot = "/proc/self/fd";
#else
  /* Native runner supplies a private fdescfs mount with vnode handoff. */
  const char *fdroot = getenv("INOTIFY_FD_ROOT");
  CHECK(fdroot != NULL && fdroot[0] == '/');
#endif
  length = snprintf(other, sizeof(other), "%s/%d", fdroot, file);
  CHECK(length > 0 && (size_t)length < sizeof(other));
  wd = watch(fd, other, IN_DELETE_SELF | IN_MODIFY);
  CHECK(write(file, "a", 1) == 1); event(fd, wd, IN_MODIFY); empty(fd);
  CHECK(close(file) == 0); deleted(fd, wd, 0);
 } else if (!strcmp(argv[1], "hardlink")) {
  CHECK(link(path, other) == 0);
  wd = watch(fd, path, IN_DELETE_SELF);
  CHECK(unlink(path) == 0); empty(fd);
  CHECK(close(file) == 0); empty(fd);
  CHECK(unlink(other) == 0); deleted(fd, wd, 0);
 } else if (!strcmp(argv[1], "replace")) {
  int replacement = open(other, O_CREAT | O_RDWR, 0600);
  CHECK(replacement >= 0);
  wd = watch(fd, path, IN_DELETE_SELF);
  CHECK(rename(other, path) == 0); empty(fd);
  CHECK(close(replacement) == 0); empty(fd);
  CHECK(close(file) == 0); deleted(fd, wd, 0);
  CHECK(unlink(path) == 0);
 } else if (!strcmp(argv[1], "remove-watch")) {
  wd = watch(fd, path, IN_DELETE_SELF);
  CHECK(unlink(path) == 0); empty(fd);
  CHECK(inotify_rm_watch(fd, wd) == 0);
  event(fd, wd, IN_IGNORED); empty(fd);
  CHECK(close(file) == 0); empty(fd);
 } else if (!strcmp(argv[1], "fork-exit")) {
  int gate[2]; pid_t children[4];
  CHECK(pipe(gate) == 0);
  wd = watch(fd, path, IN_DELETE_SELF);
  CHECK(unlink(path) == 0);
  for (unsigned i = 0; i < 4; i++) {
   children[i] = fork(); CHECK(children[i] >= 0);
   if (children[i] == 0) {
    char byte;
    CHECK(close(gate[1]) == 0);
    CHECK(read(gate[0], &byte, 1) == 1);
    /* Process exit drops inherited file and watcher references. */
    _exit(0);
   }
  }
  CHECK(close(gate[0]) == 0);
  CHECK(close(file) == 0); empty(fd);
  CHECK(write(gate[1], "abcd", 4) == 4); CHECK(close(gate[1]) == 0);
  for (unsigned i = 0; i < 4; i++) {
   int status; CHECK(waitpid(children[i], &status, 0) == children[i]);
   CHECK(status == 0);
  }
  deleted(fd, wd, 0);
 } else if (!strcmp(argv[1], "close-watches")) {
  int watches[32];
  wd = watch(fd, path, IN_DELETE_SELF);
  for (unsigned i = 0; i < 32; i++) {
   watches[i] = instance(); watch(watches[i], path, IN_DELETE_SELF);
  }
  CHECK(unlink(path) == 0); empty(fd);
  for (unsigned i = 0; i < 32; i++) CHECK(close(watches[i]) == 0);
  CHECK(close(file) == 0); deleted(fd, wd, 0);
 } else {
  fprintf(stderr, "unknown case %s\n", argv[1]); return 2;
 }
 CHECK(close(fd) == 0); CHECK(rmdir(dir) == 0);
 printf("LIFETIME_CASE %s PASS\n", argv[1]); return 0;
}
