/* SPDX-License-Identifier: BSD-2-Clause */
/* Parent-path identity regression. Run only in disposable guests. */
#define _GNU_SOURCE
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "PARENT line %d: %s errno=%d\n", __LINE__, #x, errno); \
 exit(1); } } while (0)

static void
expect(int fd, int wd, unsigned mask, const char *name)
{
 union { struct inotify_event align; char bytes[4096]; } buf;
 ssize_t n = read(fd, buf.bytes, sizeof(buf.bytes));
 if (mask == 0) {
  if (n == -1 && errno == EAGAIN) return;
 } else if (n >= (ssize_t)sizeof(struct inotify_event)) {
  struct inotify_event *e = (void *)buf.bytes;
  if (n == (ssize_t)(sizeof(*e) + e->len) && e->wd == wd &&
      e->mask == mask && e->cookie == 0 &&
      ((!name[0] && e->len == 0) ||
      (name[0] && e->len > strlen(name) && !strcmp(e->name, name)))) return;
 }
 fprintf(stderr, "PARENT expected wd=%d mask=%x name=%s bytes=%zd errno=%d\n",
     wd, mask, name, n, errno);
 for (ssize_t off = 0; off + (ssize_t)sizeof(struct inotify_event) <= n;) {
  struct inotify_event *e = (void *)(buf.bytes + off);
  fprintf(stderr, "PARENT actual wd=%d mask=%x cookie=%u name=%s\n",
      e->wd, e->mask, e->cookie, e->len ? e->name : "");
  off += sizeof(*e) + e->len;
 }
 exit(1);
}

static void
race_events(int fd, int wd, int wd2, int rename_case)
{
 union { struct inotify_event align; char bytes[16384]; } buf;
 ssize_t n;
 while ((n = read(fd, buf.bytes, sizeof(buf.bytes))) > 0) {
  for (ssize_t off = 0; off < n;) {
   CHECK(off + (ssize_t)sizeof(struct inotify_event) <= n);
   struct inotify_event *e = (void *)(buf.bytes + off);
   CHECK(off + (ssize_t)(sizeof(*e) + e->len) <= n);
   CHECK(e->mask == IN_MODIFY && e->cookie == 0 && e->len >= 6);
   /* Linux can sample the parent and name on opposite sides of a rename. */
   if (!((e->wd == wd || (rename_case && e->wd == wd2)) &&
       (!strcmp(e->name, "first") || (rename_case && !strcmp(e->name, "moved"))))) {
    fprintf(stderr, "PARENT race wd=%d name=%s\n", e->wd, e->name);
    exit(1);
   }
   off += sizeof(*e) + e->len;
  }
 }
 CHECK(n == -1 && errno == EAGAIN);
}

int
main(int argc, char **argv)
{
 char dir[] = "/tmp/inotify-parent-XXXXXX";
 int f, g = -1, fd, wd, wd2, self_fd = -1, self_wd = -1;
 unsigned mask = IN_OPEN | IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE;
 CHECK(argc >= 2);
 alarm(30);
 if (argc > 2 && !strcmp(argv[2], "unprivileged")) {
  CHECK(setgid(65534) == 0); CHECK(setuid(65534) == 0);
 }
 CHECK(mkdtemp(dir) != NULL); CHECK(chdir(dir) == 0);
 CHECK(mkdir("a", 0700) == 0); CHECK(mkdir("b", 0700) == 0);
 f = open("a/first", O_CREAT | O_RDWR, 0600); CHECK(f >= 0);
 CHECK(link("a/first", "a/alias") == 0);
 CHECK(link("a/first", "b/alias") == 0);
 int excluded = strstr(argv[1], "exclude") != NULL;
 if (excluded) mask |= IN_EXCL_UNLINK;
 fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); CHECK(fd >= 0);
 wd = inotify_add_watch(fd, "a", mask); CHECK(wd >= 0);
 wd2 = inotify_add_watch(fd, "b", mask); CHECK(wd2 >= 0);
 const char *name = "first";
 int target = wd, silent = 0;
 if (!strcmp(argv[1], "dual")) {
  self_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); CHECK(self_fd >= 0);
  self_wd = inotify_add_watch(self_fd, "a/first", mask); CHECK(self_wd >= 0);
 } else if (!strcmp(argv[1], "hardlinks")) {
  g = open("b/alias", O_RDWR); CHECK(g >= 0);
  expect(fd, wd2, IN_OPEN, "alias");
  CHECK(write(g, "b", 1) == 1); expect(fd, wd2, IN_MODIFY, "alias");
  CHECK(close(g) == 0); g = -1;
  expect(fd, wd2, IN_CLOSE_WRITE, "alias");
 } else if (!strcmp(argv[1], "rename")) {
  CHECK(rename("a/first", "a/moved") == 0); name = "moved";
 } else if (!strcmp(argv[1], "crossrename")) {
  CHECK(rename("a/first", "b/moved") == 0); name = "moved"; target = wd2;
 } else if (!strcmp(argv[1], "renamechurn") || !strcmp(argv[1], "unlinkrace") ||
     !strcmp(argv[1], "excluderace")) {
  int renaming = !strcmp(argv[1], "renamechurn");
  pid_t child = fork(); CHECK(child >= 0);
  if (child == 0) {
   for (int i = 0; i < 1000; i++) {
    if (write(f, "r", 1) != 1) _exit(1);
    sched_yield();
   }
   _exit(0);
  }
  if (renaming) {
   for (int i = 0; i < 500; i++) {
    CHECK(rename("a/first", "b/moved") == 0);
    CHECK(rename("b/moved", "a/first") == 0);
    sched_yield();
   }
  } else {
   CHECK(unlink("a/first") == 0);
   CHECK(link("a/alias", "a/first") == 0);
   CHECK(rename("a/first", "a/moved") == 0);
   silent = excluded;
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  race_events(fd, wd, wd2, renaming);
 } else if (!strcmp(argv[1], "unlink") || !strcmp(argv[1], "unlinklast") || excluded ||
     !strcmp(argv[1], "recreate")) {
  CHECK(unlink("a/first") == 0); silent = excluded;
  if (strstr(argv[1], "last") != NULL) {
   CHECK(unlink("a/alias") == 0); CHECK(unlink("b/alias") == 0);
  }
  if (!strcmp(argv[1], "recreate")) {
   g = open("a/first", O_CREAT | O_RDWR, 0600); CHECK(g >= 0);
   expect(fd, wd, IN_OPEN, "first");
  }
 } else if (!strcmp(argv[1], "overwrite")) {
  g = open("b/target", O_CREAT | O_RDWR, 0600); CHECK(g >= 0);
  expect(fd, wd2, IN_OPEN, "target");
  CHECK(rename("a/first", "b/target") == 0);
  name = "target"; target = wd2;
  CHECK(write(g, "g", 1) == 1); expect(fd, wd2, IN_MODIFY, "target");
  CHECK(close(g) == 0); g = -1;
  expect(fd, wd2, IN_CLOSE_WRITE, "target");
 } else if (!strcmp(argv[1], "procfd") || !strcmp(argv[1], "procfddeleted") || !strcmp(argv[1], "procfdlast")) {
  char path[64];
  if (strcmp(argv[1], "procfd")) CHECK(unlink("a/first") == 0);
  if (!strcmp(argv[1], "procfdlast")) {
   CHECK(unlink("a/alias") == 0); CHECK(unlink("b/alias") == 0);
  }
  snprintf(path, sizeof(path), "/proc/self/fd/%d", f);
  g = open(path, O_RDWR); CHECK(g >= 0);
  expect(fd, wd, IN_OPEN, "first");
  CHECK(close(f) == 0); expect(fd, wd, IN_CLOSE_WRITE, "first");
  f = g; g = -1;
 } else if (!strcmp(argv[1], "failedopen")) {
  for (int i = 0; i < 100; i++) {
   CHECK(open("a/first", O_CREAT | O_EXCL | O_RDWR, 0600) == -1 && errno == EEXIST);
   CHECK(open("a/missing/child", O_RDONLY) == -1 && errno == ENOENT);
  }
 } else if (!strcmp(argv[1], "createlate")) {
  g = open("a/new", O_CREAT | O_RDWR, 0600); CHECK(g >= 0);
  expect(fd, wd, IN_OPEN, "new");
  CHECK(write(g, "g", 1) == 1); expect(fd, wd, IN_MODIFY, "new");
  CHECK(close(g) == 0); g = -1; expect(fd, wd, IN_CLOSE_WRITE, "new");
  CHECK(unlink("a/new") == 0);
 } else if (!strcmp(argv[1], "fork")) {
  pid_t child = fork(); CHECK(child >= 0);
  if (child == 0) _exit(write(f, "c", 1) == 1 ? 0 : 1);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  expect(fd, wd, IN_MODIFY, "first");
 } else if (!strcmp(argv[1], "mapclose")) {
  /* The common write below supplies backing data before mapping. */
 } else if (!strcmp(argv[1], "dup")) {
  g = dup(f); CHECK(g >= 0); CHECK(close(f) == 0); f = g; g = -1;
 } else { fprintf(stderr, "unknown case %s\n", argv[1]); return (2); }
 expect(fd, 0, 0, "");
 CHECK(write(f, "x", 1) == 1); expect(fd, target, silent ? 0 : IN_MODIFY, name);
 if (self_fd >= 0) expect(self_fd, self_wd, IN_MODIFY, "");
 char c;
 CHECK(pread(f, &c, 1, 0) == 1); expect(fd, target, silent ? 0 : IN_ACCESS, name);
 if (self_fd >= 0) expect(self_fd, self_wd, IN_ACCESS, "");
 if (!strcmp(argv[1], "mapclose")) {
  void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f, 0);
  CHECK(mapping != MAP_FAILED);
  expect(fd, 0, 0, "");
  CHECK(close(f) == 0); expect(fd, 0, 0, "");
  CHECK(munmap(mapping, 4096) == 0);
  expect(fd, target, IN_CLOSE_WRITE, name);
 } else {
  CHECK(close(f) == 0); expect(fd, target, silent ? 0 : IN_CLOSE_WRITE, name);
 }
 expect(fd, 0, 0, "");
 if (self_fd >= 0) {
  expect(self_fd, self_wd, IN_CLOSE_WRITE, "");
  expect(self_fd, 0, 0, ""); CHECK(close(self_fd) == 0);
 }
 CHECK(close(fd) == 0); if (g >= 0) CHECK(close(g) == 0);
 const char *paths[] = {"a/first", "a/alias", "a/moved", "b/alias", "b/moved", "b/target"};
 for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
  CHECK(unlink(paths[i]) == 0 || errno == ENOENT);
 CHECK(rmdir("a") == 0); CHECK(rmdir("b") == 0);
 CHECK(chdir("/") == 0); CHECK(rmdir(dir) == 0);
 printf("PARENT_PASS %s\n", argv[1]);
 return (0);
}
