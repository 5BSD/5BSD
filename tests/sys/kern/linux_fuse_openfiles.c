/* SPDX-License-Identifier: BSD-2-Clause */
/* Per-open Linux FUSE semantics. Runtime only in disposable guests. */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <fuse_lowlevel.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, \
 "OPENFILES line %d: %s errno %d\n", __LINE__, #x, errno); exit(1); } } while (0)
struct handle { unsigned active, released, flushes; int flags; fuse_ino_t ino; };
static struct handle handles[64];
static unsigned opened, creates, last_sync, last_setattr;
static int direct, writeback, trace;
static unsigned char bytes[8192];
static off_t lengths[7] = { [2] = 4096, [3] = 4096, [6] = 4096 };
static sem_t stream_waiting, stream_sync_started;
static int stream_phase;
static fuse_req_t stream_held;
static void *stream_read_thread(void *arg)
{
 char c;
 CHECK(read(*(int *)arg, &c, 1) == 1 && c == 's');
 return NULL;
}
static void *stream_write_thread(void *arg)
{
 CHECK(write(*(int *)arg, "w", 1) == 1);
 return NULL;
}
static void *stream_sync_thread(void *arg)
{
 CHECK(sem_post(&stream_sync_started) == 0);
 CHECK(fsync(*(int *)arg) == 0);
 return NULL;
}
static void stream_duplex(int fd, int phase)
{
 pthread_t worker, syncer;
 struct timespec deadline;
 __atomic_store_n(&stream_phase, phase, __ATOMIC_RELEASE);
 CHECK(pthread_create(&worker, NULL, phase == 1 ? stream_read_thread :
  stream_write_thread, &fd) == 0);
 CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0); deadline.tv_sec += 10;
 CHECK(sem_timedwait(&stream_waiting, &deadline) == 0);
 if (phase == 2) {
  CHECK(pthread_create(&syncer, NULL, stream_sync_thread, &fd) == 0);
  CHECK(sem_timedwait(&stream_sync_started, &deadline) == 0);
  usleep(20000);
 }
 if (phase == 1) stream_write_thread(&fd); else stream_read_thread(&fd);
 CHECK(pthread_join(worker, NULL) == 0);
 if (phase == 2) CHECK(pthread_join(syncer, NULL) == 0);
 CHECK(__atomic_load_n(&stream_phase, __ATOMIC_ACQUIRE) == 0);
}

static void attr(struct stat *st, fuse_ino_t ino)
{
 memset(st, 0, sizeof(*st)); st->st_ino = ino; st->st_nlink = 1;
 st->st_mode = ino == FUSE_ROOT_ID ? S_IFDIR | 0755 : S_IFREG | 0666;
 st->st_size = lengths[ino];
 st->st_uid = getuid(); st->st_gid = getgid();
}
static void entry(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
 struct fuse_entry_param e = {0}; e.ino = ino; attr(&e.attr, ino);
 if (fi != NULL) fuse_reply_create(req, &e, fi); else fuse_reply_entry(req, &e);
}
static void lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
 CHECK(parent == FUSE_ROOT_ID);
 if (!strcmp(name, "file")) entry(req, 2, NULL);
 else if (!strcmp(name, "stream")) entry(req, 3, NULL);
 else if (!strcmp(name, "deny")) entry(req, 5, NULL);
 else if (!strcmp(name, "duplex")) entry(req, 6, NULL);
 else fuse_reply_err(req, ENOENT);
}
static void getattr_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
 struct stat st; (void)fi; attr(&st, ino); fuse_reply_attr(req, &st, 0);
}
static void init(void *arg, struct fuse_conn_info *conn)
{
 (void)arg;
 if (writeback) { CHECK(conn->capable & FUSE_CAP_WRITEBACK_CACHE);
  conn->want |= FUSE_CAP_WRITEBACK_CACHE; }
 else conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
}
static void allocate(fuse_ino_t ino, struct fuse_file_info *fi)
{
 unsigned id = __atomic_add_fetch(&opened, 1, __ATOMIC_RELAXED);
 CHECK(id < 64); fi->fh = id; handles[id].flags = fi->flags;
 handles[id].ino = ino; __atomic_store_n(&handles[id].active, 1, __ATOMIC_RELEASE);
 fi->direct_io = direct || ino == 3; fi->nonseekable = ino == 3;
 fi->keep_cache = 1;
}
static void open_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
 if (ino == 5) { fuse_reply_err(req, EACCES); return; }
 allocate(ino, fi);
 if (ino == 6) {
  /* Supply the wire OPEN reply: libfuse has no stream bit in file_info. */
  struct { uint64_t fh; uint32_t flags, padding; } reply = { fi->fh, 1 | 16, 0 };
  fuse_reply_buf(req, (const char *)&reply, sizeof(reply));
 } else fuse_reply_open(req, fi);
}
static void create_cb(fuse_req_t req, fuse_ino_t parent, const char *name,
 mode_t mode, struct fuse_file_info *fi)
{
 (void)mode; CHECK(parent == FUSE_ROOT_ID && !strcmp(name, "new"));
 CHECK((fi->flags & (O_ACCMODE | O_CREAT | O_EXCL | O_NONBLOCK)) ==
  (O_WRONLY | O_CREAT | O_EXCL | O_NONBLOCK));
 __atomic_fetch_add(&creates, 1, __ATOMIC_RELAXED);
 allocate(4, fi); entry(req, 4, fi);
}
static struct handle *check(fuse_ino_t ino, struct fuse_file_info *fi)
{
 CHECK(fi->fh > 0 && fi->fh < 64);
 struct handle *h = &handles[fi->fh];
 CHECK(__atomic_load_n(&h->active, __ATOMIC_ACQUIRE) && h->ino == ino);
 return h;
}
static void setattr_cb(fuse_req_t req, fuse_ino_t ino, struct stat *st,
 int to_set, struct fuse_file_info *fi)
{
 if (fi != NULL) { check(ino, fi);
  __atomic_store_n(&last_setattr, fi->fh, __ATOMIC_RELEASE); }
 if (to_set & FUSE_SET_ATTR_SIZE) {
  CHECK(st->st_size >= 0 && st->st_size <= (off_t)sizeof(bytes));
  lengths[ino] = st->st_size;
 }
 struct stat result; attr(&result, ino); fuse_reply_attr(req, &result, 0);
}
static void read_cb(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
 struct fuse_file_info *fi)
{
 check(ino, fi);
 if (ino == 6) {
  CHECK(off == 0 && size > 0);
  int phase = __atomic_load_n(&stream_phase, __ATOMIC_ACQUIRE);
  if (phase == 1) { stream_held = req; CHECK(sem_post(&stream_waiting) == 0); return; }
  if (phase == 2) {
   CHECK(stream_held != NULL); fuse_reply_write(stream_held, 1); stream_held = NULL;
   __atomic_store_n(&stream_phase, 0, __ATOMIC_RELEASE);
  }
  fuse_reply_buf(req, "s", 1); return;
 }
 CHECK(off >= 0 && off <= (off_t)sizeof(bytes));
 off_t length = lengths[ino];
 if (off >= length) size = 0;
 else if (size > (size_t)(length - off)) size = length - off;
 fuse_reply_buf(req, (char *)bytes + off, size);
}
static void write_cb(fuse_req_t req, fuse_ino_t ino, const char *buf,
 size_t size, off_t off, struct fuse_file_info *fi)
{
 check(ino, fi);
 if (ino == 6) {
  CHECK(off == 0 && size > 0);
  if (buf[0] == 'e') { fuse_reply_err(req, EIO); return; }
  int phase = __atomic_load_n(&stream_phase, __ATOMIC_ACQUIRE);
  if (phase == 2) { stream_held = req; CHECK(sem_post(&stream_waiting) == 0); return; }
  if (phase == 1) {
   CHECK(stream_held != NULL); fuse_reply_buf(stream_held, "s", 1); stream_held = NULL;
   __atomic_store_n(&stream_phase, 0, __ATOMIC_RELEASE);
  }
  fuse_reply_write(req, 1); return;
 }
 CHECK(off >= 0 && size <= sizeof(bytes) &&
  (uint64_t)off + size <= sizeof(bytes));
 if (trace) fprintf(stderr, "OF_WRITE ino=%llu fh=%llu off=%lld size=%zu bytes=%02x,%02x\n",
  (unsigned long long)ino, (unsigned long long)fi->fh, (long long)off, size,
  size > 0 ? (unsigned char)buf[0] : 0, size > 1 ? (unsigned char)buf[1] : 0);
 memcpy(bytes + off, buf, size); if (off + (off_t)size > lengths[ino])
  lengths[ino] = off + size;
 fuse_reply_write(req, size);
}
static void flush_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
 struct handle *h = check(ino, fi);
 __atomic_fetch_add(&h->flushes, 1, __ATOMIC_RELEASE); fuse_reply_err(req, 0);
}
static void release_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
 struct handle *h = check(ino, fi);
 if (trace) fprintf(stderr, "OF_RELEASE fh=%llu bytes=%02x,%02x\n",
  (unsigned long long)fi->fh, bytes[0], bytes[1]);
 CHECK((fi->flags & (O_ACCMODE | O_APPEND | O_NONBLOCK)) ==
  (h->flags & (O_ACCMODE | O_APPEND | O_NONBLOCK)));
 __atomic_store_n(&h->active, 0, __ATOMIC_RELEASE);
 __atomic_store_n(&h->released, 1, __ATOMIC_RELEASE); fuse_reply_err(req, 0);
}
static void fsync_cb(fuse_req_t req, fuse_ino_t ino, int data,
 struct fuse_file_info *fi)
{
 (void)data; check(ino, fi);
 if (ino == 6) CHECK(__atomic_load_n(&stream_phase, __ATOMIC_ACQUIRE) == 0);
 __atomic_store_n(&last_sync, fi->fh, __ATOMIC_RELEASE); fuse_reply_err(req, 0);
}
static void *serve(void *arg) { return (void *)(intptr_t)fuse_session_loop(arg); }
static void released(unsigned id)
{
 for (unsigned i = 0; i < 500 && !__atomic_load_n(&handles[id].released,
  __ATOMIC_ACQUIRE); i++) usleep(10000);
 CHECK(__atomic_load_n(&handles[id].released, __ATOMIC_ACQUIRE) == 1);
}
int main(int argc, char **argv)
{
 const struct fuse_lowlevel_ops ops = { .init=init, .lookup=lookup,
  .getattr=getattr_cb, .setattr=setattr_cb, .open=open_cb, .create=create_cb, .read=read_cb,
  .write=write_cb, .flush=flush_cb, .release=release_cb, .fsync=fsync_cb };
 char *options[] = {(char *)"openfiles", (char *)"-o",
  (char *)"allow_other", NULL};
 struct fuse_args args = FUSE_ARGS_INIT(3, options);
 struct fuse_session *se; pthread_t thread; char path[4096], c;
 CHECK(argc == 3); trace = getenv("OPENFILES_TRACE") != NULL; direct = !strcmp(argv[2], "direct");
 writeback = !strcmp(argv[2], "writeback");
 CHECK(direct || writeback || !strcmp(argv[2], "cached"));
 alarm(120); memset(bytes, 'x', sizeof(bytes));
 CHECK((se=fuse_session_new(&args, &ops, sizeof(ops), NULL)) != NULL);
 CHECK(fuse_session_mount(se, argv[1]) == 0);
 CHECK(pthread_create(&thread, NULL, serve, se) == 0);
 CHECK(snprintf(path, sizeof(path), "%s/file", argv[1]) < (int)sizeof(path));
 int a=open(path, O_RDWR | O_APPEND); CHECK(a >= 0);
 int b=open(path, O_RDWR); CHECK(b >= 0);
 CHECK(__atomic_load_n(&opened, __ATOMIC_ACQUIRE) == 2);
 if (direct) {
  CHECK(mmap(NULL, 4096, PROT_READ, MAP_SHARED, b, 0) == MAP_FAILED && errno == ENODEV);
  char *private = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, b, 0);
  CHECK(private != MAP_FAILED && private[0] == 'x');
  private[0] = 'P'; CHECK(munmap(private, 4096) == 0);
  CHECK(bytes[0] == 'x');
 }
 CHECK(pwrite(b, "B", 1, 0) == 1); CHECK(write(a, "A", 1) == 1);
 CHECK(pread(b, &c, 1, 0) == 1 && c == 'B');
 CHECK(fsync(b) == 0 && __atomic_load_n(&last_sync, __ATOMIC_ACQUIRE) == 2);
 CHECK(ftruncate(b, 4096) == 0 &&
  __atomic_load_n(&last_setattr, __ATOMIC_ACQUIRE) == 2);
 CHECK(close(a) == 0); released(1);
 int duplicate=dup(b); CHECK(duplicate >= 0); CHECK(close(b) == 0);
 CHECK(__atomic_load_n(&handles[2].released, __ATOMIC_ACQUIRE) == 0);
 CHECK(__atomic_load_n(&handles[2].flushes, __ATOMIC_ACQUIRE) >= 1);
 pid_t child=fork(); CHECK(child >= 0);
 if (child == 0) { CHECK(setuid(65534) == 0);
  CHECK(pread(duplicate, &c, 1, 0) == 1 && c == 'B');
  CHECK(close(duplicate) == 0); _exit(0); }
 int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
  WEXITSTATUS(status) == 0);
 CHECK(__atomic_load_n(&handles[2].released, __ATOMIC_ACQUIRE) == 0);
 CHECK(close(duplicate) == 0); released(2);
 a=open(path, O_WRONLY); CHECK(a >= 0);
 CHECK(pwrite(a, "W", 1, 7) == 1); CHECK(close(a) == 0); released(3);
 if (!direct) {
  a=open(path, O_RDWR); CHECK(a >= 0);
  char *map=mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, a, 0);
  CHECK(map != MAP_FAILED); map[0]='M'; CHECK(close(a) == 0);
  CHECK(__atomic_load_n(&handles[4].released, __ATOMIC_ACQUIRE) == 0);
  map[1]='N'; CHECK(munmap(map, 4096) == 0); released(4);
  if (trace) fprintf(stderr, "OF_MAPPED bytes=%02x,%02x\n", bytes[0], bytes[1]);
  CHECK(bytes[0] == 'M' && bytes[1] == 'N');
 }
 snprintf(path, sizeof(path), "%s/stream", argv[1]);
 a=open(path, O_RDONLY); CHECK(a >= 0); unsigned id=opened;
 CHECK(lseek(a, 0, SEEK_SET) == -1 && errno == ESPIPE);
 CHECK(pread(a, &c, 1, 0) == -1 && errno == ESPIPE);
 CHECK(read(a, &c, 1) == 1); CHECK(close(a) == 0); released(id);
 snprintf(path, sizeof(path), "%s/duplex", argv[1]);
 a=open(path, O_RDWR); CHECK(a >= 0); id=opened;
 CHECK(sem_init(&stream_waiting, 0, 0) == 0);
 CHECK(sem_init(&stream_sync_started, 0, 0) == 0);
 for (unsigned round = 0; round < 5; round++) {
  CHECK(read(a, &c, 1) == 1 && c == 's');
  CHECK(write(a, "s", 1) == 1);
  stream_duplex(a, 1); stream_duplex(a, 2);
 }
 char shortbuf[3];
 CHECK(read(a, shortbuf, sizeof(shortbuf)) == 1 && shortbuf[0] == 's');
 CHECK(write(a, "ab", 2) == 1);
 CHECK(write(a, "e", 1) == -1 && errno == EIO);
 CHECK(write(a, "z", 1) == 1);
 CHECK(lseek(a, 0, SEEK_SET) == -1 && errno == ESPIPE);
 CHECK(pread(a, &c, 1, 0) == -1 && errno == ESPIPE);
 CHECK(pwrite(a, &c, 1, 0) == -1 && errno == ESPIPE);
 CHECK(close(a) == 0); released(id);
 CHECK(sem_destroy(&stream_waiting) == 0);
 CHECK(sem_destroy(&stream_sync_started) == 0);
 printf("FUSE_STREAM_PASS %s\n", argv[2]);
 snprintf(path, sizeof(path), "%s/new", argv[1]);
 a=open(path, O_CREAT|O_EXCL|O_WRONLY|O_NONBLOCK, 0600); CHECK(a >= 0); id=opened;
 CHECK(write(a, "C", 1) == 1); CHECK(close(a) == 0); released(id);
 CHECK(creates == 1);
 snprintf(path, sizeof(path), "%s/deny", argv[1]);
 CHECK(open(path, O_RDONLY) == -1 && errno == EACCES);
 CHECK(umount2(argv[1], 0) == 0); fuse_session_unmount(se);
 pthread_cancel(thread); CHECK(pthread_join(thread, NULL) == 0);
 for (unsigned i=1; i <= opened; i++) CHECK(handles[i].released == 1);
 fuse_session_destroy(se); fuse_opt_free_args(&args);
 printf("FUSE_OPENFILES_PASS %s %u\n", argv[2], opened);
 return 0;
}
