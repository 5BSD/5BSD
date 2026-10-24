/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/sbuf.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
 fprintf(stderr, "sbuf check failed at line %d: %s\n", __LINE__, #test); \
 return (4); } } while (0)
#define LOAD(name) __typeof__(&name) call_##name = \
 (__typeof__(&name))resolve(handle, #name, library); CHECK(call_##name != NULL)

static void *
resolve(void *handle, const char *name, const char *expected)
{
 Dl_info info;
 char actual[PATH_MAX];
 void *symbol = dlvsym(handle, name, "FBSD_1.2");
 if (symbol == NULL || dladdr(symbol, &info) == 0 || info.dli_fname == NULL ||
     realpath(info.dli_fname, actual) == NULL || strcmp(actual, expected) != 0) {
  fprintf(stderr, "incorrect versioned provider for %s\n", name);
  return (NULL);
 }
 return (symbol);
}

struct sink { char data[128]; size_t length; unsigned calls; };
static int
drain(void *arg, const char *data, int length)
{
 struct sink *sink = arg;
 /* Consume only three bytes to exercise repeated partial drains. */
 size_t n = length > 3 ? 3 : (size_t)length;
 if (n > sizeof(sink->data) - sink->length)
  return (-ENOSPC);
 memcpy(sink->data + sink->length, data, n);
 sink->length += n;
 sink->calls++;
 return ((int)n);
}
static int
fail_drain(void *arg, const char *data, int length)
{
 (void)arg; (void)data; (void)length;
 return (-EIO);
}

int
main(int argc, char **argv)
{
 char library[PATH_MAX], payload[4097], fixed[8];
 struct sink sink = {0};
 struct sbuf *s;
 void *handle;
 if (argc != 2 || argv[1][0] != '/')
  return (1);
 handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
 if (handle == NULL) {
  fprintf(stderr, "dlopen %s: %s\n", argv[1], dlerror());
  return (2);
 }
 CHECK(realpath(argv[1], library) != NULL);
 LOAD(sbuf_new); LOAD(sbuf_cat); LOAD(sbuf_printf); LOAD(sbuf_finish);
 LOAD(sbuf_data); LOAD(sbuf_len); LOAD(sbuf_done); LOAD(sbuf_error);
 LOAD(sbuf_delete); LOAD(sbuf_clear); LOAD(sbuf_set_drain);
 memset(payload, 'x', sizeof(payload) - 1);
 payload[sizeof(payload) - 1] = '\0';
 s = call_sbuf_new(NULL, NULL, 2, SBUF_AUTOEXTEND);
 CHECK(s != NULL);
 CHECK(call_sbuf_cat(s, payload) == 0);
 CHECK(call_sbuf_printf(s, ":%d:%s", -17, "ok") == 0);
 CHECK(call_sbuf_finish(s) == 0 && call_sbuf_done(s));
 CHECK(call_sbuf_error(s) == 0 && call_sbuf_len(s) == 4103);
 CHECK(memcmp(call_sbuf_data(s), payload, 4096) == 0);
 CHECK(strcmp(call_sbuf_data(s) + 4096, ":-17:ok") == 0);
 call_sbuf_clear(s);
 CHECK(!call_sbuf_done(s));
 CHECK(call_sbuf_cat(s, "reuse") == 0 && call_sbuf_finish(s) == 0);
 CHECK(call_sbuf_len(s) == 5 && strcmp(call_sbuf_data(s), "reuse") == 0);
 call_sbuf_delete(s);
 s = call_sbuf_new(NULL, fixed, sizeof(fixed), SBUF_FIXEDLEN);
 CHECK(s != NULL);
 CHECK(call_sbuf_cat(s, payload) == -1 && call_sbuf_error(s) == ENOMEM);
 errno = 0;
 CHECK(call_sbuf_finish(s) == -1 && errno == ENOMEM);
 call_sbuf_clear(s);
 CHECK(call_sbuf_error(s) == 0);
 CHECK(call_sbuf_cat(s, "ok") == 0 && call_sbuf_finish(s) == 0);
 CHECK(strcmp(call_sbuf_data(s), "ok") == 0);
 call_sbuf_delete(s);
 s = call_sbuf_new(NULL, fixed, sizeof(fixed), SBUF_FIXEDLEN);
 CHECK(s != NULL);
 call_sbuf_set_drain(s, drain, &sink);
 CHECK(call_sbuf_cat(s, "abcdefghijklmnopqrstuvwxyz") == 0);
 CHECK(call_sbuf_finish(s) == 0 && sink.calls > 1 && sink.length == 26);
 CHECK(memcmp(sink.data, "abcdefghijklmnopqrstuvwxyz", 26) == 0);
 call_sbuf_delete(s);
 s = call_sbuf_new(NULL, fixed, sizeof(fixed), SBUF_FIXEDLEN);
 CHECK(s != NULL);
 call_sbuf_set_drain(s, fail_drain, NULL);
 CHECK(call_sbuf_cat(s, "abc") == 0);
 errno = 0;
 CHECK(call_sbuf_finish(s) == -1 && errno == EIO && call_sbuf_error(s) == EIO);
 call_sbuf_delete(s);
 CHECK(dlclose(handle) == 0);
 puts("sbuf-runtime: ok");
 return (0);
}
