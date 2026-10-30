/* SPDX-License-Identifier: BSD-2-Clause */
/* Bazel test adapter: compare declared output bytes and normal exit status. */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
required(const char *name)
{
 const char *value = getenv(name);
 if (value == NULL || *value == '\0') { fprintf(stderr, "missing %s\n", name); exit(1); }
 return value;
}
static void
join(char *out, const char *root, const char *leaf)
{
 int n = snprintf(out, PATH_MAX, "%s/%s", root, leaf);
 if (n < 0 || n >= PATH_MAX) { fprintf(stderr, "test path too long\n"); exit(1); }
}
static int
compare_files(const char *actual_path, const char *expected_path)
{
 FILE *a, *b;
 unsigned char abuf[16384], bbuf[16384];
 size_t na, nb;
 a = fopen(actual_path, "rb"); b = fopen(expected_path, "rb");
 if (a == NULL || b == NULL) return (1);
 do {
  na = fread(abuf, 1, sizeof(abuf), a); nb = fread(bbuf, 1, sizeof(bbuf), b);
  if (na != nb || memcmp(abuf, bbuf, na) != 0) {
   fprintf(stderr, "output differs from declared reference\n"); return (1);
  }
 } while (na != 0);
 if (ferror(a) || ferror(b)) return (1);
 fclose(a); fclose(b);
 return (0);
}
int
main(void)
{
 char root[PATH_MAX], program[PATH_MAX], input[PATH_MAX], expected[PATH_MAX];
 char actual[PATH_MAX], libs[PATH_MAX], key[64], leaf[PATH_MAX], *end;
 char **args;
 long count, file_count, expected_exit;
 int compare_stderr, error = -1;
 char actual_stderr[PATH_MAX], expected_stderr[PATH_MAX];
 int in, out, status;
 pid_t child, waited;
 join(root, required("TEST_SRCDIR"), required("TEST_WORKSPACE"));
 join(leaf, "test-program", required("BSD_COMPARE_PROGRAM"));
 join(program, root, leaf);
 join(input, root, "test-data/input");
 join(expected, root, "test-data/expected");
 join(libs, root, "test-runtime/lib");
 join(actual, required("TEST_TMPDIR"), "actual-output");
 join(actual_stderr, required("TEST_TMPDIR"), "actual-stderr");
 join(expected_stderr, root, "test-data/expected-stderr");
 compare_stderr = strcmp(required("BSD_COMPARE_STDERR"), "1") == 0;
 errno = 0; expected_exit = strtol(required("BSD_COMPARE_EXIT"), &end, 10);
 if (errno || *end || expected_exit < 0 || expected_exit > 255) return (1);
 errno = 0; count = strtol(required("BSD_COMPARE_ARGC"), &end, 10);
 if (errno || *end || count < 0 || count > 1024) return (1);
 errno = 0; file_count = strtol(required("BSD_COMPARE_FILE_ARGC"), &end, 10);
 if (errno || *end || file_count < 0 || file_count > 1024) return (1);
 args = calloc((size_t)(count + file_count) + 2, sizeof(*args));
 if (args == NULL) return (1);
 args[0] = program;
 for (long i = 0; i < count; i++) {
  snprintf(key, sizeof(key), "BSD_COMPARE_ARG_%ld", i);
  args[i + 1] = (char *)required(key);
 }
 for (long i = 0; i < file_count; i++) {
  snprintf(leaf, sizeof(leaf), "test-data/argument-%ld", i);
  join(input, root, leaf);
  args[count + i + 1] = strdup(input);
  if (args[count + i + 1] == NULL) return (1);
 }
 join(input, root, "test-data/input");
 if (unsetenv("LD_PRELOAD") != 0 || setenv("LD_LIBRARY_PATH", libs, 1) != 0 || setenv("LC_ALL", "C", 1) != 0) return (1);
 in = open(strcmp(required("BSD_COMPARE_STDIN"), "1") == 0 ? input : "/dev/null", O_RDONLY); out = open(actual, O_WRONLY|O_CREAT|O_EXCL, 0600);
 if (in < 0 || out < 0) { perror("test files"); return (1); }
 if (compare_stderr) {
  error = open(actual_stderr, O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (error < 0) { perror("stderr file"); return (1); }
 }
 child = fork();
 if (child < 0) { perror("fork"); return (1); }
 if (child == 0) {
  const char *workdir = getenv("BSD_COMPARE_WORKDIR");
  if (workdir != NULL && strcmp(workdir, "1") == 0) {
   char directory[PATH_MAX];
   join(directory, root, "test-work");
   if (chdir(directory) != 0) { perror(directory); _exit(126); }
  }
  if (dup2(in, STDIN_FILENO) < 0 || dup2(out, STDOUT_FILENO) < 0) _exit(126);
  if (compare_stderr && dup2(error, STDERR_FILENO) < 0) _exit(126);
  if (error >= 0) close(error);
  close(in); close(out);
  execv(program, args); perror(program); _exit(127);
 }
 close(in); close(out);
 if (error >= 0) close(error);
 do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
 if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != expected_exit) {
  fprintf(stderr, "test program did not return the declared exit status\n"); return (1);
 }
 if (compare_files(actual, expected) != 0) return (1);
 if (compare_stderr && compare_files(actual_stderr, expected_stderr) != 0) return (1);
 for (long i = 0; i < file_count; i++) free(args[count + i + 1]);
 free(args);
 return (0);
}
