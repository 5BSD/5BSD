/* SPDX-License-Identifier: BSD-2-Clause */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *
runfile(const char *name)
{
 const char *root = getenv("TEST_SRCDIR"), *workspace = getenv("TEST_WORKSPACE");
 char *path;
 if (root == NULL || workspace == NULL || name[0] == '/')
  errx(126, "invalid runfiles input");
 if (asprintf(&path, "%s/%s/%s", root, workspace, name) < 0)
  err(126, "asprintf");
 if (access(path, R_OK) != 0)
  err(126, "%s", path);
 return path;
}
int
main(int argc, char **argv)
{
 char *loader, *program, *script, *libs = NULL, *next, *path, *slash;
 char **args;
 const char *tmp = getenv("TEST_TMPDIR");
 int i, n = 0, split;
 if (argc < 7 || tmp == NULL) errx(126, "missing test inputs");
 loader = runfile(argv[1]); program = runfile(argv[2]); script = runfile(argv[3]);
 for (split = 5; split < argc && strcmp(argv[split], "--") != 0; split++) {
  path = runfile(argv[split]); slash = strrchr(path, '/'); *slash = '\0';
  if (asprintf(&next, "%s%s%s", libs == NULL ? "" : libs,
      libs == NULL ? "" : ":", path) < 0) err(126, "asprintf");
  free(libs); free(path); libs = next;
 }
 if (libs == NULL || split == argc || (argc-split-1)%2 != 0)
  errx(126, "invalid library/module inputs");
 args = calloc((size_t)argc + 3, sizeof(*args));
 if (args == NULL) err(126, "calloc");
 args[n++] = loader; args[n++] = program; args[n++] = "-E";
 args[n++] = script; args[n++] = argv[4];
 for (i = split+1; i < argc; i += 2) {
  args[n++] = argv[i]; args[n++] = runfile(argv[i+1]);
 }
 if (clearenv() != 0 || setenv("LD_LIBRARY_PATH", libs, 1) != 0 ||
     setenv("LC_ALL", "C", 1) != 0 || chdir(tmp) != 0)
  err(126, "test environment");
 execv(loader, args); err(127, "%s", loader);
}
