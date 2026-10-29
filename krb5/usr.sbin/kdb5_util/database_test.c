/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *message)
{
    fprintf(stderr, "%s: %s\n", message, strerror(errno));
    exit(1);
}
static void run(char *const argv[], const char *expected)
{
    FILE *capture = tmpfile();
    if (!capture) fail("capture");
    pid_t pid = fork();
    if (pid < 0) fail("fork");
    if (pid == 0) {
        alarm(20);
        if (dup2(fileno(capture), 1) < 0 || dup2(fileno(capture), 2) < 0) _exit(125);
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    pid_t ended;
    do { ended = waitpid(pid, &status, 0); } while (ended < 0 && errno == EINTR);
    if (ended != pid) fail("wait");
    rewind(capture);
    char output[32768];
    size_t n = fread(output, 1, sizeof(output) - 1, capture);
    output[n] = 0;
    if (ferror(capture) || !feof(capture)) fail("capture overflow/read");
    fclose(capture);
    if (!WIFEXITED(status) || WEXITSTATUS(status) || (expected && !strstr(output, expected))) {
        fprintf(stderr, "command %s status %d; expected %s\n%s", argv[0], status, expected ? expected : "success", output);
        exit(1);
    }
}
int main(int argc, char **argv)
{
    char utility[PATH_MAX], admin[PATH_MAX], plugin[PATH_MAX], path[PATH_MAX], work[PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc < 5 || !tmp || !realpath(argv[1], utility) || !realpath(argv[2], admin) || !realpath(argv[3], plugin)) fail("inputs");
    size_t cap = (size_t)argc * PATH_MAX;
    char *libs = calloc(cap, 1);
    if (!libs) fail("allocation");
    for (int i = 4; i < argc; ++i) {
        if (!realpath(argv[i], path)) fail("library");
        char *slash = strrchr(path, '/');
        if (!slash) fail("library path");
        *slash = 0;
        if (strlcat(libs, i == 4 ? "" : ":", cap) >= cap || strlcat(libs, path, cap) >= cap) fail("path overflow");
    }
    if (snprintf(work, sizeof(work), "%s/database.XXXXXX", tmp) >= (int)sizeof(work) || !mkdtemp(work) || chdir(work)) fail("work directory");
    /* Unique module name prevents loading an installed system DB2 fallback. */
    if (symlink(plugin, "bazel_test_db2.so")) fail("plugin symlink");
    FILE *conf = fopen("krb5.conf", "w");
    if (!conf) fail("config");
    fprintf(conf, "[libdefaults]\n default_realm = EXAMPLE.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n[realms]\n EXAMPLE.TEST = {\n database_module = testdb\n key_stash_file = %s/stash\n }\n[dbmodules]\n db_module_dir = %s\n testdb = {\n db_library = bazel_test_db2\n database_name = %s/database\n }\n", work, work, work);
    if (fclose(conf)) fail("config close");
    if (snprintf(path, sizeof(path), "%s/krb5.conf", work) >= (int)sizeof(path)) fail("config path");
    if (setenv("KRB5_CONFIG", path, 1) || setenv("KRB5_KDC_PROFILE", "/dev/null", 1) || setenv("LD_LIBRARY_PATH", libs, 1) || setenv("HOME", work, 1) || setenv("LC_ALL", "C", 1) || setenv("PATH", "/nonexistent", 1)) fail("environment");
    free(libs);
    run((char *[]){utility, "create", "-s", "-P", "disposable-test-master-password", NULL}, NULL);
    run((char *[]){admin, "-q", "addprinc -randkey test@EXAMPLE.TEST", NULL}, "created");
    run((char *[]){admin, "-q", "getprinc test@EXAMPLE.TEST", NULL}, "Principal: test@EXAMPLE.TEST");
    run((char *[]){utility, "dump", "database.dump", NULL}, NULL);
    run((char *[]){utility, "-d", "restored", "load", "database.dump", NULL}, NULL);
    /* Prove restored queries do not silently use the original database. */
    run((char *[]){admin, "-q", "delprinc -force test@EXAMPLE.TEST", NULL}, "deleted");
    run((char *[]){admin, "-d", "restored", "-q", "getprinc test@EXAMPLE.TEST", NULL}, "Principal: test@EXAMPLE.TEST");
    DIR *dir = opendir(".");
    if (!dir) fail("cleanup open");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (unlink(entry->d_name)) fail("cleanup file");
    }
    closedir(dir);
    if (chdir(tmp) || rmdir(work)) fail("cleanup directory");
    return 0;
}
