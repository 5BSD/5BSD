/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pid_t daemon_pid = -1;
static void stop_daemon(void)
{
    if (daemon_pid > 0) {
        kill(daemon_pid, SIGKILL);
        while (waitpid(daemon_pid, NULL, 0) < 0 && errno == EINTR) {}
        daemon_pid = -1;
    }
}
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
    int first_library = 4;
    char clients[5][PATH_MAX];
    int network = argc > 4 && !strcmp(argv[4], "--kdc");
    if (network) {
        if (argc < 11) fail("KDC inputs");
        for (int i = 0; i < 5; i++) if (!realpath(argv[5+i], clients[i])) fail("KDC program");
        first_library = 10;
    }
    if (atexit(stop_daemon)) fail("cleanup registration");
    size_t cap = (size_t)argc * PATH_MAX;
    char *libs = calloc(cap, 1);
    if (!libs) fail("allocation");
    for (int i = first_library; i < argc; ++i) {
        if (!realpath(argv[i], path)) fail("library");
        char *slash = strrchr(path, '/');
        if (!slash) fail("library path");
        *slash = 0;
        if (strlcat(libs, i == first_library ? "" : ":", cap) >= cap || strlcat(libs, path, cap) >= cap) fail("path overflow");
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
    if (network) {
        run((char *[]){admin, "-q", "addprinc -randkey client@EXAMPLE.TEST", NULL}, "created");
        run((char *[]){admin, "-q", "ktadd -k client.keytab client@EXAMPLE.TEST", NULL}, "added to keytab");
        run((char *[]){admin, "-q", "addprinc -randkey host/test.example.test@EXAMPLE.TEST", NULL}, "created");
        /* Ask the kernel for an available loopback TCP port; startup must
         * fail if another process takes it before the KDC binds. */
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = { .sin_len = sizeof(addr), .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        socklen_t len = sizeof(addr);
        if (sock < 0 || bind(sock, (struct sockaddr *)&addr, sizeof(addr)) || getsockname(sock, (struct sockaddr *)&addr, &len)) fail("loopback port");
        unsigned port = ntohs(addr.sin_port);
        conf = fopen("krb5.conf", "a");
        if (!conf) fail("KDC config");
        fprintf(conf, "\n[realms]\n EXAMPLE.TEST = {\n kdc = 127.0.0.1:%u\n }\n[kdcdefaults]\n kdc_listen = \"\"\n kdc_tcp_listen = 127.0.0.1:%u\n[logging]\n kdc = FILE:%s/kdc.log\n", port, port, work);
        if (fclose(conf) || setenv("KRB5_KDC_PROFILE", path, 1)) fail("KDC config close");
        int log = open("daemon.log", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (log < 0) fail("daemon log");
        close(sock);
        daemon_pid = fork();
        if (daemon_pid < 0) fail("daemon fork");
        if (daemon_pid == 0) {
            alarm(40);
            if (dup2(log, 1) < 0 || dup2(log, 2) < 0) _exit(125);
            close(log);
            execl(clients[0], clients[0], "-n", (char *)NULL);
            _exit(127);
        }
        char output[8192];
        int ready = 0;
        for (int i = 0; i < 100; i++) {
            ssize_t n = pread(log, output, sizeof(output)-1, 0);
            if (n < 0) fail("daemon log read");
            output[n] = 0;
            if (strstr(output, "starting...")) { ready = 1; break; }
            if (waitpid(daemon_pid, NULL, WNOHANG) == daemon_pid) {
                daemon_pid = -1;
                fprintf(stderr, "%s", output); fail("daemon early exit");
            }
            struct timespec pause = { .tv_nsec = 100000000 };
            nanosleep(&pause, NULL);
        }
        close(log);
        if (!ready) { fprintf(stderr, "%s", output); fail("daemon readiness"); }
        run((char *[]){clients[1], "-k", "-t", "client.keytab", "-c", "FILE:client.ccache", "client@EXAMPLE.TEST", NULL}, NULL);
        run((char *[]){clients[2], "-c", "FILE:client.ccache", "host/test.example.test@EXAMPLE.TEST", NULL}, "kvno =");
        run((char *[]){clients[3], "-c", "FILE:client.ccache", NULL}, "host/test.example.test@EXAMPLE.TEST");
        run((char *[]){clients[4], "-c", "FILE:client.ccache", NULL}, NULL);
        if (access("client.ccache", F_OK) == 0 || errno != ENOENT) fail("cache destruction");
        stop_daemon();
    }
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
