/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test-only bhyve IPC controller for the bhyvectl suite: listens on
 * RUNDIR/VMNAME and answers each nvlist request according to the reply mode
 * currently stored in MODEFILE, appending what it received to LOGFILE.
 *
 * Modes: pid, pid-missing, error, ok, repair-ok, repair-false, repair-stuck,
 * close (drop the connection without replying).
 */
#include <sys/types.h>
#include <sys/nv.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int listener;

	if (argc != 5)
		errx(2, "usage: rundir vmname modefile logfile");
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", argv[1], argv[2]);
	addr.sun_len = SUN_LEN(&addr);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0 || bind(listener, (struct sockaddr *)&addr, addr.sun_len) != 0 ||
	    listen(listener, 8) != 0)
		err(2, "listen");
	printf("ready\n");
	fflush(stdout);
	for (;;) {
		char mode[64] = "";
		nvlist_t *request, *reply;
		FILE *log, *modef;
		int client;

		client = accept(listener, NULL, NULL);
		if (client < 0)
			err(2, "accept");
		modef = fopen(argv[3], "r");
		if (modef != NULL) {
			if (fgets(mode, sizeof(mode), modef) == NULL)
				mode[0] = '\0';
			fclose(modef);
			mode[strcspn(mode, "\n")] = '\0';
		}
		request = nvlist_recv(client, 0);
		log = fopen(argv[4], "a");
		if (log == NULL)
			err(2, "log");
		if (request == NULL) {
			fprintf(log, "request unreadable\n");
		} else {
			fprintf(log, "cmd=%s", nvlist_exists_string(request, "cmd") ?
			    nvlist_get_string(request, "cmd") : "(none)");
			if (nvlist_exists_string(request, "filename"))
				fprintf(log, " filename=%s",
				    nvlist_get_string(request, "filename"));
			if (nvlist_exists_bool(request, "suspend"))
				fprintf(log, " suspend=%d",
				    nvlist_get_bool(request, "suspend"));
			if (nvlist_exists_string(request, "action"))
				fprintf(log, " action=%s",
				    nvlist_get_string(request, "action"));
			static const char *const flags[] = { "source_retired",
			    "acknowledge_loss", "plaintext_unix" };
			for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++)
				if (nvlist_exists_bool(request, flags[i]))
					fprintf(log, " %s=%d", flags[i],
					    nvlist_get_bool(request, flags[i]));
			if (nvlist_exists_descriptor(request, "fddir")) {
				struct stat st;
				int fd = nvlist_get_descriptor(request, "fddir");
				fprintf(log, " fddir-is-dir=%d",
				    fstat(fd, &st) == 0 && S_ISDIR(st.st_mode));
			}
			fprintf(log, " mode=%s\n", mode);
		}
		fclose(log);
		if (strcmp(mode, "close") == 0 || request == NULL) {
			close(client);
			nvlist_destroy(request);
			continue;
		}
		reply = nvlist_create(0);
		if (strcmp(mode, "pid") == 0)
			nvlist_add_number(reply, "pid", 4242);
		else if (strcmp(mode, "error") == 0)
			nvlist_add_string(reply, "error", "controller refused");
		else if (strcmp(mode, "repair-ok") == 0) {
			nvlist_add_bool(reply, "repaired", true);
			nvlist_add_bool(reply, "source_runnable", true);
		} else if (strcmp(mode, "repair-false") == 0) {
			nvlist_add_bool(reply, "repaired", false);
			nvlist_add_bool(reply, "source_runnable", true);
		} else if (strncmp(mode, "migrate-", 8) == 0 ||
		    strncmp(mode, "recover-", 8) == 0) {
			/* migrate-R-P-S / recover-R-C: source_runnable R, phase P,
			 * reason S, confirmed C; '-' omits, 'x' for absent keys. */
			const char *f = mode + 8;
			if (f[0] != 'x')
				nvlist_add_bool(reply, "source_runnable", f[0] == '1');
			if (mode[0] == 'm' && strlen(f) >= 5) {
				if (f[2] != 'x')
					nvlist_add_number(reply, "phase", f[2] - '0');
				if (f[4] != 'x')
					nvlist_add_number(reply, "reason", f[4] - '0');
			} else if (strlen(f) >= 3 && f[2] != 'x')
				nvlist_add_bool(reply, "confirmed", f[2] == '1');
		} else if (strncmp(mode, "resolve-", 8) == 0) {
			/* resolve-R-T[-C]: resolved R, retained T ('x' omits),
			 * optional error_code C. */
			const char *f = mode + 8;
			if (f[0] != 'x')
				nvlist_add_bool(reply, "resolved", f[0] == '1');
			if (strlen(f) >= 3 && f[2] != 'x')
				nvlist_add_bool(reply, "retained", f[2] == '1');
			if (strlen(f) >= 5)
				nvlist_add_number(reply, "error_code",
				    strtoull(f + 4, NULL, 10));
		} else if (strcmp(mode, "repair-stuck") == 0) {
			nvlist_add_bool(reply, "repaired", true);
			nvlist_add_bool(reply, "source_runnable", false);
		}
		(void)nvlist_send(client, reply);
		nvlist_destroy(reply);
		nvlist_destroy(request);
		close(client);
	}
}
