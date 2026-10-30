/* SPDX-License-Identifier: BSD-2-Clause */
/* Executed by the real NSS child setup. Check state in an executable
 * constructor, before the main request loop. Does not claim to inspect every
 * shared-library constructor or to establish a nonempty parent authority. */
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/procctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "nss_protocol.h"
extern char **environ;
static bool clean;
static void __attribute__((constructor))
inspect_startup(void)
{
	struct cap_authority_info authority;
	struct mac_cap_process_info process;
	int state;
	if (environ == NULL || environ[0] != NULL ||
	    procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS, &state) == -1 ||
	    state != PROC_NO_NEW_PRIVS_ENABLE ||
	    syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &authority) == -1 ||
	    authority.identity != 0 ||
	    syscall(SYS_cap_process, MAC_CAP_PROCESS_INFO, -1, 0, &process) == -1 ||
	    process.present != 0) return;
	/* The test deliberately installs a non-CLOEXEC marker at fd 128. */
	for (int fd = 3; fd <= 128; fd++) {
		errno = 0;
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return;
	}
	clean = true;
}
void
sb_nss_lookup(const struct sb_nss_request *request, struct sb_nss_reply *reply)
{
	memset(reply, 0, sizeof(*reply));
	reply->version = SB_NSS_VERSION;
	if (!clean || sb_nss_request_valid(request) == -1) {
		reply->error = EPERM;
		return;
	}
	/* Kernel-fixture mode: attempt a second exec of its registered image.
	 * The image's test entry point returns the protocol reply only if it
	 * still has no authority. The path is fixture input, not production policy. */
	if (request->operation == SB_NSS_USER_NAME && request->name[0] == '/') {
		char mode[] = "--nss-unprivileged";
		char *const argv[] = { __DECONST(char *, request->name), mode, NULL };
		char *const env[] = { NULL };
		execve(request->name, argv, env);
		reply->error = errno;
		return;
	}
	if (request->operation != SB_NSS_USER_UID) {
		reply->error = EINVAL;
		return;
	}
	reply->uid = request->id;
	strlcpy(reply->name, "isolation-probe", sizeof(reply->name));
}
