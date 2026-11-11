/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The helper image of the boundary pins (procnet_boundary_test,
 * procnet_outside_test, procnet_ipcs_test).  A target must have exec'd
 * after it changed its credentials: P_SUGID, which setuid(2) sets, makes
 * p_candebug() refuse an unprivileged actor with EPERM and would hide the
 * results the pins are about.
 *
 *   pause [notrace]   write "<pid> <tid>\n" to descriptor 1, then read
 *                     descriptor 0 to end of file and exit 0.  With
 *                     "notrace", PROC_TRACE_CTL_DISABLE first (P2_NOTRACE).
 *   as UID GID CMD... setgroups, setgid and setuid, then exec CMD.
 *   ipcmk             make a System V segment, semaphore set and message
 *                     queue (IPC_PRIVATE, mode 0666) and print their ids.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/procctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/thr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char buf[64];
	gid_t gid;
	long tid;
	int len, msq, sem, shm, v;

	if (argc >= 5 && strcmp(argv[1], "as") == 0) {
		gid = (gid_t)atoi(argv[3]);
		if (setgroups(1, &gid) != 0 || setgid(gid) != 0 ||
		    setuid((uid_t)atoi(argv[2])) != 0)
			return (68);
		(void)execv(argv[4], argv + 4);
		return (69);
	}
	if (argc == 2 && strcmp(argv[1], "ipcmk") == 0) {
		shm = shmget(IPC_PRIVATE, 4096, 0666);
		sem = semget(IPC_PRIVATE, 1, 0666);
		msq = msgget(IPC_PRIVATE, 0666);
		if (shm == -1 || sem == -1 || msq == -1)
			return (70);
		printf("%d %d %d\n", shm, sem, msq);
		return (0);
	}
	if (argc < 2 || strcmp(argv[1], "pause") != 0)
		return (64);
	if (argc > 2) {
		if (strcmp(argv[2], "notrace") != 0)
			return (64);
		v = PROC_TRACE_CTL_DISABLE;
		if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &v) != 0)
			return (65);
	}
	if (thr_self(&tid) != 0)
		return (66);
	len = snprintf(buf, sizeof(buf), "%d %ld\n", (int)getpid(), tid);
	if (write(1, buf, (size_t)len) != len)
		return (67);
	while (read(0, buf, sizeof(buf)) > 0)
		continue;
	return (0);
}
