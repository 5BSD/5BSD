/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * logprobe: a throwaway capability unit for the bsdlog container-model reclaim
 * test.  It enters capability mode (switchboard's readiness boundary) and emits
 * a few records to system.Log, which makes bsdlog map this unit's flat owner key
 * to its bundle ("Test").  Removing the bundle must make bsdlog's reconcile seal
 * that owner and drop it from the owner->bundle map.
 */
#include <sys/capsicum.h>

#include <syslog.h>
#include <unistd.h>

#include <logcmp.h>

int
main(void)
{
	int i;

	if (cap_enter() == -1)
		return (1);
	for (i = 0; i < 3; i++) {
		logcmp_log(LOG_NOTICE, "logprobe: alive %d", i);
		(void)sleep(1);
	}
	for (;;)
		(void)pause();
	return (0);
}
