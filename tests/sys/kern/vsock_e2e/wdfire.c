/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * wdfire -- 5BSD guest helper that arms the platform watchdog(4) through
 * /dev/fido and, only when told to, lets it lapse so the host i6300esb model
 * applies its configured action.
 *
 * The 5BSD guest base ships watchdogd(8) but no one-shot `watchdog` arm CLI and
 * no python3, so the Alpine lane's gnonvirtio.py watchdog helper cannot run
 * here.  This mirrors that helper's watchdog_freebsd() path in C:
 *
 *   - open /dev/fido;
 *   - WDIOC_SETTIMEOUT with an sbintime_t timeout to arm the timer (this drives
 *     the in-guest i6300esbwd(4) driver, which programs the emulated
 *     8086:25ab watchdog function -- the ioctl returns 0 only if a hardware
 *     watchdog actually responded, so success proves the arm reached the model);
 *   - WDIOC_GETTIMEOUT to confirm a positive programmed timeout;
 *   - pat once (a second WDIOC_SETTIMEOUT) to prove the keepalive path.
 *
 * By default (non-destructive) it then DISABLES the timer via WDIOC_CONTROL so
 * it can never lapse, and exits.  Closing /dev/fido does not disarm the
 * watchdog, so the explicit disable is required.
 *
 * When WATCHDOG_EXPECT_RESET=1 (or a single "fire" argument) it instead stops
 * patting and sleeps past the two-stage lapse.  bhyve is configured
 * action=notify, so the host merely logs
 *   i6300esb: watchdog expired, applying action "notify"
 * and the guest survives for the runner to observe on the host log.
 *
 * An sbintime_t encodes whole seconds as (seconds << 32); see SBT_1S in
 * <sys/time.h>.  The device path defaults to /dev/fido.
 */

#include <sys/types.h>
#include <sys/_types.h>
#include <sys/ioctl.h>
#include <sys/watchdog.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* One second as an sbintime_t: whole seconds live in the upper 32 bits. */
#define	WDFIRE_SBT_1S	((sbintime_t)1 << 32)

/*
 * Short lapse target for the destructive case so a live observation does not
 * stall the lab; the emulated timer is two-stage, so the host action lands near
 * 2x this value.  The non-destructive case arms a longer timer that it always
 * disables before it can lapse.
 */
#define	WDFIRE_FIRE_SECONDS	2
#define	WDFIRE_ARM_SECONDS	8

static int
env_expect_reset(void)
{
	const char *value = getenv("WATCHDOG_EXPECT_RESET");

	return (value != NULL && strcmp(value, "0") != 0 && value[0] != '\0');
}

int
main(int argc, char **argv)
{
	const char *node = "/dev/fido";
	sbintime_t sbt, total;
	int fd, expect_reset, seconds, ctrl;

	expect_reset = env_expect_reset();

	if (argc > 1 && strcmp(argv[1], "fire") == 0) {
		expect_reset = 1;
		argc--;
		argv++;
	}
	if (argc > 1)
		node = argv[1];

	seconds = expect_reset ? WDFIRE_FIRE_SECONDS : WDFIRE_ARM_SECONDS;
	sbt = (sbintime_t)seconds * WDFIRE_SBT_1S;

	fd = open(node, O_RDWR);
	if (fd < 0)
		err(1, "open %s", node);

	/*
	 * Arm the timer.  WDIOC_SETTIMEOUT both sets the timeout and pats, and
	 * returns non-zero if no hardware watchdog responded, so a 0 return is
	 * itself evidence that the emulated i6300esb accepted the arm.
	 */
	if (ioctl(fd, WDIOC_SETTIMEOUT, &sbt) != 0)
		err(1, "WDIOC_SETTIMEOUT arm on %s", node);

	total = 0;
	if (ioctl(fd, WDIOC_GETTIMEOUT, &total) != 0)
		err(1, "WDIOC_GETTIMEOUT on %s", node);
	if (total <= 0)
		errx(1, "%s reports a non-positive timeout", node);

	if (!expect_reset) {
		/* Pat once more to prove the keepalive path, then disable so the
		 * timer can never lapse. */
		if (ioctl(fd, WDIOC_SETTIMEOUT, &sbt) != 0)
			err(1, "WDIOC_SETTIMEOUT pat on %s", node);
		ctrl = WD_CTRL_DISABLE;
		if (ioctl(fd, WDIOC_CONTROL, &ctrl) != 0)
			err(1, "WDIOC_CONTROL disable on %s", node);
		(void)close(fd);
		printf("wdfire: node=%s timeout=%d armed=yes fired=no\n",
		    node, seconds);
		return (0);
	}

	/*
	 * Destructive lane: stop patting and let it lapse.  Do NOT disable the
	 * timer.  action=notify keeps the guest alive for the runner to observe
	 * on the host log.
	 */
	(void)close(fd);
	fflush(stdout);
	sleep((unsigned)(seconds * 3 + 10));
	printf("wdfire: node=%s timeout=%d armed=yes fired=expected\n",
	    node, seconds);
	return (0);
}
