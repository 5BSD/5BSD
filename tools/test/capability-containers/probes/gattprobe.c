/*
 * gattprobe: a throwaway unit that opens blued over the capability plane
 * (ble_open_plane: its stamped identity reaches the daemon), registers one
 * local GATT service with the 16-bit UUID named on its command line plus a
 * readable characteristic, records the outcome in its own persistent store
 * ("GATT_REGISTERED <uuid> <handle>" / "GATT_FAILED <uuid> <errno>"), and
 * idles with the connection open.  The container proofs use it to give
 * blued services to attribute to a bundle and reclaim once it is gone.
 *
 * A VM has no Bluetooth adapter and blued exits without one, so the probe
 * first has bsdextension load the Bluetooth netgraph stack and the virtual HCI
 * (the proof's allow-list permits them) and then waits the number of
 * seconds given as its second argument before the first open: the proof
 * creates a virtual controller with vhcitool(8) in that window, so the
 * daemon's first on-demand launch finds an adapter.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ble.h>
#include <libservice.h>

static void
report(int outfd, const char *line)
{
	int fd;

	if (outfd < 0)
		return;
	fd = openat(outfd, "result", O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (fd < 0)
		return;
	(void)write(fd, line, strlen(line));
	(void)close(fd);
}

int
main(int argc, char **argv)
{
	struct service_context *ctx = NULL;
	ble_ctx_t *ble = NULL;
	ble_uuid_t uuid, cuuid;
	char line[128];
	const uint8_t value[2] = { 0x42, 0x24 };
	uint16_t svc = 0, chr = 0;
	unsigned u = 0xfff0;
	int outfd = -1, i;

	static const char *const mods[] = { "ng_socket", "ng_bluetooth",
	    "ng_hci", "ng_l2cap", "ng_btsocket", "ng_hci_virt" };
	unsigned delay = 0, m;

	openlog("gattprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (argc > 1)
		u = (unsigned)strtoul(argv[1], NULL, 16);
	if (argc > 2)
		delay = (unsigned)strtoul(argv[2], NULL, 10);
	if (service_acquire(&ctx) == -1) {
		syslog(LOG_ERR, "gattprobe: service_acquire: %m");
		for (;;)
			(void)pause();
	}
	/* Results in the unit's own persistent store (capmode units cannot syslog). */
	for (i = 0; i < 60; i++) {
		if (service_storage_open(ctx, "state", &outfd) == 0)
			break;
		sleep(1);
	}
	/* The Bluetooth stack and the virtual controller driver, via bsdextension. */
	for (m = 0; m < sizeof(mods) / sizeof(mods[0]); m++) {
		int ok = 0;

		for (i = 0; i < 60 && !ok; i++) {
			if (service_ensure_extension(ctx, mods[m]) == 0)
				ok = 1;
			else if (errno == EPERM || errno == EINVAL)
				break;		/* refused: never going to load */
			else
				sleep(1);	/* provider not up yet */
		}
		if (!ok) {
			(void)snprintf(line, sizeof(line), "MODULE_FAILED %s %d\n",
			    mods[m], errno);
			report(outfd, line);
		}
	}
	report(outfd, "MODULES_DONE\n");
	/* The proof creates the virtual controller in this window. */
	sleep(delay);
	/*
	 * The daemon is activated on demand: fail soft, retry -- slowly, since
	 * every failed launch counts against the supervisor's limit.
	 */
	for (i = 0; i < 12; i++) {
		ble = ble_open_plane();
		if (ble != NULL)
			break;
		sleep(15);
	}
	if (ble == NULL) {
		(void)snprintf(line, sizeof(line), "GATT_FAILED %04x %d\n", u, errno);
		report(outfd, line);
		for (;;)
			(void)pause();
	}
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = (uint16_t)u;
	memset(&cuuid, 0, sizeof(cuuid));
	cuuid.uuid16 = (uint16_t)(u + 1);
	if (ble_add_service(ble, &uuid, &svc) != 0 ||
	    ble_add_characteristic(ble, svc, &cuuid, 0x02 /* read */,
	    0x01 /* readable */, value, sizeof(value), &chr) != 0) {
		(void)snprintf(line, sizeof(line), "GATT_FAILED %04x %d\n", u, errno);
		report(outfd, line);
	} else {
		(void)snprintf(line, sizeof(line), "GATT_REGISTERED %04x %04x\n",
		    u, svc);
		report(outfd, line);
	}
	for (;;)
		(void)pause();
	return (0);
}
