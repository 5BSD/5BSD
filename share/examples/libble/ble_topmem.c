/*
 * ble_topmem.c — advertise top 5 processes by RAM usage via BLE.
 *
 * Usage: ble_topmem
 *
 * Creates a custom GATT service (UUID 0xFFC0) with a single
 * read/notify characteristic (UUID 0xFFC1) containing a UTF-8
 * snapshot of the top 5 processes by resident set size.
 *
 * Updates every 10 seconds.  A BLE central can connect and read
 * the characteristic or subscribe for live updates.
 *
 * Build:
 *   cc -o ble_topmem ble_topmem.c -lble -lbluetooth
 */

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ble.h>

#define UPDATE_INTERVAL_SEC	10
#define TOPMEM_SVC_UUID		0xFFC0
#define TOPMEM_CHAR_UUID	0xFFC1
#define ATT_MAX_VALUE		244	/* conservative ATT_MTU - 3 */

static volatile sig_atomic_t running = 1;
static uint16_t char_handle;

static void
sigint(int sig __unused)
{

	running = 0;
}

/*
 * Get top 5 processes by RSS using ps(1).
 * Output fits within ATT_MAX_VALUE bytes for a single read.
 */
static int
get_top_procs(char *buf, size_t buflen)
{
	FILE *fp;
	char line[128];
	int count;
	size_t off;

	fp = popen("ps -axo rss=,comm= --libxo:J 2>/dev/null || "
	    "ps -axo rss=,comm= | sort -rn | head -5", "r");
	if (fp == NULL)
		return (-1);

	off = 0;
	count = 0;
	while (fgets(line, sizeof(line), fp) != NULL && count < 5) {
		unsigned long rss;
		char comm[64];
		int n;

		line[strcspn(line, "\n\r")] = '\0';

		/* ps output: "  RSS COMMAND" */
		if (sscanf(line, "%lu %63s", &rss, comm) != 2)
			continue;

		/* Format: "123M procname\n" */
		n = snprintf(buf + off, buflen - off,
		    "%luM %s\n", rss / 1024, comm);
		if (n < 0 || (size_t)n >= buflen - off)
			break;
		off += (size_t)n;
		count++;
	}
	pclose(fp);

	/* Trim trailing newline */
	if (off > 0 && buf[off - 1] == '\n')
		buf[--off] = '\0';

	return (count > 0 ? 0 : -1);
}

int
main(void)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	uint16_t svc_handle;
	struct pollfd pfd;
	time_t last_update;
	char procbuf[ATT_MAX_VALUE];

	signal(SIGINT, sigint);

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	/* Create service */
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = TOPMEM_SVC_UUID;
	if (ble_add_service(ctx, &uuid, &svc_handle) < 0) {
		fprintf(stderr, "Failed to add service\n");
		ble_close(ctx);
		return (1);
	}

	/* Process list characteristic: read + notify */
	uuid.uuid16 = TOPMEM_CHAR_UUID;
	ble_add_characteristic(ctx, svc_handle, &uuid,
	    BLE_PROP_READ | BLE_PROP_NOTIFY, BLE_PERM_READ,
	    NULL, 0, &char_handle);

	/* Process initial responses */
	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) > 0)
		ble_process(ctx);

	printf("Top-memory service running (Ctrl-C to stop)\n");
	printf("Service UUID: 0x%04X\n", TOPMEM_SVC_UUID);
	printf("  Process list: 0x%04X (read, notify)\n", TOPMEM_CHAR_UUID);
	printf("  Updates every %d seconds\n", UPDATE_INTERVAL_SEC);

	last_update = 0;

	while (running) {
		time_t now;

		now = time(NULL);
		if (now - last_update >= UPDATE_INTERVAL_SEC) {
			if (get_top_procs(procbuf, sizeof(procbuf)) == 0) {
				printf("\n--- Top 5 by RAM ---\n%s\n",
				    procbuf);

				ble_set_value(ctx, char_handle,
				    (const uint8_t *)procbuf,
				    (uint16_t)strlen(procbuf));
			}
			last_update = now;
		}

		if (poll(&pfd, 1, 2000) > 0)
			ble_process(ctx);
	}

	printf("\nCleaning up...\n");
	ble_remove_service(ctx, svc_handle);
	ble_close(ctx);
	return (0);
}
