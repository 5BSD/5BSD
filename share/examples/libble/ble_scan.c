/*
 * ble_scan.c — scan for nearby BLE devices using libble.
 *
 * Usage: ble_scan
 *
 * Connects to blued, runs a scan, prints results, and exits.
 */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <ble.h>

static void
on_device(const ble_scan_result_t *r, void *arg __unused)
{
	char buf[18];

	printf("  %s  %s  rssi=%-4d  mfr=0x%04X",
	    ble_addr_str(&r->addr, buf),
	    r->addr.addr_type ? "random" : "public",
	    r->rssi, r->mfr_id);
	if (r->name[0] != '\0')
		printf("  name=%s", r->name);
	if (r->num_svc_uuids > 0) {
		printf("  svcs=");
		for (int i = 0; i < r->num_svc_uuids; i++)
			printf("%s0x%04X", i ? "," : "",
			    r->svc_uuids[i].uuid16);
	}
	printf("\n");
}

int
main(void)
{
	ble_ctx_t *ctx;
	struct pollfd pfd;

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	printf("Scanning for BLE devices...\n");
	if (ble_scan(ctx, on_device, NULL) < 0) {
		fprintf(stderr, "ble_scan: failed\n");
		ble_close(ctx);
		return (1);
	}

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 10000) > 0) {
		if (ble_process(ctx) < 0)
			break;
	}

	ble_close(ctx);
	return (0);
}
