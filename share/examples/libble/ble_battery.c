/*
 * ble_battery.c — read battery level from a connected BLE device.
 *
 * Usage: ble_battery <addr>
 *
 * Connects to the device, reads its battery level, and prints it.
 */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ble.h>

static int done;

static void
on_connect(const ble_addr_t *addr, int error, void *arg)
{
	ble_ctx_t *ctx = arg;

	if (error != 0) {
		fprintf(stderr, "Connection failed\n");
		done = 1;
		return;
	}
	printf("Connected, reading battery...\n");
	ble_read_battery(ctx, addr, on_battery, NULL);
}

static void
on_battery(const ble_addr_t *addr __unused, uint16_t handle __unused,
    const uint8_t *value, uint16_t len, int error, void *arg __unused)
{

	if (error != 0 || len == 0) {
		fprintf(stderr, "Battery read failed\n");
	} else {
		printf("Battery level: %d%%\n", value[0]);
	}
	done = 1;
}

int
main(int argc, char *argv[])
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	struct pollfd pfd;
	bdaddr_t ba;

	if (argc < 2) {
		fprintf(stderr, "usage: ble_battery <addr>\n");
		return (1);
	}

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	memset(&addr, 0, sizeof(addr));
	if (bt_aton(argv[1], &ba))
		memcpy(addr.addr, &ba, 6);
	addr.addr_type = 1;	/* random — most common for peripherals */

	/* Register battery callback first, then connect */
	/* The read_cb is set by ble_read_battery inside on_connect */
	ble_connect(ctx, &addr, on_connect, ctx);

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	while (!done && poll(&pfd, 1, 15000) > 0) {
		if (ble_process(ctx) < 0)
			break;
	}

	ble_disconnect(ctx, &addr);
	ble_close(ctx);
	return (0);
}
