/*
 * ble_peripheral.c — advertise a custom GATT service.
 *
 * Usage: ble_peripheral
 *
 * Creates a service with a read/notify characteristic, updates
 * its value periodically, and handles remote write requests.
 */

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ble.h>

static volatile sig_atomic_t running = 1;
static uint16_t char_handle;

static void
sigint(int sig __unused)
{

	running = 0;
}

static void
on_write(uint16_t handle, const uint8_t *value, uint16_t len,
    void *arg __unused)
{

	printf("Remote wrote handle=0x%04X: ", handle);
	for (uint16_t i = 0; i < len; i++)
		printf("%02X", value[i]);
	printf("\n");
}

int
main(void)
{
	ble_ctx_t *ctx;
	ble_uuid_t svc_uuid, char_uuid;
	uint16_t svc_handle;
	struct pollfd pfd;
	int counter;

	signal(SIGINT, sigint);

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	/* Create a custom service: UUID 0xFFE0 */
	memset(&svc_uuid, 0, sizeof(svc_uuid));
	svc_uuid.uuid16 = 0xFFE0;
	if (ble_add_service(ctx, &svc_uuid, &svc_handle) < 0) {
		fprintf(stderr, "Failed to add service\n");
		ble_close(ctx);
		return (1);
	}

	/* Process response to get the service handle */
	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) > 0)
		ble_process(ctx);

	/* Add a read+notify characteristic: UUID 0xFFE1 */
	memset(&char_uuid, 0, sizeof(char_uuid));
	char_uuid.uuid16 = 0xFFE1;
	if (ble_add_characteristic(ctx, svc_handle, &char_uuid,
	    BLE_PROP_READ | BLE_PROP_NOTIFY | BLE_PROP_WRITE,
	    BLE_PERM_READ | BLE_PERM_WRITE,
	    NULL, 0, &char_handle) < 0) {
		fprintf(stderr, "Failed to add characteristic\n");
		ble_close(ctx);
		return (1);
	}

	/* Register write handler */
	ble_on_write(ctx, on_write, NULL);

	printf("Peripheral running (Ctrl-C to stop)...\n");
	printf("Service UUID: 0xFFE0, Char UUID: 0xFFE1\n");

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	counter = 0;

	while (running) {
		/* Update value every 2 seconds */
		{
			uint8_t val[4];
			time_t now = time(NULL);

			val[0] = (uint8_t)(counter & 0xFF);
			val[1] = (uint8_t)((counter >> 8) & 0xFF);
			val[2] = (uint8_t)(now & 0xFF);
			val[3] = (uint8_t)((now >> 8) & 0xFF);
			ble_set_value(ctx, char_handle, val, 4);
			counter++;
		}

		if (poll(&pfd, 1, 2000) > 0)
			ble_process(ctx);
	}

	printf("\nCleaning up...\n");
	ble_remove_service(ctx, svc_handle);
	ble_close(ctx);
	return (0);
}
