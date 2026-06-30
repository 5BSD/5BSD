/*
 * ble_weather.c — advertise weather data for a zip code via BLE.
 *
 * Usage: ble_weather <zipcode>
 *
 * Fetches weather from wttr.in (requires fetch(1) or curl(1)),
 * advertises a custom GATT service (UUID 0xFFD0) with two
 * characteristics:
 *   0xFFD1: Temperature (read, notify) — UTF-8 string
 *   0xFFD2: Conditions (read) — UTF-8 string
 *
 * Updates every 5 minutes.  A BLE central can connect and read
 * the temperature and conditions, or subscribe to 0xFFD1 for
 * live updates.
 *
 * Build:
 *   cc -o ble_weather ble_weather.c -lble -lbluetooth
 */

#include <ctype.h>
#include <err.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ble.h>

#define UPDATE_INTERVAL_SEC	300	/* 5 minutes */
#define WEATHER_SVC_UUID	0xFFD0
#define TEMP_CHAR_UUID		0xFFD1
#define COND_CHAR_UUID		0xFFD2

static volatile sig_atomic_t running = 1;
static uint16_t temp_handle;
static uint16_t cond_handle;

static void
sigint(int sig __unused)
{

	running = 0;
}

/*
 * Fetch weather for a zip code using wttr.in.
 * Parses temperature and conditions from the one-liner format.
 */
static int
fetch_weather(const char *zipcode, char *temp_out, size_t temp_sz,
    char *cond_out, size_t cond_sz)
{
	char cmd[256];
	char line[256];
	FILE *fp;

	/* Validate zipcode: alphanumeric and hyphens only */
	{
		const char *p;
		for (p = zipcode; *p != '\0'; p++) {
			if (!isalnum((unsigned char)*p) && *p != '-') {
				warnx("invalid zipcode character: '%c'", *p);
				return (-1);
			}
		}
	}

	/* wttr.in format: "+72°F|Clear" */
	snprintf(cmd, sizeof(cmd),
	    "fetch -qo - 'https://wttr.in/%s?format=%%t|%%C' 2>/dev/null || "
	    "curl -sf 'https://wttr.in/%s?format=%%t|%%C' 2>/dev/null",
	    zipcode, zipcode);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return (-1);

	line[0] = '\0';
	if (fgets(line, sizeof(line), fp) == NULL) {
		pclose(fp);
		return (-1);
	}
	pclose(fp);

	/* Strip newline */
	line[strcspn(line, "\n\r")] = '\0';

	/* Split on '|' */
	{
		char *sep = strchr(line, '|');

		if (sep != NULL) {
			*sep = '\0';
			strlcpy(temp_out, line, temp_sz);
			strlcpy(cond_out, sep + 1, cond_sz);
		} else {
			strlcpy(temp_out, line, temp_sz);
			strlcpy(cond_out, "Unknown", cond_sz);
		}
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	uint16_t svc_handle;
	struct pollfd pfd;
	char temperature[64];
	char conditions[64];
	time_t last_update;
	const char *zipcode;

	if (argc < 2) {
		fprintf(stderr, "usage: ble_weather <zipcode>\n");
		return (1);
	}
	zipcode = argv[1];

	signal(SIGINT, sigint);

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	/* Create weather service */
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = WEATHER_SVC_UUID;
	if (ble_add_service(ctx, &uuid, &svc_handle) < 0) {
		fprintf(stderr, "Failed to add service\n");
		ble_close(ctx);
		return (1);
	}

	/* Temperature characteristic: read + notify */
	uuid.uuid16 = TEMP_CHAR_UUID;
	ble_add_characteristic(ctx, svc_handle, &uuid,
	    BLE_PROP_READ | BLE_PROP_NOTIFY, BLE_PERM_READ,
	    NULL, 0, &temp_handle);

	/* Conditions characteristic: read only */
	uuid.uuid16 = COND_CHAR_UUID;
	ble_add_characteristic(ctx, svc_handle, &uuid,
	    BLE_PROP_READ, BLE_PERM_READ,
	    NULL, 0, &cond_handle);

	/* Process initial responses */
	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) > 0)
		ble_process(ctx);

	printf("Weather service running for zip %s (Ctrl-C to stop)\n",
	    zipcode);
	printf("Service UUID: 0x%04X\n", WEATHER_SVC_UUID);
	printf("  Temperature: 0x%04X (read, notify)\n", TEMP_CHAR_UUID);
	printf("  Conditions:  0x%04X (read)\n", COND_CHAR_UUID);

	last_update = 0;

	while (running) {
		time_t now;

		now = time(NULL);
		if (now - last_update >= UPDATE_INTERVAL_SEC) {
			printf("Fetching weather for %s...\n", zipcode);
			if (fetch_weather(zipcode, temperature,
			    sizeof(temperature), conditions,
			    sizeof(conditions)) == 0) {
				printf("  Temp: %s  Conditions: %s\n",
				    temperature, conditions);

				ble_set_value(ctx, temp_handle,
				    (const uint8_t *)temperature,
				    (uint16_t)strlen(temperature));
				ble_set_value(ctx, cond_handle,
				    (const uint8_t *)conditions,
				    (uint16_t)strlen(conditions));
			} else {
				fprintf(stderr, "  (fetch failed)\n");
			}
			last_update = now;
		}

		if (poll(&pfd, 1, 5000) > 0)
			ble_process(ctx);
	}

	printf("\nCleaning up...\n");
	ble_remove_service(ctx, svc_handle);
	ble_close(ctx);
	return (0);
}
