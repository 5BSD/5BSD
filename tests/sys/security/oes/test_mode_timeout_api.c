/*
 * OES GET_MODE / SET_TIMEOUT / GET_TIMEOUT API tests
 *
 * Tests the new configuration query and independent timeout APIs.
 */
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

static int
test_get_mode_initial(int fd)
{
	struct oes_mode_args args;

	printf("  get_mode initial values: ");

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_MODE, &args) < 0) {
		printf("FAIL (ioctl: %s)\n", strerror(errno));
		return (1);
	}

	/* Initial mode should be NOTIFY (0) */
	if (args.ema_mode != OES_MODE_NOTIFY) {
		printf("FAIL (mode=%u, expected %u)\n",
		    args.ema_mode, OES_MODE_NOTIFY);
		return (1);
	}

	/* Timeout should be default (30000ms) */
	if (args.ema_timeout_ms != OES_DEFAULT_TIMEOUT_MS) {
		printf("FAIL (timeout=%u, expected %u)\n",
		    args.ema_timeout_ms, OES_DEFAULT_TIMEOUT_MS);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_get_mode_after_set(int fd)
{
	struct oes_mode_args set_args, get_args;

	printf("  get_mode after set_mode: ");

	memset(&set_args, 0, sizeof(set_args));
	set_args.ema_mode = OES_MODE_AUTH;
	set_args.ema_timeout_ms = 5000;
	set_args.ema_queue_size = 512;

	if (ioctl(fd, OES_IOC_SET_MODE, &set_args) < 0) {
		printf("FAIL (set_mode: %s)\n", strerror(errno));
		return (1);
	}

	memset(&get_args, 0, sizeof(get_args));
	if (ioctl(fd, OES_IOC_GET_MODE, &get_args) < 0) {
		printf("FAIL (get_mode: %s)\n", strerror(errno));
		return (1);
	}

	if (get_args.ema_mode != OES_MODE_AUTH) {
		printf("FAIL (mode=%u, expected %u)\n",
		    get_args.ema_mode, OES_MODE_AUTH);
		return (1);
	}

	if (get_args.ema_timeout_ms != 5000) {
		printf("FAIL (timeout=%u, expected 5000)\n",
		    get_args.ema_timeout_ms);
		return (1);
	}

	if (get_args.ema_queue_size != 512) {
		printf("FAIL (queue_size=%u, expected 512)\n",
		    get_args.ema_queue_size);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_set_timeout_independent(int fd)
{
	struct oes_mode_args mode_args;
	struct oes_timeout_args timeout_args;

	printf("  set_timeout independent: ");

	/* First set mode with a specific timeout */
	memset(&mode_args, 0, sizeof(mode_args));
	mode_args.ema_mode = OES_MODE_AUTH;
	mode_args.ema_timeout_ms = 10000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode_args) < 0) {
		printf("FAIL (set_mode: %s)\n", strerror(errno));
		return (1);
	}

	/* Now change timeout independently */
	memset(&timeout_args, 0, sizeof(timeout_args));
	timeout_args.eta_timeout_ms = 20000;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT, &timeout_args) < 0) {
		printf("FAIL (set_timeout: %s)\n", strerror(errno));
		return (1);
	}

	/* Verify timeout changed but mode stayed same */
	memset(&mode_args, 0, sizeof(mode_args));
	if (ioctl(fd, OES_IOC_GET_MODE, &mode_args) < 0) {
		printf("FAIL (get_mode: %s)\n", strerror(errno));
		return (1);
	}

	if (mode_args.ema_mode != OES_MODE_AUTH) {
		printf("FAIL (mode changed to %u)\n", mode_args.ema_mode);
		return (1);
	}

	if (mode_args.ema_timeout_ms != 20000) {
		printf("FAIL (timeout=%u, expected 20000)\n",
		    mode_args.ema_timeout_ms);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_get_timeout(int fd)
{
	struct oes_timeout_args set_args, get_args;

	printf("  get_timeout: ");

	memset(&set_args, 0, sizeof(set_args));
	set_args.eta_timeout_ms = 15000;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT, &set_args) < 0) {
		printf("FAIL (set_timeout: %s)\n", strerror(errno));
		return (1);
	}

	memset(&get_args, 0, sizeof(get_args));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT, &get_args) < 0) {
		printf("FAIL (get_timeout: %s)\n", strerror(errno));
		return (1);
	}

	if (get_args.eta_timeout_ms != 15000) {
		printf("FAIL (timeout=%u, expected 15000)\n",
		    get_args.eta_timeout_ms);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_timeout_clamping(int fd)
{
	struct oes_timeout_args args;

	printf("  timeout clamping: ");

	/* Test below minimum (should clamp to OES_MIN_TIMEOUT_MS = 1000) */
	memset(&args, 0, sizeof(args));
	args.eta_timeout_ms = 100;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT, &args) < 0) {
		printf("FAIL (set_timeout min: %s)\n", strerror(errno));
		return (1);
	}

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT, &args) < 0) {
		printf("FAIL (get_timeout: %s)\n", strerror(errno));
		return (1);
	}

	if (args.eta_timeout_ms != OES_MIN_TIMEOUT_MS) {
		printf("FAIL (timeout=%u, expected min %u)\n",
		    args.eta_timeout_ms, OES_MIN_TIMEOUT_MS);
		return (1);
	}

	/* Test above maximum (should clamp to OES_MAX_TIMEOUT_MS = 300000) */
	memset(&args, 0, sizeof(args));
	args.eta_timeout_ms = 999999;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT, &args) < 0) {
		printf("FAIL (set_timeout max: %s)\n", strerror(errno));
		return (1);
	}

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT, &args) < 0) {
		printf("FAIL (get_timeout: %s)\n", strerror(errno));
		return (1);
	}

	if (args.eta_timeout_ms != OES_MAX_TIMEOUT_MS) {
		printf("FAIL (timeout=%u, expected max %u)\n",
		    args.eta_timeout_ms, OES_MAX_TIMEOUT_MS);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_stats_includes_config(int fd)
{
	struct oes_mode_args mode_args;
	struct oes_timeout_action_args action_args;
	struct oes_stats stats;

	printf("  stats includes config: ");

	/* Set up specific configuration */
	memset(&mode_args, 0, sizeof(mode_args));
	mode_args.ema_mode = OES_MODE_AUTH;
	mode_args.ema_timeout_ms = 7500;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode_args) < 0) {
		printf("FAIL (set_mode: %s)\n", strerror(errno));
		return (1);
	}

	memset(&action_args, 0, sizeof(action_args));
	action_args.eta_action = OES_AUTH_DENY;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &action_args) < 0) {
		printf("FAIL (set_timeout_action: %s)\n", strerror(errno));
		return (1);
	}

	/* Get stats and verify config fields */
	memset(&stats, 0, sizeof(stats));
	if (ioctl(fd, OES_IOC_GET_STATS, &stats) < 0) {
		printf("FAIL (get_stats: %s)\n", strerror(errno));
		return (1);
	}

	if (stats.es_mode != OES_MODE_AUTH) {
		printf("FAIL (stats.mode=%u, expected %u)\n",
		    stats.es_mode, OES_MODE_AUTH);
		return (1);
	}

	if (stats.es_timeout_ms != 7500) {
		printf("FAIL (stats.timeout=%u, expected 7500)\n",
		    stats.es_timeout_ms);
		return (1);
	}

	if (stats.es_timeout_action != OES_AUTH_DENY) {
		printf("FAIL (stats.timeout_action=%u, expected %u)\n",
		    stats.es_timeout_action, OES_AUTH_DENY);
		return (1);
	}

	printf("ok\n");
	return (0);
}

int
main(void)
{
	int fd;
	int failures = 0;

	printf("mode/timeout API tests:\n");

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	failures += test_get_mode_initial(fd);
	close(fd);

	/* Reopen for fresh client state */
	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_get_mode_after_set(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_set_timeout_independent(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_get_timeout(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_timeout_clamping(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_stats_includes_config(fd);
	close(fd);

	if (failures > 0) {
		printf("\nFAILED: %d test(s)\n", failures);
		return (1);
	}

	printf("\nmode/timeout API: all tests passed\n");
	return (0);
}
