/* OES mode, deadline, scope, subscription, and statistics API tests. */
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
	if (args.ema_default_deadline_ms != OES_DEFAULT_DEADLINE_MS) {
		printf("FAIL (timeout=%u, expected %u)\n",
		    args.ema_default_deadline_ms, OES_DEFAULT_DEADLINE_MS);
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
	set_args.ema_default_deadline_ms = 5000;
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

	if (get_args.ema_default_deadline_ms != 5000) {
		printf("FAIL (timeout=%u, expected 5000)\n",
		    get_args.ema_default_deadline_ms);
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
test_timeout_clamping(int fd)
{
	struct oes_mode_args args;

	printf("  timeout clamping: ");

	/* Test below the one-second minimum. */
	memset(&args, 0, sizeof(args));
	args.ema_mode = OES_MODE_AUTH;
	args.ema_default_deadline_ms = 100;
	if (ioctl(fd, OES_IOC_SET_MODE, &args) < 0) {
		printf("FAIL (set_mode min: %s)\n", strerror(errno));
		return (1);
	}

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_MODE, &args) < 0) {
		printf("FAIL (get_mode: %s)\n", strerror(errno));
		return (1);
	}

	if (args.ema_default_deadline_ms != OES_MIN_DEADLINE_MS) {
		printf("FAIL (timeout=%u, expected min %u)\n",
		    args.ema_default_deadline_ms, OES_MIN_DEADLINE_MS);
		return (1);
	}

	/* Test above the five-minute maximum. */
	memset(&args, 0, sizeof(args));
	args.ema_mode = OES_MODE_AUTH;
	args.ema_default_deadline_ms = 999999;
	if (ioctl(fd, OES_IOC_SET_MODE, &args) < 0) {
		printf("FAIL (set_mode max: %s)\n", strerror(errno));
		return (1);
	}

	memset(&args, 0, sizeof(args));
	if (ioctl(fd, OES_IOC_GET_MODE, &args) < 0) {
		printf("FAIL (get_mode: %s)\n", strerror(errno));
		return (1);
	}

	if (args.ema_default_deadline_ms != OES_MAX_DEADLINE_MS) {
		printf("FAIL (timeout=%u, expected max %u)\n",
		    args.ema_default_deadline_ms, OES_MAX_DEADLINE_MS);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_stats_includes_config(int fd)
{
	struct oes_mode_args mode_args;
	struct oes_deadline_miss_mode_args action_args;
	struct oes_stats stats;

	printf("  stats includes config: ");

	/* Set up specific configuration */
	memset(&mode_args, 0, sizeof(mode_args));
	mode_args.ema_mode = OES_MODE_AUTH;
	mode_args.ema_default_deadline_ms = 7500;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode_args) < 0) {
		printf("FAIL (set_mode: %s)\n", strerror(errno));
		return (1);
	}

	memset(&action_args, 0, sizeof(action_args));
	action_args.edma_mode = OES_DEADLINE_MISS_FAIL_CLOSED;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action_args) < 0) {
		printf("FAIL (set_deadline_miss_mode: %s)\n", strerror(errno));
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

	if (stats.es_default_deadline_ms != 7500) {
		printf("FAIL (stats.timeout=%u, expected 7500)\n",
		    stats.es_default_deadline_ms);
		return (1);
	}

	if (stats.es_deadline_miss_mode != OES_DEADLINE_MISS_FAIL_CLOSED) {
		printf("FAIL (stats.timeout_action=%u, expected %u)\n",
		    stats.es_deadline_miss_mode,
		    OES_DEADLINE_MISS_FAIL_CLOSED);
		return (1);
	}

	printf("ok\n");
	return (0);
}

static int
test_subscription_query_remove(int fd)
{
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_subscribe_bitmap_args current;
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_OPEN,
		OES_EVENT_NOTIFY_CLOSE,
	};
	oes_event_type_t remove = OES_EVENT_AUTH_OPEN;
	uint64_t auth_bit = 1ULL << (OES_EVENT_AUTH_OPEN & 0x3f);
	uint64_t notify_bit = 1ULL << (OES_EVENT_NOTIFY_CLOSE & 0x3f);

	printf("  subscription query/remove: ");
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0)
		goto fail;

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 2;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0)
		goto fail;

	memset(&current, 0, sizeof(current));
	if (ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &current) < 0)
		goto fail;
	if ((current.esba_auth[0] & auth_bit) == 0 ||
	    (current.esba_notify[0] & notify_bit) == 0)
		goto fail;

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = &remove;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REMOVE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0)
		goto fail;
	memset(&current, 0, sizeof(current));
	if (ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &current) < 0)
		goto fail;
	if ((current.esba_auth[0] & auth_bit) != 0 ||
	    (current.esba_notify[0] & notify_bit) == 0)
		goto fail;

	printf("ok\n");
	return (0);

fail:
	printf("FAIL (%s)\n", strerror(errno));
	return (1);
}

static int
test_bitmap_subscription_128(int fd)
{
	struct oes_subscribe_bitmap_args bitmap, current;
	uint32_t bit;

	printf("  128-bit bitmap subscription: ");
	bit = OES_EVENT_NOTIFY_MOUNT_STAT & 0x0fff;
	if (bit < 64 || bit >= 128)
		goto fail;
	memset(&bitmap, 0, sizeof(bitmap));
	bitmap.esba_notify[bit / 64] = 1ULL << (bit % 64);
	bitmap.esba_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP, &bitmap) < 0)
		goto fail;
	memset(&current, 0, sizeof(current));
	if (ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &current) < 0 ||
	    current.esba_notify[1] != bitmap.esba_notify[1])
		goto fail;
	bitmap.esba_reserved = 1;
	errno = 0;
	if (ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP, &bitmap) == 0 ||
	    errno != EINVAL)
		goto fail;
	printf("ok\n");
	return (0);
fail:
	printf("FAIL (%s)\n", strerror(errno));
	return (1);
}

static int
test_descendants_scope_configuration(int fd)
{
	struct oes_scope_args scope;
	struct oes_mode_args mode;
	struct oes_get_muted_processes_args muted;
	struct oes_muted_process_entry entries[4];

	printf("  descendants scope configuration: ");
	memset(&scope, 0, sizeof(scope));
	if (ioctl(fd, OES_IOC_GET_SCOPE, &scope) < 0 ||
	    scope.esa_scope != OES_SCOPE_GLOBAL)
		goto fail;
	scope.esa_scope = OES_SCOPE_DESCENDANTS;
	if (ioctl(fd, OES_IOC_SET_SCOPE, &scope) < 0)
		goto fail;
	memset(&scope, 0, sizeof(scope));
	if (ioctl(fd, OES_IOC_GET_SCOPE, &scope) < 0 ||
	    scope.esa_scope != OES_SCOPE_DESCENDANTS)
		goto fail;

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0)
		goto fail;
	/* Root NOTIFY visibility requires descendants scope to skip self-mute. */
	memset(&muted, 0, sizeof(muted));
	muted.egmp_entries = entries;
	muted.egmp_count = 4;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &muted) < 0 ||
	    muted.egmp_actual != 0)
		goto fail;

	memset(&scope, 0, sizeof(scope));
	scope.esa_scope = OES_SCOPE_DESCENDANTS;
	errno = 0;
	if (ioctl(fd, OES_IOC_SET_SCOPE, &scope) == 0 || errno != EBUSY)
		goto fail;
	printf("ok\n");
	return (0);

fail:
	printf("FAIL (%s)\n", strerror(errno));
	return (1);
}

static int
test_deadline_bounds_global(int fd)
{
	struct oes_event_deadline_args args;

	printf("  per-event deadline maximums: ");
	memset(&args, 0, sizeof(args));
	args.oeda_event = OES_EVENT_AUTH_EXEC;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MAX, &args) < 0 ||
	    args.oeda_milliseconds != OES_DEFAULT_DEADLINE_MS)
		goto fail;

	args.oeda_milliseconds = 5000;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &args) < 0)
		goto fail;
	args.oeda_milliseconds = 0;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MAX, &args) < 0 ||
	    args.oeda_milliseconds != 5000)
		goto fail;

	/* Only real AUTH events are valid deadline keys. */
	memset(&args, 0, sizeof(args));
	args.oeda_event = OES_EVENT_NOTIFY_EXEC;
	errno = 0;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &args) == 0 ||
	    errno != EINVAL)
		goto fail;

	/* Minimum extensions are deliberately descendants-only. */
	memset(&args, 0, sizeof(args));
	args.oeda_event = OES_EVENT_AUTH_EXEC;
	errno = 0;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MIN, &args) == 0 ||
	    errno != EPERM)
		goto fail;

	/* Reserved fields are validated on both SET and GET paths. */
	args.oeda_reserved[1] = 1;
	errno = 0;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MAX, &args) == 0 ||
	    errno != EINVAL)
		goto fail;

	printf("ok\n");
	return (0);
fail:
	printf("FAIL (%s)\n", strerror(errno));
	return (1);
}

static int
test_deadline_bounds_descendants(int fd)
{
	struct oes_event_deadline_args args;
	struct oes_scope_args scope;

	printf("  descendants deadline min/max interaction: ");
	memset(&scope, 0, sizeof(scope));
	scope.esa_scope = OES_SCOPE_DESCENDANTS;
	if (ioctl(fd, OES_IOC_SET_SCOPE, &scope) < 0)
		goto fail;

	memset(&args, 0, sizeof(args));
	args.oeda_event = OES_EVENT_AUTH_OPEN;
	args.oeda_milliseconds = 5000;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &args) < 0)
		goto fail;
	args.oeda_milliseconds = 7000;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MIN, &args) < 0)
		goto fail;
	args.oeda_milliseconds = 0;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MIN, &args) < 0 ||
	    args.oeda_milliseconds != 7000)
		goto fail;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MAX, &args) < 0 ||
	    args.oeda_milliseconds != 7000)
		goto fail;

	/* Lowering maximum also lowers the minimum to preserve the bound. */
	args.oeda_milliseconds = 4000;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &args) < 0)
		goto fail;
	args.oeda_milliseconds = 0;
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MIN, &args) < 0 ||
	    args.oeda_milliseconds != 4000)
		goto fail;

	/* Zero removes each override and restores inherited defaults. */
	args.oeda_milliseconds = 0;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MIN, &args) < 0 ||
	    ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &args) < 0 ||
	    ioctl(fd, OES_IOC_GET_DEADLINE_MAX, &args) < 0 ||
	    args.oeda_milliseconds != OES_DEFAULT_DEADLINE_MS)
		goto fail;

	printf("ok\n");
	return (0);
fail:
	printf("FAIL (%s)\n", strerror(errno));
	return (1);
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
	failures += test_timeout_clamping(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_stats_includes_config(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_subscription_query_remove(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_bitmap_subscription_128(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_descendants_scope_configuration(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_deadline_bounds_global(fd);
	close(fd);

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	failures += test_deadline_bounds_descendants(fd);
	close(fd);

	if (failures > 0) {
		printf("\nFAILED: %d test(s)\n", failures);
		return (1);
	}

	printf("\nmode/timeout API: all tests passed\n");
	return (0);
}
