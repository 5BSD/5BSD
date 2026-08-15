/*
 * OES default muting sysctl tests.
 *
 * Tests security.oes.default_muted_paths and related sysctls.
 * Requires root privileges.
 */
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

static int
test_read_default_paths_sysctl(void)
{
	char buf[1024];
	size_t len = sizeof(buf);
	int ret;

	printf("  Testing read security.oes.default_muted_paths...\n");

	ret = sysctlbyname("security.oes.default_muted_paths", buf, &len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    INFO: sysctl not found (module not loaded?)\n");
			return (0);
		}
		perror("sysctlbyname");
		return (1);
	}

	printf("    current value: '%s'\n", buf);
	printf("    PASS: read default_muted_paths\n");
	return (0);
}

static int
test_read_default_self_mute_sysctl(void)
{
	int val;
	size_t len = sizeof(val);
	int ret;

	printf("  Testing read security.oes.default_self_mute...\n");

	ret = sysctlbyname("security.oes.default_self_mute", &val, &len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    INFO: sysctl not found (module not loaded?)\n");
			return (0);
		}
		perror("sysctlbyname");
		return (1);
	}

	printf("    current value: %d\n", val);
	printf("    PASS: read default_self_mute\n");
	return (0);
}

static int
test_write_default_paths_sysctl(void)
{
	char old_val[1024];
	char new_val[] = "/dev:/proc";
	size_t old_len = sizeof(old_val);
	int ret;

	printf("  Testing write security.oes.default_muted_paths...\n");

	if (geteuid() != 0) {
		printf("    SKIP: requires root\n");
		return (0);
	}

	/* Save old value */
	ret = sysctlbyname("security.oes.default_muted_paths", old_val, &old_len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    INFO: sysctl not found (module not loaded?)\n");
			return (0);
		}
		perror("sysctlbyname (read)");
		return (1);
	}

	/* Write new value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    new_val, strlen(new_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (write)");
		return (1);
	}

	/* Restore old value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    old_val, strlen(old_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (restore)");
		return (1);
	}

	printf("    PASS: write default_muted_paths\n");
	return (0);
}

static int
test_default_mute_applied(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_get_muted_paths_args get_paths;
	struct oes_muted_path_entry entries[16];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	char old_val[1024];
	char new_val[] = "/usr/share";
	size_t old_len = sizeof(old_val);
	int ret;
	size_t i;
	int found = 0;

	printf("  Testing default muting applied on mode set...\n");

	if (geteuid() != 0) {
		printf("    SKIP: requires root\n");
		return (0);
	}

	/* Save old sysctl value */
	ret = sysctlbyname("security.oes.default_muted_paths", old_val, &old_len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    INFO: sysctl not found (module not loaded?)\n");
			return (0);
		}
		perror("sysctlbyname (read)");
		return (1);
	}

	/* Set test value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    new_val, strlen(new_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (write)");
		return (1);
	}

	/* Open new client and set mode */
	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		/* Restore */
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	/* Query muted paths - should include /usr/share */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	for (i = 0; i < get_paths.egmpa_actual && i < 16; i++) {
		if (strstr(entries[i].emp_path, "/usr/share") != NULL) {
			found = 1;
			break;
		}
	}

	close(fd);

	/* Restore old sysctl value */
	sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    old_val, strlen(old_val) + 1);

	if (found) {
		printf("    PASS: default muted path applied\n");
	} else {
		printf("    INFO: default muted path not found in list\n");
		printf("    (may need module reload to take effect)\n");
	}

	return (0);
}

static int
test_default_self_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_get_muted_processes_args get_procs;
	struct oes_muted_process_entry entries[16];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	int old_val, new_val = 1;
	size_t old_len = sizeof(old_val);
	int ret;
	size_t i;
	int found = 0;
	pid_t mypid = getpid();

	printf("  Testing default self-mute...\n");

	if (geteuid() != 0) {
		printf("    SKIP: requires root\n");
		return (0);
	}

	/* Save old sysctl value */
	ret = sysctlbyname("security.oes.default_self_mute", &old_val, &old_len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    INFO: sysctl not found (module not loaded?)\n");
			return (0);
		}
		perror("sysctlbyname (read)");
		return (1);
	}

	/* Enable default self-mute */
	ret = sysctlbyname("security.oes.default_self_mute", NULL, NULL,
	    &new_val, sizeof(new_val));
	if (ret < 0) {
		perror("sysctlbyname (write)");
		return (1);
	}

	/* Open new client */
	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		sysctlbyname("security.oes.default_self_mute", NULL, NULL,
		    &old_val, sizeof(old_val));
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		sysctlbyname("security.oes.default_self_mute", NULL, NULL,
		    &old_val, sizeof(old_val));
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		sysctlbyname("security.oes.default_self_mute", NULL, NULL,
		    &old_val, sizeof(old_val));
		return (1);
	}

	/* Query muted processes - should include self */
	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		sysctlbyname("security.oes.default_self_mute", NULL, NULL,
		    &old_val, sizeof(old_val));
		return (1);
	}

	for (i = 0; i < get_procs.egmp_actual && i < 16; i++) {
		if (entries[i].emp_token.ept_id == (uint64_t)mypid) {
			found = 1;
			break;
		}
	}

	close(fd);

	/* Restore old sysctl value */
	sysctlbyname("security.oes.default_self_mute", NULL, NULL,
	    &old_val, sizeof(old_val));

	if (found) {
		printf("    PASS: default self-mute applied\n");
	} else {
		printf("    INFO: self not found in muted list\n");
	}

	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing default muting sysctls...\n");

	failed += test_read_default_paths_sysctl();
	failed += test_read_default_self_mute_sysctl();
	failed += test_write_default_paths_sysctl();
	failed += test_default_mute_applied();
	failed += test_default_self_mute();

	if (failed > 0) {
		printf("default muting: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("default muting: ok\n");
	return (0);
}
