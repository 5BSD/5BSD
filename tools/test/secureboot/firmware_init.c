/* SPDX-License-Identifier: BSD-2-Clause */
/* Firmware-variable mechanism fixture, only for a disposable VM as PID 1.
 * This does not qualify loader authentication, veriexec or root integrity. */
#include <sys/types.h>
#include <sys/efiio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static const efi_guid_t global =
    {0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
static const efi_guid_t database =
    {0xd719b2cb,0x3d3a,0x4596,{0xa3,0xbc,0xda,0xd0,0x0e,0x67,0x65,0x6f}};

static struct efi_var_ioctl
variable(const char *name, efi_char *wide, void *data, size_t size)
{
	struct efi_var_ioctl v = {0};
	size_t i;

	for (i = 0; name[i] != '\0'; i++)
		wide[i] = name[i];
	wide[i] = 0;
	v.name = wide;
	v.namesize = (i + 1) * sizeof(*wide);
	v.vendor = strncmp(name, "db", 2) == 0 ? database : global;
	v.data = data;
	v.datasize = size;
	return (v);
}

static int
state(int fd, const char *name, unsigned expected)
{
	efi_char wide[32];
	unsigned char value = 255;
	struct efi_var_ioctl v = variable(name, wide, &value, sizeof(value));

	if (ioctl(fd, EFIIOC_VAR_GET, &v) == -1 ||
	    v.datasize != 1 || value != expected) {
		printf("FIRMWARE_FAIL %s value=%u errno=%d\n", name, value, errno);
		return (1);
	}
	printf("FIRMWARE_STATE %s=%u\n", name, value);
	return (0);
}

static int
protect(int fd, const char *name)
{
	unsigned char before[32768], after[32768];
	efi_char wide[32];
	struct efi_var_ioctl original, attempt, current;

	original = variable(name, wide, before, sizeof(before));
	if (ioctl(fd, EFIIOC_VAR_GET, &original) == -1 || original.datasize == 0)
		return (1);
	/* Also try removing the authenticated-write attribute from key variables. */
	int tries = original.datasize == 1 ? 2 : 4;
	for (int mode = 0; mode < tries; mode++) {
		int remove = mode & 1;
		attempt = original;
		if ((mode & 2) != 0)
			attempt.attrib &= ~0x20U; /* TIME_BASED_AUTHENTICATED_WRITE_ACCESS */
		attempt.datasize = remove ? 0 : original.datasize;
		if (!remove)
			before[original.datasize - 1] ^= 1;
		errno = 0;
		int rc = ioctl(fd, EFIIOC_VAR_SET, &attempt);
		int error = errno;
		if (!remove)
			before[original.datasize - 1] ^= 1;
		current = variable(name, wide, after, sizeof(after));
		if (rc != -1 || error == ENOSYS || error == ENOENT ||
		    ioctl(fd, EFIIOC_VAR_GET, &current) == -1 ||
		    current.attrib != original.attrib ||
		    current.datasize != original.datasize ||
		    memcmp(before, after, original.datasize) != 0) {
			printf("FIRMWARE_FAIL mutation %s remove=%d errno=%d\n",
			    name, remove, error);
			return (1);
		}
		printf("FIRMWARE_DENIED %s %s attributes=%#x errno=%d\n", name,
		    remove ? "delete" : "replace", attempt.attrib, error);
	}
	return (0);
}

int
main(int argc, char **argv __unused)
{
	char fstype[] = "fstype", devfs[] = "devfs", fspath[] = "fspath", dev[] = "/dev";
	struct iovec iov[] = {{fstype, sizeof(fstype)}, {devfs, sizeof(devfs)},
	    {fspath, sizeof(fspath)}, {dev, sizeof(dev)}};
	int fd, failed = 0;

	if (getpid() != 1 || argc != 1)
		return (64);
	if (nmount(iov, 4, 0) != 0 && errno != EBUSY)
		failed = 1;
	fd = open("/dev/console", O_RDWR);
	if (fd < 0) {
		(void)reboot(RB_POWEROFF);
		for (;;) pause();
	}
	if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
		failed = 1;
	if (fd > 2) close(fd);
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("FIRMWARE_VARIABLES_STARTED uid=%u\n", getuid());
	fd = open("/dev/efi", O_RDWR);
	if (fd < 0) {
		perror("/dev/efi");
		failed = 1;
	} else {
		failed |= state(fd, "SecureBoot", 1);
		failed |= state(fd, "SetupMode", 0);
		failed |= protect(fd, "PK");
		failed |= protect(fd, "KEK");
		failed |= protect(fd, "db");
		failed |= protect(fd, "dbx");
		failed |= protect(fd, "SecureBoot");
		failed |= protect(fd, "SetupMode");
		failed |= state(fd, "SecureBoot", 1);
		failed |= state(fd, "SetupMode", 0);
		close(fd);
	}
	puts(failed ? "FIRMWARE_VARIABLES_FAIL" : "FIRMWARE_VARIABLES_PASS");
	(void)tcdrain(1);
	reboot(RB_POWEROFF);
	for (;;) pause();
}
