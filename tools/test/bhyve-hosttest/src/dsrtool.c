/*
 * dsrtool: helpers for the devices-sr (device save/restore) phase.
 * Built static; the guest copy lives in guest-bin/ and the host uses the
 * same binary for the uinput source.
 *
 *   dsrtool vfsmount DEV MNT        mount a virtio-fs device (/dev/virtiofsN)
 *                                   on MNT through fusefs, as mount_virtiofs(8)
 *                                   does (that program is not in the published
 *                                   packages; see dm-record.md)
 *   dsrtool uinput NAME CTL PIDOUT  host: create a uinput keyboard NAME, print
 *                                   /dev/input/eventN, then for each new line
 *                                   "key" appended to CTL emit one
 *                                   LEFTSHIFT press+release; exits when CTL
 *                                   disappears or on SIGTERM
 *   dsrtool evread DEV STATUS SECS  guest: count EV_KEY events read from DEV
 *                                   for SECS seconds; STATUS (rewritten on
 *                                   every event) holds "DSREV count=N"
 *   dsrtool tpmrand DEV             guest: TPM2_GetRandom(8) through DEV;
 *                                   prints "DSRTPM rc=0x... bytes=N"
 */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <dev/evdev/input.h>
#include <dev/evdev/uinput.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void
iov_add(struct iovec *iov, int *n, const char *name, const char *val)
{
	iov[*n].iov_base = __DECONST(char *, name);
	iov[*n].iov_len = strlen(name) + 1;
	(*n)++;
	iov[*n].iov_base = __DECONST(char *, val);
	iov[*n].iov_len = strlen(val) + 1;
	(*n)++;
}

static int
cmd_vfsmount(const char *dev, const char *mnt)
{
	struct iovec iov[10];
	char fdstr[16];
	int fd, n;

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("DSRVFS error=open:%s dev=%s\n", strerror(errno), dev);
		return (1);
	}
	snprintf(fdstr, sizeof(fdstr), "%d", fd);
	n = 0;
	iov_add(iov, &n, "fstype", "fusefs");
	iov_add(iov, &n, "fspath", mnt);
	iov_add(iov, &n, "from", dev);
	iov_add(iov, &n, "fd", fdstr);
	iov_add(iov, &n, "max_read=", "131072");
	if (nmount(iov, n, MNT_RDONLY) < 0) {
		printf("DSRVFS error=nmount:%s dev=%s mnt=%s\n", strerror(errno),
		    dev, mnt);
		return (1);
	}
	close(fd);
	printf("DSRVFS mounted dev=%s mnt=%s\n", dev, mnt);
	return (0);
}

static volatile sig_atomic_t stop;
static void
on_term(int sig __unused)
{
	stop = 1;
}

static void
emit(int fd, int type, int code, int value)
{
	struct input_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.code = code;
	ev.value = value;
	if (write(fd, &ev, sizeof(ev)) != (ssize_t)sizeof(ev))
		warn("uinput write");
}

static int
cmd_uinput(const char *name, const char *ctl, const char *pidout)
{
	struct uinput_setup us;
	struct stat st;
	char sys[64], line[64];
	FILE *f;
	off_t off;
	int fd, keys;

	fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		err(1, "/dev/uinput");
	if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_SYN) < 0 ||
	    ioctl(fd, UI_SET_KEYBIT, KEY_LEFTSHIFT) < 0 ||
	    ioctl(fd, UI_SET_KEYBIT, KEY_RIGHTSHIFT) < 0)
		err(1, "uinput setbits");
	memset(&us, 0, sizeof(us));
	us.id.bustype = BUS_VIRTUAL;
	us.id.vendor = 0x5bd;
	us.id.product = 0x0d5e;
	us.id.version = 1;
	strlcpy(us.name, name, sizeof(us.name));
	if (ioctl(fd, UI_DEV_SETUP, &us) < 0 || ioctl(fd, UI_DEV_CREATE) < 0)
		err(1, "uinput create");
	memset(sys, 0, sizeof(sys));
	if (ioctl(fd, UI_GET_SYSNAME(sizeof(sys) - 1), sys) < 0)
		err(1, "UI_GET_SYSNAME");
	if ((f = fopen(pidout, "w")) != NULL) {
		fprintf(f, "%d /dev/input/%s\n", (int)getpid(), sys);
		fclose(f);
	}
	printf("/dev/input/%s\n", sys);
	fflush(stdout);
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	off = 0;
	keys = 0;
	while (!stop) {
		if (stat(ctl, &st) < 0)
			break;
		if (st.st_size > off && (f = fopen(ctl, "r")) != NULL) {
			fseeko(f, off, SEEK_SET);
			while (fgets(line, sizeof(line), f) != NULL) {
				if (strncmp(line, "key", 3) == 0) {
					emit(fd, EV_KEY, KEY_LEFTSHIFT, 1);
					emit(fd, EV_SYN, SYN_REPORT, 0);
					emit(fd, EV_KEY, KEY_LEFTSHIFT, 0);
					emit(fd, EV_SYN, SYN_REPORT, 0);
					keys++;
				}
			}
			off = ftello(f);
			fclose(f);
		}
		usleep(100000);
	}
	ioctl(fd, UI_DEV_DESTROY);
	close(fd);
	fprintf(stderr, "dsrtool uinput: %d key pairs sent\n", keys);
	return (0);
}

static void
put_status(const char *status, long count)
{
	char tmp[PATH_MAX];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.tmp.%d", status, (int)getpid());
	if ((f = fopen(tmp, "w")) == NULL)
		return;
	fprintf(f, "DSREV count=%ld pid=%d\n", count, (int)getpid());
	fclose(f);
	rename(tmp, status);
}

static int
cmd_evread(const char *dev, const char *status, int secs)
{
	struct input_event ev;
	time_t end;
	long count;
	ssize_t r;
	int fd;

	fd = open(dev, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		printf("DSREV error=open:%s dev=%s\n", strerror(errno), dev);
		return (1);
	}
	count = 0;
	put_status(status, count);
	end = time(NULL) + secs;
	while (time(NULL) < end) {
		r = read(fd, &ev, sizeof(ev));
		if (r == (ssize_t)sizeof(ev)) {
			if (ev.type == EV_KEY) {
				count++;
				put_status(status, count);
			}
			continue;
		}
		usleep(50000);
	}
	put_status(status, count);
	return (0);
}

static int
cmd_tpmrand(const char *dev)
{
	/* TPM2_GetRandom, ST_NO_SESSIONS, size 12, bytesRequested 8. */
	static const unsigned char cmd[] = { 0x80, 0x01, 0x00, 0x00, 0x00,
	    0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08 };
	unsigned char rsp[64];
	unsigned int rc;
	ssize_t n;
	int fd;

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("DSRTPM error=open:%s\n", strerror(errno));
		return (1);
	}
	if (write(fd, cmd, sizeof(cmd)) != (ssize_t)sizeof(cmd)) {
		printf("DSRTPM error=write:%s\n", strerror(errno));
		return (1);
	}
	n = read(fd, rsp, sizeof(rsp));
	if (n < 10) {
		printf("DSRTPM error=read:%s n=%zd\n", strerror(errno), n);
		return (1);
	}
	rc = (rsp[6] << 24) | (rsp[7] << 16) | (rsp[8] << 8) | rsp[9];
	printf("DSRTPM rc=0x%x bytes=%d\n", rc,
	    n >= 12 ? (rsp[10] << 8 | rsp[11]) : -1);
	return (rc == 0 ? 0 : 1);
}

int
main(int argc, char **argv)
{
	if (argc == 4 && strcmp(argv[1], "vfsmount") == 0)
		return (cmd_vfsmount(argv[2], argv[3]));
	if (argc == 5 && strcmp(argv[1], "uinput") == 0)
		return (cmd_uinput(argv[2], argv[3], argv[4]));
	if (argc == 5 && strcmp(argv[1], "evread") == 0)
		return (cmd_evread(argv[2], argv[3], atoi(argv[4])));
	if (argc == 3 && strcmp(argv[1], "tpmrand") == 0)
		return (cmd_tpmrand(argv[2]));
	fprintf(stderr, "usage: dsrtool vfsmount DEV MNT | uinput NAME CTL "
	    "PIDOUT | evread DEV STATUS SECS | tpmrand DEV\n");
	return (2);
}
