/* SPDX-License-Identifier: BSD-2-Clause */
/* Native synthetic input fixture. Run only in a disposable guest. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <dev/evdev/input.h>
#include <dev/evdev/uinput.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct uinput_setup setup;
	char node[64], path[80];
	int fd, status;
	pid_t child, waited;

	if (argc != 3)
		errx(1, "usage: fixture probe zero|bounds");
	fd = open("/dev/uinput", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		err(1, "open uinput");
	memset(&setup, 0, sizeof(setup));
	strlcpy(setup.name, "starnix-input-probe", sizeof(setup.name));
	setup.id.bustype = BUS_VIRTUAL;
	/* Omit EV_SYN deliberately: the Linux query must expose implicit support. */
	if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 ||
	    ioctl(fd, UI_SET_KEYBIT, KEY_A) < 0 ||
	    ioctl(fd, UI_DEV_SETUP, &setup) < 0 ||
	    ioctl(fd, UI_SET_PHYS, "starnix/input0") < 0 ||
	    ioctl(fd, UI_SET_BSDUNIQ, "starnix-serial") < 0 ||
	    ioctl(fd, UI_DEV_CREATE) < 0 ||
	    ioctl(fd, UI_GET_SYSNAME(sizeof(node)), node) < 0)
		err(1, "configure uinput");
	if (snprintf(path, sizeof(path), "/dev/input/%s", node) >=
	    (int)sizeof(path))
		errx(1, "event path too long");
	child = fork();
	if (child < 0)
		err(1, "fork");
	if (child == 0) {
		execl(argv[1], argv[1], path, argv[2], (char *)NULL);
		err(1, "exec probe");
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (ioctl(fd, UI_DEV_DESTROY) < 0)
		err(1, "destroy uinput");
	close(fd);
	if (waited < 0)
		err(1, "waitpid");
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 127);
}
