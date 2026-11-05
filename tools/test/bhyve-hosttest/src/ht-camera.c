/*
 * ht-camera: grab one frame from a video(4) device with read(2).
 *   ht-camera /dev/video0 out.raw
 * Prints driver/card, the current format and frame statistics. Exit 0 when
 * a non-empty, non-constant frame was read.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/videoio.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct v4l2_capability cap;
	struct v4l2_format fmt;
	unsigned char *buf, lo = 255, hi = 0;
	ssize_t n, got = 0;
	size_t sz;
	int fd, out;

	if (argc != 3)
		errx(2, "usage: ht-camera DEVICE OUTFILE");
	if ((fd = open(argv[1], O_RDWR)) == -1)
		err(1, "open %s", argv[1]);
	memset(&cap, 0, sizeof(cap));
	if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == -1)
		err(1, "VIDIOC_QUERYCAP");
	printf("driver=%s card=%s bus=%s caps=0x%x\n", cap.driver, cap.card,
	    cap.bus_info, cap.capabilities);
	memset(&fmt, 0, sizeof(fmt));
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(fd, VIDIOC_G_FMT, &fmt) == -1)
		err(1, "VIDIOC_G_FMT");
	printf("format=%ux%u fourcc=%.4s sizeimage=%u\n", fmt.fmt.pix.width,
	    fmt.fmt.pix.height, (char *)&fmt.fmt.pix.pixelformat,
	    fmt.fmt.pix.sizeimage);
	sz = fmt.fmt.pix.sizeimage ? fmt.fmt.pix.sizeimage : 8 * 1024 * 1024;
	if ((buf = malloc(sz)) == NULL)
		err(1, "malloc");
	/* The first frames after power-up may be dark; take the third. */
	for (int i = 0; i < 3; i++) {
		if ((n = read(fd, buf, sz)) == -1)
			err(1, "read frame %d", i);
		got = n;
	}
	for (ssize_t i = 0; i < got; i++) {
		if (buf[i] < lo) lo = buf[i];
		if (buf[i] > hi) hi = buf[i];
	}
	if ((out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1 ||
	    write(out, buf, got) != got)
		err(1, "write %s", argv[2]);
	close(out);
	printf("FRAME bytes=%zd min=%u max=%u\n", got, lo, hi);
	return (got > 0 && hi != lo ? 0 : 1);
}
