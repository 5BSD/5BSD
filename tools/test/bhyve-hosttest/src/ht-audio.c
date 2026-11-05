/*
 * ht-audio: minimal OSS playback/capture check.
 *   ht-audio play DEVICE SECONDS   (440 Hz sine, s16le stereo 48 kHz, -12 dBFS)
 *   ht-audio rec  DEVICE SECONDS   (prints PEAK and RMS in dBFS)
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>
#include <err.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RATE 48000
int
main(int argc, char **argv)
{
	int fd, fmtv = AFMT_S16_LE, ch = 2, rate = RATE, secs;
	int16_t buf[RATE / 10 * 2];
	double peak = 0, sum = 0;
	long frames = 0, total;
	int play;

	if (argc != 4 || (strcmp(argv[1], "play") && strcmp(argv[1], "rec")))
		errx(2, "usage: ht-audio play|rec DEVICE SECONDS");
	play = strcmp(argv[1], "play") == 0;
	secs = atoi(argv[3]);
	if ((fd = open(argv[2], play ? O_WRONLY : O_RDONLY)) == -1)
		err(1, "open %s", argv[2]);
	if (ioctl(fd, SNDCTL_DSP_SETFMT, &fmtv) == -1 ||
	    ioctl(fd, SNDCTL_DSP_CHANNELS, &ch) == -1 ||
	    ioctl(fd, SNDCTL_DSP_SPEED, &rate) == -1)
		err(1, "configure %s", argv[2]);
	printf("device=%s format=0x%x channels=%d rate=%d\n", argv[2], fmtv, ch, rate);
	total = (long)rate * secs;
	while (frames < total) {
		int nf = sizeof(buf) / sizeof(buf[0]) / ch;
		if (play) {
			for (int i = 0; i < nf; i++)
				for (int c = 0; c < ch; c++)
					buf[i * ch + c] = (int16_t)(8192 *
					    sin(2 * M_PI * 440 * (frames + i) / rate));
			if (write(fd, buf, nf * ch * 2) != nf * ch * 2)
				err(1, "write");
		} else {
			ssize_t n = read(fd, buf, nf * ch * 2);
			if (n <= 0)
				err(1, "read");
			nf = n / 2 / ch;
			for (int i = 0; i < nf * ch; i++) {
				double v = buf[i] / 32768.0;
				if (fabs(v) > peak) peak = fabs(v);
				sum += v * v;
			}
		}
		frames += nf;
	}
	if (play) {
		ioctl(fd, SNDCTL_DSP_SYNC, NULL);
		printf("PLAYED seconds=%d frames=%ld\n", secs, frames);
	} else {
		double rms = sqrt(sum / (frames * ch));
		printf("RECORDED frames=%ld PEAK %.1f dBFS RMS %.1f dBFS\n", frames,
		    peak > 0 ? 20 * log10(peak) : -999.0, rms > 0 ? 20 * log10(rms) : -999.0);
	}
	close(fd);
	return (0);
}
