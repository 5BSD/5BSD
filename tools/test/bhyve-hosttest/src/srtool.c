/*
 * srtool: guest-side save/restore probes for the hosttest kit (sr2).
 * Built static so the same binary runs in the guest and on the host (the
 * host uses "expect" to compute reference digests independently).
 *
 *   srtool pattern MB SEED          deterministic bytes to stdout
 *   srtool expect MB SEED           SHA-256 of that pattern
 *   srtool work MB SEED             same, plus the CPU it finished on
 *   srtool hold MB SEED STATUS      hold MB of pattern in memory; SIGUSR1
 *                                   recomputes the digest into STATUS
 *   srtool verify STATUS [TIMEOUT]  signal the holder, wait for a new
 *                                   verification, print the status line
 *   srtool dirty MB STATUS          rewrite every word each pass, checking
 *                                   first that it still holds the previous
 *                                   pass's value (lost dirty pages -> errors)
 *   srtool spin STATUS              CPU-bound loop; STATUS = count + cpu
 *   srtool clock                    realtime, monotonic and uptime clocks
 *
 * Status files are replaced atomically (write + rename), one line each.
 */
#include <sys/types.h>
#include <sys/mman.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <sha256.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t want_verify;

static uint64_t
mix(uint64_t a, uint64_t b)
{
	uint64_t z = a * 0x9e3779b97f4a7c15ULL + b + 0x632be59bd9b4e019ULL;

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return (z ^ (z >> 31));
}

static size_t
mb_arg(const char *s)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0 || v > 65536)
		errx(2, "bad size in MiB: %s", s);
	return ((size_t)v << 20);
}

static uint64_t
u64_arg(const char *s)
{
	char *end;
	unsigned long long v;

	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno != 0 || *end != '\0')
		errx(2, "bad number: %s", s);
	return (v);
}

static void
fill(uint64_t *w, size_t words, uint64_t seed)
{
	for (size_t i = 0; i < words; i++)
		w[i] = mix(seed, i);
}

static void
digest(const void *p, size_t len, char out[65])
{
	SHA256_CTX c;

	SHA256_Init(&c);
	SHA256_Update(&c, p, len);
	SHA256_End(&c, out);
}

static void
put_status(const char *path, const char *line)
{
	char tmp[1024];
	int fd;

	snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		err(1, "%s", tmp);
	if (write(fd, line, strlen(line)) < 0 || fsync(fd) != 0 ||
	    close(fd) != 0)
		err(1, "%s", tmp);
	if (rename(tmp, path) != 0)
		err(1, "rename %s", path);
}

static uint64_t *
alloc_words(size_t bytes)
{
	void *p;

	p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
	    -1, 0);
	if (p == MAP_FAILED)
		err(1, "mmap %zu", bytes);
	return (p);
}

static void
on_usr1(int sig)
{
	(void)sig;
	want_verify = 1;
}

static int
cmd_pattern(size_t bytes, uint64_t seed)
{
	uint64_t buf[8192];
	size_t words = bytes / 8, i = 0;

	while (i < words) {
		size_t n = words - i < 8192 ? words - i : 8192;

		for (size_t j = 0; j < n; j++)
			buf[j] = mix(seed, i + j);
		if (fwrite(buf, 8, n, stdout) != n)
			err(1, "write");
		i += n;
	}
	return (fflush(stdout) == 0 ? 0 : 1);
}

static int
cmd_expect(size_t bytes, uint64_t seed, int show_cpu)
{
	SHA256_CTX c;
	uint64_t buf[8192];
	size_t words = bytes / 8, i = 0;
	char out[65];

	SHA256_Init(&c);
	while (i < words) {
		size_t n = words - i < 8192 ? words - i : 8192;

		for (size_t j = 0; j < n; j++)
			buf[j] = mix(seed, i + j);
		SHA256_Update(&c, buf, n * 8);
		i += n;
	}
	SHA256_End(&c, out);
	if (show_cpu)
		printf("%s cpu=%d\n", out, sched_getcpu());
	else
		printf("%s\n", out);
	return (0);
}

static int
cmd_hold(size_t bytes, uint64_t seed, const char *status)
{
	uint64_t *w;
	char d0[65], dn[65], line[512];
	unsigned long verifies = 0;
	sigset_t block, old;

	w = alloc_words(bytes);
	fill(w, bytes / 8, seed);
	digest(w, bytes, d0);
	signal(SIGUSR1, on_usr1);
	snprintf(line, sizeof(line), "SRHOLD pid=%d mb=%zu seed=%ju digest=%s "
	    "verifies=0 last=%s ok=yes\n", (int)getpid(), bytes >> 20,
	    (uintmax_t)seed, d0, d0);
	put_status(status, line);
	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	for (;;) {
		sigprocmask(SIG_BLOCK, &block, &old);
		while (!want_verify)
			sigsuspend(&old);
		want_verify = 0;
		sigprocmask(SIG_SETMASK, &old, NULL);
		digest(w, bytes, dn);
		verifies++;
		snprintf(line, sizeof(line), "SRHOLD pid=%d mb=%zu seed=%ju "
		    "digest=%s verifies=%lu last=%s ok=%s\n", (int)getpid(),
		    bytes >> 20, (uintmax_t)seed, d0, verifies, dn,
		    strcmp(d0, dn) == 0 ? "yes" : "no");
		put_status(status, line);
	}
}

static unsigned long
status_field(const char *path, const char *key, int *pid)
{
	char buf[1024], *p;
	FILE *f;
	size_t klen = strlen(key);

	*pid = -1;
	f = fopen(path, "r");
	if (f == NULL)
		return (0);
	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		return (0);
	}
	fclose(f);
	p = strstr(buf, "pid=");
	if (p != NULL)
		*pid = atoi(p + 4);
	for (p = buf; (p = strstr(p, key)) != NULL; p += klen) {
		if ((p == buf || p[-1] == ' ') && p[klen] == '=')
			return (strtoul(p + klen + 1, NULL, 10));
	}
	return (0);
}

static int
cmd_verify(const char *status, int timeout)
{
	unsigned long before, now;
	int pid, pid2;
	char buf[1024];
	FILE *f;

	before = status_field(status, "verifies", &pid);
	if (pid <= 0) {
		printf("SRHOLD-MISSING status=%s\n", status);
		return (1);
	}
	if (kill(pid, SIGUSR1) != 0) {
		printf("SRHOLD-DEAD pid=%d (%s)\n", pid, strerror(errno));
		return (1);
	}
	for (int i = 0; i < timeout * 10; i++) {
		now = status_field(status, "verifies", &pid2);
		if (now > before) {
			f = fopen(status, "r");
			if (f != NULL && fgets(buf, sizeof(buf), f) != NULL)
				fputs(buf, stdout);
			if (f != NULL)
				fclose(f);
			return (strstr(buf, " ok=yes") != NULL ? 0 : 1);
		}
		usleep(100000);
	}
	printf("SRHOLD-TIMEOUT pid=%d verifies=%lu after %d s\n", pid, before,
	    timeout);
	return (1);
}

static int
cmd_dirty(size_t bytes, const char *status)
{
	uint64_t *w;
	size_t words = bytes / 8;
	uint64_t pass, errors = 0, last_errors = 0;
	char line[512];
	struct timespec t0, t1;

	w = alloc_words(bytes);
	fill(w, words, 0);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (pass = 1;; pass++) {
		uint64_t e = 0;

		for (size_t i = 0; i < words; i++) {
			if (w[i] != mix(pass - 1, i))
				e++;
			w[i] = mix(pass, i);
		}
		errors += e;
		if (e != 0)
			last_errors = pass;
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if (t1.tv_sec != t0.tv_sec || e != 0) {
			snprintf(line, sizeof(line), "SRDIRTY pid=%d mb=%zu "
			    "pass=%ju errors=%ju last_error_pass=%ju\n",
			    (int)getpid(), bytes >> 20, (uintmax_t)pass,
			    (uintmax_t)errors, (uintmax_t)last_errors);
			put_status(status, line);
			t0 = t1;
		}
	}
}

static int
cmd_spin(const char *status)
{
	uint64_t n = 0, x = 1;
	char line[256];
	struct timespec t0, t1;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		for (int i = 0; i < 1000000; i++)
			x = mix(x, (uint64_t)i);
		n++;
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if ((t1.tv_sec - t0.tv_sec) * 1000000000L +
		    (t1.tv_nsec - t0.tv_nsec) >= 200000000L) {
			snprintf(line, sizeof(line), "SRSPIN pid=%d n=%ju "
			    "cpu=%d x=%ju\n", (int)getpid(), (uintmax_t)n,
			    sched_getcpu(), (uintmax_t)(x & 0xff));
			put_status(status, line);
			t0 = t1;
		}
	}
}

static int
cmd_clock(void)
{
	struct timespec r, m, u;

	clock_gettime(CLOCK_REALTIME, &r);
	clock_gettime(CLOCK_MONOTONIC, &m);
	clock_gettime(CLOCK_UPTIME, &u);
	printf("SRCLOCK real=%jd.%09ld mono=%jd.%09ld uptime=%jd.%09ld\n",
	    (intmax_t)r.tv_sec, r.tv_nsec, (intmax_t)m.tv_sec, m.tv_nsec,
	    (intmax_t)u.tv_sec, u.tv_nsec);
	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: srtool pattern|expect|work MB SEED | hold MB SEED "
	    "STATUS | verify STATUS [TIMEOUT] | dirty MB STATUS | "
	    "spin STATUS | clock\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		usage();
	if (strcmp(argv[1], "pattern") == 0 && argc == 4)
		return (cmd_pattern(mb_arg(argv[2]), u64_arg(argv[3])));
	if (strcmp(argv[1], "expect") == 0 && argc == 4)
		return (cmd_expect(mb_arg(argv[2]), u64_arg(argv[3]), 0));
	if (strcmp(argv[1], "work") == 0 && argc == 4)
		return (cmd_expect(mb_arg(argv[2]), u64_arg(argv[3]), 1));
	if (strcmp(argv[1], "hold") == 0 && argc == 5)
		return (cmd_hold(mb_arg(argv[2]), u64_arg(argv[3]), argv[4]));
	if (strcmp(argv[1], "verify") == 0 && (argc == 3 || argc == 4))
		return (cmd_verify(argv[2], argc == 4 ?
		    (int)u64_arg(argv[3]) : 60));
	if (strcmp(argv[1], "dirty") == 0 && argc == 4)
		return (cmd_dirty(mb_arg(argv[2]), argv[3]));
	if (strcmp(argv[1], "spin") == 0 && argc == 3)
		return (cmd_spin(argv[2]));
	if (strcmp(argv[1], "clock") == 0 && argc == 2)
		return (cmd_clock());
	usage();
}
