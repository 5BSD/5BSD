/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ipc_soak SECONDS [SEED]: sustained bidirectional native-channel traffic.
 *
 * Each epoch forks a provider and connects it to the client over a fresh
 * channel pair.  The client keeps a window of requests in flight with payload
 * sizes across every receive size class up to the maximum, attaches pipe
 * descriptors to some requests and cancels some.  The provider answers in a
 * shuffled order (deferring some replies), writes a marker byte through every
 * received descriptor, and sends events with descriptors back.  Every
 * payload carries a checksum; every descriptor is proven by its marker.  At
 * each epoch end the client checks that its descriptor count returned to the
 * baseline and reports live heap and kernel message-zone usage, which must
 * not grow over the run.  Output is one JSON object per epoch.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc_np.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	MAGIC		0x5350434bu	/* "SPCK" */
#define	WINDOW		16
#define	EPOCH_SECONDS	20
#define	MAX_ATTACH	3
#define	KIND_REQUEST	1
#define	KIND_REPLY	2
#define	KIND_EVENT	3

struct header {
	uint32_t magic, kind, seq, length, checksum, nfds;
};

static void
fail(const char *what)
{
	fprintf(stderr, "ipc_soak: FAIL %s: %s\n", what, strerror(errno));
	exit(1);
}

static void
failx(const char *what, uint64_t a, uint64_t b)
{
	fprintf(stderr, "ipc_soak: FAIL %s (%ju, %ju)\n", what, (uintmax_t)a,
	    (uintmax_t)b);
	exit(1);
}

static uint64_t rng_state;
static uint32_t
rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return ((uint32_t)rng_state);
}

/* Payload sizes spanning the small/large kernel zones and receive growth. */
static size_t
pick_length(void)
{
	uint32_t r = rng() % 100;

	if (r < 55)
		return (sizeof(struct header) + rng() % 200);
	if (r < 80)
		return (sizeof(struct header) + 200 + rng() % 900);
	if (r < 95)
		return (sizeof(struct header) + 1100 + rng() % 6000);
	return (MAC_CAPABILITY_MAX_MSG - (rng() % 2 ? 0 : rng() % 64));
}

static uint32_t
checksum(const uint8_t *p, size_t n)
{
	uint32_t h = 2166136261u;

	while (n-- > 0)
		h = (h ^ *p++) * 16777619u;
	return (h);
}

static void
fill(uint8_t *buf, size_t length, uint32_t kind, uint32_t seq, uint32_t nfds)
{
	struct header h;
	size_t i;

	for (i = sizeof(h); i < length; i++)
		buf[i] = (uint8_t)(seq * 131 + i * 7);
	h.magic = MAGIC;
	h.kind = kind;
	h.seq = seq;
	h.length = (uint32_t)length;
	h.checksum = checksum(buf + sizeof(h), length - sizeof(h));
	h.nfds = nfds;
	memcpy(buf, &h, sizeof(h));
}

static struct header
verify(const struct channel_message *m, uint32_t kind)
{
	struct header h;
	size_t length = channel_message_length(m);
	const uint8_t *p = channel_message_data(m);

	if (length < sizeof(h))
		failx("short message", length, kind);
	memcpy(&h, p, sizeof(h));
	if (h.magic != MAGIC || h.kind != kind || h.length != length)
		failx("bad header", h.kind, length);
	if (h.checksum != checksum(p + sizeof(h), length - sizeof(h)))
		failx("payload checksum", h.seq, length);
	if (h.nfds != channel_message_fd_count(m))
		failx("descriptor count", h.nfds, channel_message_fd_count(m));
	return (h);
}

/*
 * Prove each received descriptor: write the expected marker through a
 * request's descriptors (the client reads it back); for events, whose pipe
 * the provider has already closed, check the descriptor is a live FIFO.
 */
static void
mark_descriptors(struct channel_message *m, uint32_t seq, bool write_marker)
{
	uint8_t marker = (uint8_t)seq;
	struct stat st;
	size_t i;
	int fd;

	for (i = 0; i < channel_message_fd_count(m); i++) {
		struct channel_fd_info info;

		/* Pipes; narrowed sends deliver exactly write. */
		if (channel_message_fd_info(m, i, &info) == 0) {
			if (info.type != CHANNEL_FD_TYPE_OTHER)
				failx("descriptor type", info.type,
				    CHANNEL_FD_TYPE_OTHER);
			if ((info.rights & CHANNEL_FD_RIGHTS_EXACT) != 0 &&
			    info.rights != (CHANNEL_FD_RIGHT_WRITE |
			    CHANNEL_FD_RIGHTS_EXACT))
				failx("narrowed rights", info.rights,
				    CHANNEL_FD_RIGHT_WRITE);
		} else if (errno != ENOTSUP) {
			fail("descriptor info");
		}
		fd = channel_message_take_fd(m, i);
		if (fd < 0)
			fail("take descriptor");
		if (write_marker) {
			if (write(fd, &marker, 1) != 1)
				fail("write marker");
		} else if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode)) {
			fail("event descriptor");
		}
		close(fd);
	}
}

/* ------------------------------------------------------------ provider --- */

static struct channel_message *held[8];
static unsigned nheld;
static uint32_t provider_seq;
static uint8_t provider_buf[MAC_CAPABILITY_MAX_MSG];

static void
provider_reply(struct channel_message *request)
{
	struct header h;
	size_t length = pick_length();

	memcpy(&h, channel_message_data(request), sizeof(h));
	fill(provider_buf, length, KIND_REPLY, h.seq, 0);
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(provider_buf,
	    length);
	/* A cancelled request's reply is legitimately dropped by the client. */
	if (channel_send_reply(request, &out) != 0 && errno != EPIPE &&
	    errno != ECONNRESET)
		fail("send reply");
	channel_message_free(request);
}

static void
provider_request(struct channel *channel, struct channel_message *request,
    void *context)
{
	struct header h;

	(void)context;
	h = verify(request, KIND_REQUEST);
	mark_descriptors(request, h.seq, true);
	/* Defer some replies, then answer the held batch in reverse. */
	if (rng() % 4 == 0 && nheld < 8) {
		held[nheld++] = request;
		return;
	}
	provider_reply(request);
	while (nheld > 0)
		provider_reply(held[--nheld]);
	/* Events in the other direction, sometimes carrying a descriptor. */
	if (rng() % 3 == 0) {
		int pipefd[2], nfds = 0;
		size_t length = pick_length();

		if (rng() % 4 == 0) {
			if (pipe(pipefd) != 0)
				fail("pipe");
			nfds = 1;
		}
		fill(provider_buf, length, KIND_EVENT, ++provider_seq,
		    (uint32_t)nfds);
		bool move = nfds != 0 && rng() % 2 == 0;
		struct channel_outgoing out = {
			.size = sizeof(out), .data = provider_buf,
			.length = length, .fds = nfds ? &pipefd[1] : NULL,
			.nfds = (size_t)nfds,
			.flags = move ? CHANNEL_SEND_MOVE : 0,
		};
		if (channel_send_event(channel, &out) != 0) {
			if (errno != EPIPE && errno != ECONNRESET &&
			    errno != ENOBUFS)
				fail("send event");
			move = false;	/* Still ours after a failed send. */
		}
		if (nfds) {
			if (!move)
				close(pipefd[1]);
			close(pipefd[0]);	/* The client's marker write may EPIPE. */
		}
	}
}

static void
run_provider(int fd, uint64_t seed)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel *channel;

	signal(SIGPIPE, SIG_IGN);
	rng_state = seed;
	if (channel_create(fd, &options, &channel) != 0)
		fail("provider channel");
	channel_set_request_handler(channel, provider_request, NULL);
	for (;;) {
		int ready = channel_wait(channel, channel_wants_write(channel),
		    1000);
		if (ready < 0 || channel_dispatch(channel) < 0)
			break;
		/*
		 * Deferred replies are answered out of order within a dispatch
		 * batch, never held across waits: an idle client would
		 * otherwise wait forever for them.
		 */
		while (nheld > 0)
			provider_reply(held[--nheld]);
		if (channel_flush(channel) != 0)
			break;
		if (channel_error(channel) != 0)
			break;
	}
	while (nheld > 0)
		channel_message_free(held[--nheld]);
	channel_destroy(channel);
	_exit(0);
}

/* -------------------------------------------------------------- client --- */

struct slot {
	struct channel_request *request;
	uint32_t seq;
	int readers[MAX_ATTACH];
	int nreaders;
	bool cancelled, done;
};

static struct slot slots[WINDOW];
static uint64_t replies, cancels, events, descriptors, moved, bytes;
static uint8_t client_buf[MAC_CAPABILITY_MAX_MSG];

static void
check_markers(struct slot *slot)
{
	uint8_t marker;
	int i;

	for (i = 0; i < slot->nreaders; i++) {
		if (read(slot->readers[i], &marker, 1) != 1)
			failx("descriptor marker missing", slot->seq, i);
		if (marker != (uint8_t)slot->seq)
			failx("descriptor marker", marker, slot->seq);
		close(slot->readers[i]);
		descriptors++;
	}
	slot->nreaders = 0;
}

static void
client_reply(struct channel_request *request, struct channel_message *reply,
    int error, void *context)
{
	struct slot *slot = context;
	struct header h;

	if (slot->cancelled) {
		if (error != ECANCELED && error != 0)
			failx("cancel status", error, slot->seq);
		if (reply != NULL)
			channel_message_free(reply);
	} else {
		if (error != 0)
			failx("reply error", error, slot->seq);
		h = verify(reply, KIND_REPLY);
		if (h.seq != slot->seq)
			failx("reply matched wrong request", h.seq, slot->seq);
		bytes += channel_message_length(reply);
		channel_message_free(reply);
		replies++;
	}
	channel_request_release(request);
	slot->request = NULL;
	slot->done = true;
}

static void
client_event(struct channel *channel, struct channel_message *event,
    void *context)
{
	struct header h;

	(void)channel;
	(void)context;
	h = verify(event, KIND_EVENT);
	mark_descriptors(event, h.seq, false);
	bytes += channel_message_length(event);
	channel_message_free(event);
	events++;
}

static int
open_descriptors(void)
{
	int n = 0, fd, max = getdtablesize();

	for (fd = 0; fd < max; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return (n);
}

static uint64_t
heap_allocated(void)
{
	uint64_t epoch = 1, allocated = 0;
	size_t len = sizeof(epoch);

	(void)mallctl("epoch", NULL, NULL, &epoch, len);
	len = sizeof(allocated);
	(void)mallctl("stats.allocated", &allocated, &len, NULL, 0);
	return (allocated);
}

static uint64_t
zone_items(const char *zone)
{
	char name[96];
	uint64_t value = 0;
	size_t len = sizeof(value);

	snprintf(name, sizeof(name), "vm.uma.%s.stats.current", zone);
	if (sysctlbyname(name, &value, &len, NULL, 0) != 0)
		return (0);
	return (value);
}

static uint32_t client_seq;

static void
client_send(struct channel *channel, struct slot *slot)
{
	int pipefd[2], fds[MAX_ATTACH], nfds = 0, i;
	size_t length = pick_length();

	memset(slot, 0, sizeof(*slot));
	slot->seq = ++client_seq;
	if (rng() % 8 == 0) {
		nfds = 1 + (int)(rng() % MAX_ATTACH);
		for (i = 0; i < nfds; i++) {
			if (pipe(pipefd) != 0)
				fail("pipe");
			slot->readers[i] = pipefd[0];
			fds[i] = pipefd[1];
		}
		slot->nreaders = nfds;
	}
	fill(client_buf, length, KIND_REQUEST, slot->seq, (uint32_t)nfds);
	/*
	 * Mix descriptor modes: borrowed and closed here, moved, or moved
	 * with expectations that narrow to write and lock inheritance.
	 */
	struct channel_fd_spec specs[MAX_ATTACH];
	unsigned mode = nfds != 0 ? rng() % 3 : 0;
	memset(specs, 0, sizeof(specs));
	for (i = 0; i < nfds; i++) {
		specs[i].rights = CHANNEL_FD_RIGHT_WRITE;
		specs[i].flags = (i % 2) ? CHANNEL_FD_LOCK_INHERIT : 0;
	}
	struct channel_outgoing out = {
		.size = sizeof(out), .data = client_buf, .length = length,
		.fds = nfds ? fds : NULL, .nfds = (size_t)nfds,
		.fd_specs = mode == 2 ? specs : NULL,
		.flags = mode != 0 ? CHANNEL_SEND_MOVE : 0,
	};
	if (channel_send_request(channel, &out, client_reply, slot,
	    &slot->request) != 0)
		fail("send request");
	if (mode == 0)
		for (i = 0; i < nfds; i++)
			close(fds[i]);
	else
		moved += (uint64_t)nfds;
	/* Cancel a few in flight; their markers may still arrive or not. */
	if (nfds == 0 && rng() % 32 == 0) {
		slot->cancelled = true;
		(void)channel_request_cancel(slot->request);
		cancels++;
	}
}

static void
run_epoch(uint64_t seed, double seconds)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel *channel;
	struct timespec start, now;
	int ends[2], status, i;
	pid_t child;

	if (mac_capability_channel_create(ends) != 0)
		fail("channel pair");
	child = fork();
	if (child < 0)
		fail("fork");
	if (child == 0) {
		close(ends[0]);
		run_provider(ends[1], seed ^ 0x9e3779b97f4a7c15ull);
	}
	close(ends[1]);
	if (channel_create(ends[0], &options, &channel) != 0)
		fail("client channel");
	channel_set_event_handler(channel, client_event, NULL);
	for (i = 0; i < WINDOW; i++)
		slots[i].done = true;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		bool stop = (now.tv_sec - start.tv_sec) +
		    (now.tv_nsec - start.tv_nsec) / 1e9 >= seconds;
		bool busy = false;
		for (i = 0; i < WINDOW; i++) {
			if (slots[i].done) {
				if (slots[i].seq != 0 && !slots[i].cancelled)
					check_markers(&slots[i]);
				else {
					/* A cancelled request may not deliver
					 * its descriptors; just close. */
					for (int j = 0; j < slots[i].nreaders;
					     j++)
						close(slots[i].readers[j]);
					slots[i].nreaders = 0;
				}
				slots[i].seq = 0;
				if (!stop)
					client_send(channel, &slots[i]);
			}
			if (!slots[i].done)
				busy = true;
		}
		if (stop && !busy)
			break;
		if (channel_wait(channel, channel_wants_write(channel), 5000) <=
		    0)
			fail("client wait");
		if (channel_dispatch(channel) < 0 || channel_flush(channel) != 0)
			fail("client dispatch");
	}
	channel_destroy(channel);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		failx("provider exit", (uint64_t)status, 0);
}

int
main(int argc, char **argv)
{
	double total, elapsed = 0;
	struct timespec start, now;
	uint64_t seed;
	int baseline_fds, fds, epoch = 0;
	uint64_t heap0 = 0, small0 = 0, large0 = 0;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: ipc_soak seconds [seed]\n");
		return (2);
	}
	signal(SIGPIPE, SIG_IGN);
	total = strtod(argv[1], NULL);
	seed = argc == 3 ? strtoull(argv[2], NULL, 0) : (uint64_t)getpid();
	rng_state = seed | 1;
	baseline_fds = open_descriptors();
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (elapsed < total) {
		double length = total - elapsed < EPOCH_SECONDS ?
		    total - elapsed : EPOCH_SECONDS;
		run_epoch(seed + (uint64_t)epoch, length);
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed = (now.tv_sec - start.tv_sec) +
		    (now.tv_nsec - start.tv_nsec) / 1e9;
		fds = open_descriptors();
		uint64_t heap = heap_allocated();
		uint64_t small = zone_items("mac_capability_msg_small");
		uint64_t large = zone_items("mac_capability_msg");
		if (epoch == 0) {
			heap0 = heap;
			small0 = small;
			large0 = large;
		}
		printf("{\"epoch\":%d,\"seconds\":%.1f,\"replies\":%ju,"
		       "\"cancels\":%ju,\"events\":%ju,\"descriptors\":%ju,"
		       "\"moved\":%ju,\"bytes\":%ju,\"open_fds\":%d,\"heap_allocated\":%ju,"
		       "\"kernel_small_msgs\":%ju,\"kernel_large_msgs\":%ju}\n",
		    epoch, elapsed, (uintmax_t)replies, (uintmax_t)cancels,
		    (uintmax_t)events, (uintmax_t)descriptors,
		    (uintmax_t)moved, (uintmax_t)bytes, fds, (uintmax_t)heap, (uintmax_t)small,
		    (uintmax_t)large);
		fflush(stdout);
		if (fds != baseline_fds)
			failx("descriptor leak", (uint64_t)fds,
			    (uint64_t)baseline_fds);
		/* Allow allocator caches to settle; reject steady growth. */
		if (epoch > 0 && heap > heap0 + 4 * 1024 * 1024)
			failx("heap growth", heap, heap0);
		if (epoch > 0 && small > small0 + 64)
			failx("kernel small message growth", small, small0);
		if (epoch > 0 && large > large0 + 64)
			failx("kernel large message growth", large, large0);
		epoch++;
	}
	if (replies == 0 || descriptors == 0 || events == 0)
		failx("no traffic", replies, descriptors);
	printf("ipc_soak: PASS epochs=%d replies=%ju descriptors=%ju "
	       "events=%ju\n", epoch, (uintmax_t)replies,
	    (uintmax_t)descriptors, (uintmax_t)events);
	return (0);
}
