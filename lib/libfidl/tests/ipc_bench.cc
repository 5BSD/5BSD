/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Comparative cross-process request/reply measurement over one native
 * channel. Modes share the same encoded message size:
 *   raw  libchannel request/reply with pre-encoded FIDL bytes (no codec)
 *   cpp  generated C++ client/server bindings
 *   c    generated C client/server bindings
 * Reports per-call latency percentiles, throughput and client/server heap
 * allocation counts per call. Link statically with
 * -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free.
 */
#include <sys/capsicum.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <fidl/bsd.runtime.test/c/bsd.h>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
#include <fidl/bsd/runtime.h>
#include <iterator>
#include <new>
#include <string>
#include <unistd.h>
#include <vector>

namespace types = bsd_runtime_test;
namespace bindings = bsd_runtime_test::bsd;
using fidl::bsd::Connection;
using fidl::bsd::Descriptor;

static std::atomic<uint64_t> allocations, allocated_bytes;
extern "C" {
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
void *
__wrap_malloc(size_t size)
{
	allocations.fetch_add(1, std::memory_order_relaxed);
	allocated_bytes.fetch_add(size, std::memory_order_relaxed);
	return __real_malloc(size);
}
void *
__wrap_calloc(size_t count, size_t size)
{
	allocations.fetch_add(1, std::memory_order_relaxed);
	allocated_bytes.fetch_add(count * size, std::memory_order_relaxed);
	return __real_calloc(count, size);
}
void *
__wrap_realloc(void *p, size_t size)
{
	allocations.fetch_add(1, std::memory_order_relaxed);
	allocated_bytes.fetch_add(size, std::memory_order_relaxed);
	return __real_realloc(p, size);
}
void
__wrap_free(void *p)
{
	__real_free(p);
}
}
void *
operator new(size_t size)
{
	if (void *p = __wrap_malloc(size ? size : 1))
		return p;
	throw std::bad_alloc();
}
void *
operator new[](size_t size)
{
	return operator new(size);
}
void
operator delete(void *p) noexcept
{
	__wrap_free(p);
}
void
operator delete[](void *p) noexcept
{
	__wrap_free(p);
}
void
operator delete(void *p, size_t) noexcept
{
	__wrap_free(p);
}
void
operator delete[](void *p, size_t) noexcept
{
	__wrap_free(p);
}

static constexpr uint64_t kRoundTrip = 8323773374816640790ULL;

static void
die(const char *what)
{
	fprintf(stderr, "ipc_bench: %s: %s\n", what, strerror(errno));
	exit(1);
}

struct Counters {
	uint64_t allocations, bytes;
};
static Counters
Snapshot()
{
	return { allocations.load(), allocated_bytes.load() };
}

static uint64_t warmup_calls, served;
static Counters served_start;
static void
CountServed()
{
	if (served == warmup_calls)
		served_start = Snapshot();
	++served;
}

/* Servers run until the client closes, then report allocations. */
static void
ReportServer(int report, Counters start, uint64_t calls)
{
	Counters end = Snapshot();
	uint64_t values[3] = { end.allocations - start.allocations,
		end.bytes - start.bytes, calls };
	if (write(report, values, sizeof(values)) != sizeof(values))
		die("report");
}

static void
RawReply(channel *, channel_message *message, void *)
{
	CountServed();
	channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(
	    channel_message_data(message), channel_message_length(message));
	if (channel_send_reply(message, &view) != 0)
		die("raw reply");
	channel_message_free(message);
}


static void
ServeRaw(int fd, int report)
{
	channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	channel *server;
	if (channel_create(fd, &options, &server) != 0)
		die("raw server");
	channel_set_request_handler(server, RawReply, nullptr);
	for (;;) {
		if (channel_wait(server, channel_wants_write(server), 1000) < 0)
			break;
		if (channel_dispatch(server) < 0 || channel_flush(server) != 0)
			break;
	}
	ReportServer(report, served_start, served - warmup_calls);
	channel_destroy(server);
}

struct CppServer : bindings::ServiceServer {
	Connection &connection;
	explicit CppServer(Connection &c)
	    : connection(c)
	{
	}
	void RoundTrip(types::Request request,
	    std::unique_ptr<fidl::bsd::Incoming> context) override
	{
		CountServed();
		if (ReplyRoundTrip(connection, *context,
			types::Response(std::move(request.text()))) != 0)
			die("cpp reply");
	}
	void Take(types::ReadOnly value,
	    std::unique_ptr<fidl::bsd::Incoming> context) override
	{
		CountServed();
		value = types::ReadOnly();	// Close the received descriptor.
		if (ReplyTake(connection, *context, types::Response("")) != 0)
			die("cpp take reply");
	}
	void Notify(types::Request, std::unique_ptr<fidl::bsd::Incoming>) override
	{
	}
};

static void
ServeCpp(int fd, int report)
{
	auto created = Connection::Create(fd, CHANNEL_ROLE_PROVIDER);
	if (created.is_error())
		die("cpp server");
	auto &connection = *created.value();
	CppServer server(connection);
	connection.SetRequestHandler([&](auto message) {
		server.Dispatch(connection, std::move(message));
	});
	while (connection.Poll(1000) == 0) {
	}
	ReportServer(report, served_start, served - warmup_calls);
}

static void
CReply(void *, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	CountServed();
	struct bsd_runtime_test_Response response = { value->text,
		value->text_size };
	if (bsd_runtime_test_Service_RoundTrip_reply(connection, request,
		&response) != 0)
		die("c reply");
}

static void
CTake(void *, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_ReadOnly *)
{
	CountServed();
	struct bsd_runtime_test_Response response = { "", 0 };
	if (bsd_runtime_test_Service_Take_reply(connection, request,
		&response) != 0)
		die("c take reply");
}

static void
ServeC(int fd, int report)
{
	struct fidl_bsd_connection *server;
	if (fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &server) != 0)
		die("c server");
	struct bsd_runtime_test_Service_server handlers = {};
	handlers.RoundTrip = CReply;
	handlers.Take = CTake;
	if (bsd_runtime_test_Service_bind(server, &handlers, nullptr) != 0)
		die("c bind");
	while (fidl_bsd_connection_poll(server, 1000) == 0) {
	}
	ReportServer(report, served_start, served - warmup_calls);
	fidl_bsd_connection_destroy(server);
}

struct RawClient {
	channel *ch;
	std::vector<uint8_t> bytes;
	bool done = false;
	static void Reply(channel_request *request, channel_message *message,
	    int error, void *context)
	{
		auto *self = static_cast<RawClient *>(context);
		if (error || channel_message_length(message) != self->bytes.size())
			die("raw reply mismatch");
		channel_message_free(message);
		channel_request_release(request);
		self->done = true;
	}
	void Call()
	{
		channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(
		    bytes.data(), bytes.size());
		channel_request *request;
		done = false;
		if (channel_send_request(ch, &view, Reply, this, &request) != 0)
			die("raw send");
		while (!done) {
			if (channel_wait(ch, channel_wants_write(ch), 1000) < 0 ||
			    channel_dispatch(ch) < 0 || channel_flush(ch) != 0)
				die("raw wait");
		}
	}
};

static bool c_done;
static void
CDone(void *, int error, struct bsd_runtime_test_Response *)
{
	if (error)
		die("c call");
	c_done = true;
}

int
main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage: ipc_bench raw|cpp|c|cppfd|cfd PAYLOAD "
				"CALLS WARMUP\n"
				"  cppfd, cfd: each call sends one descriptor (Take);\n"
				"  IPC_BENCH_LEGACY=1 allowlists the older channel "
				"ioctls, forcing userland descriptor checks\n");
		return 2;
	}
	std::string mode = argv[1];
	size_t payload = strtoul(argv[2], nullptr, 10);
	uint64_t calls = strtoull(argv[3], nullptr, 10);
	warmup_calls = strtoull(argv[4], nullptr, 10);
	std::string text(payload, 'x');
	int ends[2], report[2];
	if (mac_capability_channel_create(ends) != 0 || pipe(report) != 0)
		die("setup");
	if (getenv("IPC_BENCH_LEGACY") != nullptr) {
		static const cap_ioctl_t older[] = { MAC_CAPABILITY_GETINFO,
			MAC_CAPABILITY_SENDMSG, MAC_CAPABILITY_RECVMSG,
			MAC_CAPABILITY_RECVMSG_V2, MAC_CAPABILITY_RECVMSG_V3 };
		if (cap_ioctls_limit(ends[0], older, std::size(older)) != 0 ||
		    cap_ioctls_limit(ends[1], older, std::size(older)) != 0)
			die("legacy allowlist");
	}
	bool with_fd = mode == "cppfd" || mode == "cfd";
	int lend[2];
	if (with_fd && pipe(lend) != 0)
		die("pipe");
	pid_t child = fork();
	if (child < 0)
		die("fork");
	if (child == 0) {
		close(ends[0]);
		close(report[0]);
		if (mode == "raw")
			ServeRaw(ends[1], report[1]);
		else if (mode == "cpp" || mode == "cppfd")
			ServeCpp(ends[1], report[1]);
		else
			ServeC(ends[1], report[1]);
		_exit(0);
	}
	close(ends[1]);
	close(report[1]);

	std::vector<double> samples;
	samples.reserve(calls);
	std::unique_ptr<Connection> cpp;
	struct fidl_bsd_connection *c = nullptr;
	RawClient raw {};
	if (mode == "raw") {
		auto packet = fidl::bsd::Outgoing::Encode(types::Request(text), 1,
		    kRoundTrip);
		if (packet.is_error())
			die("encode");
		auto v = packet.value()->view();
		auto *b = static_cast<const uint8_t *>(v.data);
		raw.bytes.assign(b, b + v.length);
		channel_options options = CHANNEL_OPTIONS_INITIALIZER(
		    CHANNEL_ROLE_CLIENT);
		if (channel_create(ends[0], &options, &raw.ch) != 0)
			die("raw client");
	} else if (mode == "cpp" || mode == "cppfd") {
		auto created = Connection::Create(ends[0], CHANNEL_ROLE_CLIENT);
		if (created.is_error())
			die("cpp client");
		cpp = std::move(created.value());
	} else if (fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT, &c) !=
	    0)
		die("c client");
	std::unique_ptr<bindings::ServiceClient> client;
	if (cpp)
		client = std::make_unique<bindings::ServiceClient>(*cpp);
	struct bsd_runtime_test_Request c_request = { text.data(), text.size() };

	struct bsd_runtime_test_ReadOnly c_lent = { with_fd ? lend[0] : -1 };
	auto one = [&]() {
		if (mode == "raw") {
			raw.Call();
		} else if (mode == "cppfd") {
			// C++ fields own their descriptor: one dup per call.
			bool done = false;
			auto id = client->Take(
			    types::ReadOnly(Descriptor(dup(lend[0]))),
			    [&](auto result) {
				    if (result.is_error())
					    die("cppfd call");
				    done = true;
			    });
			if (id.is_error())
				die("cppfd send");
			while (!done)
				if (cpp->Poll(1000) != 0)
					die("cppfd poll");
		} else if (mode == "cfd") {
			// C lends the same descriptor every call.
			uint32_t txid;
			c_done = false;
			if (bsd_runtime_test_Service_Take(c, &c_lent, CDone,
				nullptr, &txid) != 0)
				die("cfd send");
			while (!c_done)
				if (fidl_bsd_connection_poll(c, 1000) != 0)
					die("cfd poll");
		} else if (mode == "cpp") {
			bool done = false;
			auto id = client->RoundTrip(types::Request(text),
			    [&](auto result) {
				    if (result.is_error())
					    die("cpp call");
				    done = true;
			    });
			if (id.is_error())
				die("cpp send");
			while (!done)
				if (cpp->Poll(1000) != 0)
					die("cpp poll");
		} else {
			uint32_t txid;
			c_done = false;
			if (bsd_runtime_test_Service_RoundTrip(c, &c_request,
				CDone, nullptr, &txid) != 0)
				die("c send");
			while (!c_done)
				if (fidl_bsd_connection_poll(c, 1000) != 0)
					die("c poll");
		}
	};
	for (uint64_t i = 0; i < warmup_calls; ++i)
		one();
	Counters start = Snapshot();
	auto begin = std::chrono::steady_clock::now();
	for (uint64_t i = 0; i < calls; ++i) {
		auto t0 = std::chrono::steady_clock::now();
		one();
		samples.push_back(std::chrono::duration<double, std::micro>(
		    std::chrono::steady_clock::now() - t0)
				      .count());
	}
	double elapsed = std::chrono::duration<double>(
	    std::chrono::steady_clock::now() - begin)
			     .count();
	Counters end = Snapshot();
	client.reset();
	cpp.reset();
	if (c)
		fidl_bsd_connection_destroy(c);
	if (raw.ch)
		channel_destroy(raw.ch);
	uint64_t server[3] = {};
	if (read(report[0], server, sizeof(server)) != sizeof(server))
		die("server report");
	int status;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		die("server exit");
	if (server[2] != calls) {
		fprintf(stderr, "ipc_bench: server measured %ju of %ju calls\n",
		    (uintmax_t)server[2], (uintmax_t)calls);
		return 1;
	}
	std::sort(samples.begin(), samples.end());
	auto pct = [&](double p) {
		return samples[std::min(samples.size() - 1,
		    static_cast<size_t>(p * samples.size()))];
	};
	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	if (getenv("IPC_BENCH_LEGACY") != nullptr)
		mode += "-legacy";
	printf("{\"mode\":\"%s\",\"payload\":%zu,\"message_bytes\":%zu,"
	       "\"calls\":%ju,\"seconds\":%.6f,\"calls_per_second\":%.1f,"
	       "\"p50_us\":%.2f,\"p90_us\":%.2f,\"p99_us\":%.2f,\"max_us\":%.2f,"
	       "\"client_allocations_per_call\":%.2f,"
	       "\"client_bytes_per_call\":%.1f,"
	       "\"server_allocations_per_call\":%.2f,"
	       "\"server_bytes_per_call\":%.1f,\"client_maxrss_kib\":%ld}\n",
	    mode.c_str(), payload, 16 + 16 + ((payload + 7) & ~size_t(7)),
	    (uintmax_t)calls, elapsed, calls / elapsed, pct(0.50), pct(0.90),
	    pct(0.99), samples.back(),
	    double(end.allocations - start.allocations) / calls,
	    double(end.bytes - start.bytes) / calls,
	    double(server[0]) / calls, double(server[1]) / calls,
	    usage.ru_maxrss);
	return 0;
}
