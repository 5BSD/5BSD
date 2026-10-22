/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Comparative cross-process IPC measurement over one native channel.
 *
 * Modes share the same encoded messages:
 *   raw  libchannel with pre-encoded FIDL bytes (no codec)
 *   cpp  generated C++ bindings.  The ManyResources and Large payloads,
 *        which no test protocol method carries, go through the same
 *        Connection::Call/Reply the generated methods wrap.
 *   c    generated C bindings.  ManyResources and Large use the generated
 *        C wire codecs through the same CallRaw/ReplyRaw the generated
 *        methods wrap.
 *
 * Scenarios (ipc_bench list): synchronous round trips, pipelined requests
 * with a window of outstanding calls, descriptor-heavy calls (borrowed or
 * moved; request-only or echoed back), event bursts, payloads up to the
 * 14,336-byte message ceiling, and a mixed workload.
 *
 * Each run reports latency percentiles of its sample unit, throughput,
 * client and server heap allocations per request (link-time wrappers) and,
 * from a short self-ktrace(2) phase that needs no privilege, system calls
 * per request in both processes.  Output is one JSON line per run.  Link
 * statically with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free.
 */
#include <sys/capsicum.h>
#include <sys/cpuset.h>
#include <sys/ktrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <map>
#include <new>
#include <string>
#include <unistd.h>
#include <vector>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <fidl/bsd/c_bridge.h>
#include <fidl/bsd/c_wire.h>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
#include <fidl/bsd.runtime.test/c/bridge.h>
#include <fidl/bsd/runtime.h>

namespace types = bsd_runtime_test;
namespace bindings = bsd_runtime_test::bsd;
namespace cwire = fidl::bsd::cwire;
using fidl::bsd::Connection;
using fidl::bsd::Descriptor;
using fidl::bsd::Incoming;
using fidl::bsd::Outgoing;
using namespace fidl::bsd::generated;

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

/* Service.RoundTrip and Service.Changed from the generated bindings. */
static constexpr uint64_t kRoundTrip = 8323773374816640790ULL;
static constexpr uint64_t kChanged = 7764275307639556784ULL;
/*
 * Methods the test schema does not declare, dispatched by hand through the
 * runtime entry points the generated bindings wrap: ManyResources ->
 * ManyResources, Large -> Large, and Request -> Response after a burst of
 * Changed events.
 */
static constexpr uint64_t kMany = 0x1c2a9d0f6b43e715ULL;
static constexpr uint64_t kLarge = 0x2b7f0e9a5c31d826ULL;
static constexpr uint64_t kBurst = 0x3e8c1b7d2a94f037ULL;

static void
die(const char *what)
{
	fprintf(stderr, "ipc_bench: %s: %s\n", what, strerror(errno));
	exit(1);
}

enum class Mode { Raw, Cpp, C };
enum class Dir { None, Request, Both };
enum class Transfer { None, Borrow, Move };
enum class Op { Small, Medium, Take, Many, Large, Burst };

struct Spec {
	std::string scenario, name;
	size_t payload = 8;	/* text bytes (Large: vector bytes) */
	size_t window = 1;	/* outstanding requests */
	size_t fds = 0;		/* descriptors per Many message */
	Dir dir = Dir::None;
	Transfer transfer = Transfer::None;
	size_t events = 0;	/* Changed events per burst */
	bool burst_on_roundtrip = false;	/* events scenario */
	bool take = false;	/* generated Service.Take, one descriptor */
	bool large = false;
	bool mixed = false;
};
static Spec spec;
static Mode mode;
/*
 * Synchronous scenarios (window 1) issue each request through the one-call
 * path (channel_call_request, fidl_bsd_connection_call, Connection::CallSync),
 * which kernels with MAC_CAPABILITY_CHANNEL_CALL complete in one system call;
 * IPC_BENCH_NO_CALL=1 keeps the send/wait/receive sequence for comparison.
 */
static bool sync_call;
static std::string small_text, medium_text;
static std::vector<uint8_t> large_bytes;
static int lend_fd = -1;
static std::vector<int> template_fds;

static const char *
ModeName(Mode m)
{
	return m == Mode::Raw ? "raw" : m == Mode::Cpp ? "cpp" : "c";
}

static double
NowUs()
{
	return std::chrono::duration<double, std::micro>(
	    std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

static void
Pin(int cpu)
{
	if (cpu < 0)
		return;
	cpuset_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(set),
		&set) != 0)
		die("cpuset_setaffinity");
}

struct Counters {
	uint64_t allocations, bytes;
};
static Counters
Snapshot()
{
	return { allocations.load(), allocated_bytes.load() };
}

/* Server side: requests served, with allocation snapshots around the timed
 * window (warmup_requests .. warmup_requests + measured_requests). */
static uint64_t warmup_requests, measured_requests, served;
static Counters served_start, served_end;
static bool served_end_taken;
static void
CountServed()
{
	if (served == warmup_requests)
		served_start = Snapshot();
	if (served == warmup_requests + measured_requests) {
		served_end = Snapshot();
		served_end_taken = true;
	}
	++served;
}

static void
ReportServer(int report)
{
	if (!served_end_taken)
		served_end = Snapshot();
	uint64_t values[3] = { served_end.allocations - served_start.allocations,
		served_end.bytes - served_start.bytes, served };
	if (write(report, values, sizeof(values)) != sizeof(values))
		die("report");
}

static std::vector<uint8_t>
EncodeBytes(std::unique_ptr<Outgoing> packet)
{
	auto v = packet->view();
	auto *b = static_cast<const uint8_t *>(v.data);
	return std::vector<uint8_t>(b, b + v.length);
}
template <typename T>
static std::vector<uint8_t>
Encode(T value, uint32_t txid, uint64_t ordinal)
{
	auto packet = Outgoing::Encode(std::move(value), txid, ordinal);
	if (packet.is_error()) {
		errno = packet.error_value();
		die("encode");
	}
	/* The packet closes any descriptors it was given. */
	return EncodeBytes(std::move(packet.value()));
}
static std::vector<Descriptor>
DupDescriptors(size_t count)
{
	std::vector<Descriptor> result;
	for (size_t i = 0; i < count; ++i) {
		int fd = dup(lend_fd);
		if (fd < 0)
			die("dup");
		result.emplace_back(fd);
	}
	return result;
}

/* ---------------------------------------------------------------- raw */

struct RawServer {
	channel *ch = nullptr;
	channel_message *pending = nullptr;
	std::vector<uint8_t> event_bytes;

	static void OnRequest(channel *, channel_message *m, void *ctx)
	{
		auto *self = static_cast<RawServer *>(ctx);
		CountServed();
		uint64_t ordinal;
		memcpy(&ordinal,
		    static_cast<const uint8_t *>(channel_message_data(m)) + 8,
		    sizeof(ordinal));
		if (ordinal == kBurst ||
		    (spec.burst_on_roundtrip && ordinal == kRoundTrip)) {
			if (self->pending)
				die("raw burst overlap");
			self->pending = m;
			return;
		}
		self->Reply(m);
	}
	void Reply(channel_message *m)
	{
		channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(
		    channel_message_data(m), channel_message_length(m));
		int fds[MAC_CAPABILITY_MAX_FDS];
		size_t n = channel_message_fd_count(m);
		if (spec.dir == Dir::Both && n) {
			for (size_t i = 0; i < n; ++i) {
				fds[i] = spec.transfer == Transfer::Move ?
				    channel_message_take_fd(m, i) :
				    channel_message_borrow_fd(m, i);
				if (fds[i] < 0)
					die("raw reply fd");
			}
			view.fds = fds;
			view.nfds = n;
			if (spec.transfer == Transfer::Move)
				view.flags = CHANNEL_SEND_MOVE;
		}
		if (channel_send_reply(m, &view) != 0)
			die("raw reply");
		channel_message_free(m);
	}
	void Burst()
	{
		channel_outgoing ev = CHANNEL_OUTGOING_INITIALIZER(
		    event_bytes.data(), event_bytes.size());
		for (size_t i = 0; i < spec.events; ++i) {
			while (channel_send_event(ch, &ev) != 0) {
				if (errno != ENOBUFS && errno != EAGAIN)
					die("raw event");
				if (channel_wait(ch, 1, 1000) < 0 ||
				    channel_flush(ch) != 0)
					die("raw event flush");
			}
		}
		channel_message *m = pending;
		pending = nullptr;
		Reply(m);
	}
	void Run(int fd, int report)
	{
		channel_options options = CHANNEL_OPTIONS_INITIALIZER(
		    CHANNEL_ROLE_PROVIDER);
		if (channel_create(fd, &options, &ch) != 0)
			die("raw server");
		event_bytes = Encode(types::Response(small_text), 0, kChanged);
		channel_set_request_handler(ch, OnRequest, this);
		for (;;) {
			if (channel_wait(ch, channel_wants_write(ch), 1000) < 0)
				break;
			if (channel_dispatch(ch) < 0 || channel_flush(ch) != 0)
				break;
			if (pending)
				Burst();
		}
		ReportServer(report);
		channel_destroy(ch);
	}
};

/* ---------------------------------------------------------------- cpp */

struct CppServer : bindings::ServiceServer {
	Connection &connection;
	std::unique_ptr<Incoming> pending;
	explicit CppServer(Connection &c)
	    : connection(c)
	{
	}
	void RoundTrip(types::Request request,
	    std::unique_ptr<Incoming> context) override
	{
		CountServed();
		if (spec.burst_on_roundtrip) {
			pending = std::move(context);
			return;
		}
		if (ReplyRoundTrip(connection, *context,
			types::Response(std::move(request.text()))) != 0)
			die("cpp reply");
	}
	void Take(types::ReadOnly value,
	    std::unique_ptr<Incoming> context) override
	{
		CountServed();
		value = types::ReadOnly();	/* Close the received descriptor. */
		if (ReplyTake(connection, *context, types::Response("")) != 0)
			die("cpp take reply");
	}
	void Notify(types::Request, std::unique_ptr<Incoming>) override
	{
	}
	void Handle(std::unique_ptr<Incoming> message)
	{
		switch (message->header().ordinal) {
		case kMany: {
			CountServed();
			auto decoded = message->Decode<types::ManyResources>();
			if (decoded.is_error())
				die("cpp many decode");
			types::ManyResources reply;
			if (spec.dir == Dir::Both)
				reply.fds() = std::move(decoded->fds());
			if (connection.Reply(*message, std::move(reply)) != 0)
				die("cpp many reply");
			return;
		}
		case kLarge: {
			CountServed();
			auto decoded = message->Decode<types::Large>();
			if (decoded.is_error())
				die("cpp large decode");
			if (connection.Reply(*message,
				types::Large(std::move(decoded->bytes()))) != 0)
				die("cpp large reply");
			return;
		}
		case kBurst: {
			CountServed();
			auto decoded = message->Decode<types::Request>();
			if (decoded.is_error())
				die("cpp burst decode");
			if (pending)
				die("cpp burst overlap");
			pending = std::move(message);
			return;
		}
		default:
			Dispatch(connection, std::move(message));
		}
	}
	void Burst()
	{
		for (size_t i = 0; i < spec.events; ++i) {
			int err;
			while ((err = Changed(connection,
				    types::Response(small_text))) == ENOBUFS)
				if (connection.Poll(1000) != 0)
					die("cpp event flush");
			if (err) {
				errno = err;
				die("cpp event");
			}
		}
		auto m = std::move(pending);
		if (connection.Reply(*m, types::Response(small_text)) != 0)
			die("cpp burst reply");
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
	connection.SetRequestHandler(
	    [&](auto message) { server.Handle(std::move(message)); });
	while (connection.Poll(1000) == 0)
		if (server.pending)
			server.Burst();
	ReportServer(report);
}

/* ------------------------------------------------------------------ c */

static fidl_bsd_request *c_pending;
static void
CReply(void *, fidl_bsd_connection *connection, fidl_bsd_request *request,
    bsd_runtime_test_Request *value)
{
	CountServed();
	if (spec.burst_on_roundtrip) {
		if (c_pending)
			die("c burst overlap");
		fidl_bsd_request_retain(request);
		c_pending = request;
		return;
	}
	bsd_runtime_test_Response response = { value->text, value->text_size };
	if (bsd_runtime_test_Service_RoundTrip_reply(connection, request,
		&response) != 0)
		die("c reply");
}

static void
CTake(void *, fidl_bsd_connection *connection, fidl_bsd_request *request,
    bsd_runtime_test_ReadOnly *)
{
	CountServed();
	bsd_runtime_test_Response response = { "", 0 };
	if (bsd_runtime_test_Service_Take_reply(connection, request,
		&response) != 0)
		die("c take reply");
}

static void
CBurstEvents(fidl_bsd_connection *server)
{
	bsd_runtime_test_Response event = { small_text.data(),
		small_text.size() };
	for (size_t i = 0; i < spec.events; ++i) {
		int err;
		while ((err = bsd_runtime_test_Service_Changed(server, &event)) ==
		    ENOBUFS)
			if (fidl_bsd_connection_poll(server, 1000) != 0)
				die("c event flush");
		if (err) {
			errno = err;
			die("c event");
		}
	}
}

/* Generated server for the methods the schema declares. */
static void
ServeCGenerated(fidl_bsd_connection *server, int report)
{
	bsd_runtime_test_Service_server handlers = {};
	handlers.RoundTrip = CReply;
	handlers.Take = CTake;
	if (bsd_runtime_test_Service_bind(server, &handlers, nullptr) != 0)
		die("c bind");
	while (fidl_bsd_connection_poll(server, 1000) == 0) {
		if (c_pending == nullptr)
			continue;
		CBurstEvents(server);
		bsd_runtime_test_Response response = { small_text.data(),
			small_text.size() };
		if (bsd_runtime_test_Service_RoundTrip_reply(server, c_pending,
			&response) != 0)
			die("c burst reply");
		fidl_bsd_request_release(c_pending);
		c_pending = nullptr;
	}
	ReportServer(report);
}

/* The generated C wire codecs through the runtime's raw entry points, as the
 * generator would emit for ManyResources/Large methods. */
template <typename T, typename Dec>
static void
CDecode(Incoming &incoming, cwire::Decoder &d, T *value, Dec dec)
{
	size_t at;
	if (d.Begin(incoming) || !d.Claim(16, &at) || !dec(d, at, value, 0) ||
	    !d.Finish()) {
		errno = EPROTO;
		die("c wire decode");
	}
}
template <typename T, typename Enc>
static auto
CEncoder(const T *value, Enc enc)
{
	return [value, enc](Outgoing &out) -> int {
		cwire::Encoder e(out);
		size_t at = e.Alloc(16);
		enc(e, value, at, 0);
		return e.error();
	};
}

static void
ServeCWire(fidl_bsd_connection *server, int report)
{
	Connection &conn = *server->value;
	std::unique_ptr<Incoming> pending;
	conn.SetRequestHandler([&](std::unique_ptr<Incoming> message) {
		CountServed();
		cwire::Arena arena;
		cwire::Decoder d(arena);
		int err = 0;
		switch (message->header().ordinal) {
		case kRoundTrip: {
			bsd_runtime_test_Request v {};
			CDecode(*message, d, &v, CWDec_bsd_runtime_test_Request);
			bsd_runtime_test_Response r = { v.text, v.text_size };
			err = conn.ReplyRaw(*message, false,
			    CEncoder(&r, CWEnc_bsd_runtime_test_Response));
			break;
		}
		case kMany: {
			bsd_runtime_test_ManyResources v {};
			CDecode(*message, d, &v,
			    CWDec_bsd_runtime_test_ManyResources);
			bsd_runtime_test_ManyResources r = { nullptr, 0 };
			if (spec.dir == Dir::Both)
				r = v;	/* lends the received descriptors */
			err = conn.ReplyRaw(*message, false,
			    CEncoder(&r, CWEnc_bsd_runtime_test_ManyResources));
			break;
		}
		case kLarge: {
			bsd_runtime_test_Large v {};
			CDecode(*message, d, &v, CWDec_bsd_runtime_test_Large);
			err = conn.ReplyRaw(*message, false,
			    CEncoder(&v, CWEnc_bsd_runtime_test_Large));
			break;
		}
		case kBurst: {
			bsd_runtime_test_Request v {};
			CDecode(*message, d, &v, CWDec_bsd_runtime_test_Request);
			if (pending)
				die("c burst overlap");
			pending = std::move(message);
			return;
		}
		default:
			errno = EPROTO;
			die("c wire ordinal");
		}
		if (err) {
			errno = err;
			die("c wire reply");
		}
	});
	while (fidl_bsd_connection_poll(server, 1000) == 0) {
		if (!pending)
			continue;
		CBurstEvents(server);
		bsd_runtime_test_Response r = { small_text.data(),
			small_text.size() };
		auto m = std::move(pending);
		int err = conn.ReplyRaw(*m, false,
		    CEncoder(&r, CWEnc_bsd_runtime_test_Response));
		if (err) {
			errno = err;
			die("c burst reply");
		}
	}
	ReportServer(report);
}

static bool
CServerIsGenerated()
{
	return !spec.large && !spec.mixed && (spec.fds == 0 || spec.take);
}

static void
ServeC(int fd, int report)
{
	fidl_bsd_connection *server;
	if (fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &server) != 0)
		die("c server");
	if (CServerIsGenerated())
		ServeCGenerated(server, report);
	else
		ServeCWire(server, report);
	fidl_bsd_connection_destroy(server);
}

/* ------------------------------------------------------------ clients */

struct Slot {
	double t0 = 0;
	bool busy = false;
	Op op = Op::Small;
};

struct Driver {
	std::vector<double> samples;
	bool per_op_timing = false;
	size_t completed = 0, inflight = 0;
	void Complete(Slot *slot)
	{
		if (per_op_timing)
			samples.push_back(NowUs() - slot->t0);
		slot->busy = false;
		++completed;
		--inflight;
	}
};
static Driver *g_driver;

struct Client {
	virtual ~Client() = default;
	virtual void Issue(Op op, Slot *slot) = 0;
	virtual void Pump() = 0;
	virtual void Close() = 0;
	uint64_t events = 0;
};
static Client *g_client;

struct RawClient : Client {
	channel *ch = nullptr;
	std::vector<uint8_t> small, medium, take, many, large, burst;
	std::vector<int> held;	/* moved-and-echoed descriptors in hand */
	RawClient(int fd)
	{
		channel_options options = CHANNEL_OPTIONS_INITIALIZER(
		    CHANNEL_ROLE_CLIENT);
		if (channel_create(fd, &options, &ch) != 0)
			die("raw client");
		channel_set_event_handler(ch, OnEvent, this);
		small = Encode(types::Request(small_text), 1, kRoundTrip);
		medium = Encode(types::Request(medium_text), 1, kRoundTrip);
		burst = Encode(types::Request(small_text), 1, kBurst);
		if (spec.fds) {
			many = Encode(types::ManyResources(DupDescriptors(
					  spec.fds)),
			    1, kMany);
			if (spec.transfer == Transfer::Move &&
			    spec.dir == Dir::Both)
				for (size_t i = 0; i < spec.fds; ++i)
					held.push_back(dup(lend_fd));
		}
		if (!large_bytes.empty())
			large = Encode(types::Large(large_bytes), 1, kLarge);
	}
	static void OnEvent(channel *, channel_message *m, void *ctx)
	{
		static_cast<RawClient *>(ctx)->events++;
		channel_message_free(m);
	}
	static void OnReply(channel_request *request, channel_message *m,
	    int error, void *ctx)
	{
		auto *slot = static_cast<Slot *>(ctx);
		auto *self = static_cast<RawClient *>(g_client);
		if (error)
			die("raw reply error");
		if (slot->op == Op::Many && spec.dir == Dir::Both) {
			if (channel_message_fd_count(m) != spec.fds)
				die("raw reply descriptor count");
			if (spec.transfer == Transfer::Move)
				for (size_t i = 0; i < spec.fds; ++i) {
					self->held[i] = channel_message_take_fd(
					    m, i);
					if (self->held[i] < 0)
						die("raw take");
				}
		}
		channel_message_free(m);
		channel_request_release(request);
		g_driver->Complete(slot);
	}
	void Issue(Op op, Slot *slot) override
	{
		const std::vector<uint8_t> *bytes = &small;
		switch (op) {
		case Op::Small:
			break;
		case Op::Medium:
			bytes = &medium;
			break;
		case Op::Many:
			bytes = &many;
			break;
		case Op::Large:
			bytes = &large;
			break;
		case Op::Burst:
			bytes = &burst;
			break;
		case Op::Take:
			die("raw take unsupported");
		}
		channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(
		    bytes->data(), bytes->size());
		int dups[MAC_CAPABILITY_MAX_FDS];
		if (op == Op::Many) {
			view.nfds = spec.fds;
			if (spec.transfer == Transfer::Move) {
				view.flags = CHANNEL_SEND_MOVE;
				if (spec.dir == Dir::Both)
					view.fds = held.data();
				else {
					for (size_t i = 0; i < spec.fds; ++i)
						if ((dups[i] = dup(lend_fd)) < 0)
							die("dup");
					view.fds = dups;
				}
			} else
				view.fds = template_fds.data();
		}
		slot->op = op;
		channel_request *request;
		if (sync_call) {
			/* Request and reply in one system call where the
			 * kernel allows; OnReply then runs before return. */
			if (channel_call_request(ch, &view, OnReply, slot,
				&request, 5000) != 0)
				die("raw call");
			return;
		}
		if (channel_send_request(ch, &view, OnReply, slot, &request) !=
		    0)
			die("raw send");
	}
	void Pump() override
	{
		if (channel_wait(ch, channel_wants_write(ch), 1000) < 0 ||
		    channel_dispatch(ch) < 0 || channel_flush(ch) != 0)
			die("raw wait");
	}
	void Close() override
	{
		for (int fd : held)
			close(fd);
		held.clear();
		channel_destroy(ch);
		ch = nullptr;
	}
};

struct CppClient : Client, bindings::ServiceEvents {
	std::unique_ptr<Connection> conn;
	std::unique_ptr<bindings::ServiceClient> svc;
	std::vector<Descriptor> held;
	CppClient(int fd)
	{
		auto created = Connection::Create(fd, CHANNEL_ROLE_CLIENT);
		if (created.is_error())
			die("cpp client");
		conn = std::move(created.value());
		conn->SetEventHandler(
		    [this](auto m) { Dispatch(*conn, std::move(m)); });
		svc = std::make_unique<bindings::ServiceClient>(*conn);
	}
	void Changed(types::Response, const Incoming &) override { ++events; }
	void Issue(Op op, Slot *slot) override
	{
		if (sync_call) {
			struct Args {
				CppClient *self;
				Op op;
				Slot *slot;
			} args { this, op, slot };
			int error = conn->CallSync(
			    5000,
			    [](void *ctx) -> int {
				    auto *a = static_cast<Args *>(ctx);
				    a->self->IssueAsync(a->op, a->slot);
				    return 0;
			    },
			    &args);
			if (error) {
				errno = error;
				die("cpp sync call");
			}
			return;
		}
		IssueAsync(op, slot);
	}
	void IssueAsync(Op op, Slot *slot)
	{
		fidl::bsd::Result<uint32_t> id = fit::ok(0u);
		switch (op) {
		case Op::Small:
			id = svc->RoundTrip(types::Request(small_text),
			    [slot](auto r) {
				    if (r.is_error())
					    die("cpp call");
				    g_driver->Complete(slot);
			    });
			break;
		case Op::Medium:
			id = svc->RoundTrip(types::Request(medium_text),
			    [slot](auto r) {
				    if (r.is_error())
					    die("cpp call");
				    g_driver->Complete(slot);
			    });
			break;
		case Op::Take:
			/* C++ fields own their descriptor: one dup per call. */
			id = svc->Take(types::ReadOnly(Descriptor(dup(lend_fd))),
			    [slot](auto r) {
				    if (r.is_error())
					    die("cpp take");
				    g_driver->Complete(slot);
			    });
			break;
		case Op::Many: {
			std::vector<Descriptor> fds;
			if (spec.dir == Dir::Both && !held.empty())
				fds = std::move(held);
			else
				fds = DupDescriptors(spec.fds);
			id = conn->Call<types::ManyResources,
			    types::ManyResources>(kMany,
			    types::ManyResources(std::move(fds)),
			    [this, slot](
				fidl::bsd::Result<types::ManyResources> r) {
				    if (r.is_error())
					    die("cpp many");
				    if (spec.dir == Dir::Both) {
					    if (r->fds().size() != spec.fds)
						    die("cpp many count");
					    held = std::move(r->fds());
				    }
				    g_driver->Complete(slot);
			    });
			break;
		}
		case Op::Large:
			id = conn->Call<types::Large, types::Large>(kLarge,
			    types::Large(large_bytes),
			    [slot](fidl::bsd::Result<types::Large> r) {
				    if (r.is_error() ||
					r->bytes().size() != large_bytes.size())
					    die("cpp large");
				    g_driver->Complete(slot);
			    });
			break;
		case Op::Burst:
			id = conn->Call<types::Request, types::Response>(kBurst,
			    types::Request(small_text),
			    [slot](fidl::bsd::Result<types::Response> r) {
				    if (r.is_error())
					    die("cpp burst");
				    g_driver->Complete(slot);
			    });
			break;
		}
		if (id.is_error()) {
			errno = id.error_value();
			die("cpp send");
		}
	}
	void Pump() override
	{
		if (conn->Poll(1000) != 0)
			die("cpp poll");
	}
	void Close() override
	{
		held.clear();
		svc.reset();
		conn.reset();
	}
};

struct CClient : Client {
	fidl_bsd_connection *conn = nullptr;
	bsd_runtime_test_Request small_request, medium_request;
	bsd_runtime_test_ReadOnly lent;
	bsd_runtime_test_ManyResources many_value;
	bsd_runtime_test_Large large_value;
	bsd_runtime_test_Service_events events_table;
	/* Move scenarios: fidl_bsd_fd_owned() slots for one call, and the
	 * echoed descriptors in hand for the next (both + move). */
	std::vector<int> owned_slots, held;
	CClient(int fd)
	{
		if (fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &conn) != 0)
			die("c client");
		events_table = { OnChanged };
		if (bsd_runtime_test_Service_bind_events(conn, &events_table,
			this) != 0)
			die("c bind events");
		small_request = { small_text.data(), small_text.size() };
		medium_request = { medium_text.data(), medium_text.size() };
		lent = { lend_fd };
		/* Borrow scenarios lend the same descriptors every call. */
		many_value = { template_fds.data(), template_fds.size() };
		large_value = { large_bytes.data(), large_bytes.size() };
	}
	static void OnChanged(void *ctx, bsd_runtime_test_Response *)
	{
		static_cast<CClient *>(ctx)->events++;
	}
	static void Done(void *ctx, int error, bsd_runtime_test_Response *)
	{
		if (error) {
			errno = error;
			die("c call");
		}
		g_driver->Complete(static_cast<Slot *>(ctx));
	}
	template <typename R, typename T, typename Enc, typename Dec>
	void CallWire(uint64_t ordinal, const T *value, Enc enc, Dec dec,
	    Slot *slot, size_t expect_fds, bool keep_fds = false)
	{
		auto result = conn->value->CallRaw(ordinal, false,
		    CEncoder(value, enc),
		    [this, slot, dec, expect_fds, keep_fds](int error,
			Incoming *incoming) {
			    if (error) {
				    errno = error;
				    die("c wire call");
			    }
			    cwire::Arena arena;
			    cwire::Decoder d(arena);
			    R data {};
			    CDecode(*incoming, d, &data, dec);
			    if (d.Handles() != expect_fds)
				    die("c wire reply descriptors");
			    if (keep_fds)
				    Keep(data);
			    g_driver->Complete(slot);
		    });
		if (result.is_error()) {
			errno = result.error_value();
			die("c wire send");
		}
	}
	/* both + move: take the echoed descriptors to send them again. */
	void Keep(bsd_runtime_test_ManyResources &data)
	{
		held.clear();
		for (size_t i = 0; i < data.fds_size; ++i)
			held.push_back(fidl_bsd_take_fd(&data.fds[i]));
	}
	template <typename R> void Keep(R &) { }
	/* The Many request for this call: lent template descriptors, or
	 * owned ones the call takes (echoed ones recycled, else fresh dups,
	 * whose system calls are part of the measurement as for C++). */
	bsd_runtime_test_ManyResources ManyRequest()
	{
		if (spec.transfer != Transfer::Move)
			return many_value;
		owned_slots.resize(spec.fds);
		if (spec.dir == Dir::Both && held.size() == spec.fds) {
			for (size_t i = 0; i < spec.fds; ++i)
				owned_slots[i] = fidl_bsd_fd_owned(held[i]);
			held.clear();
		} else {
			for (size_t i = 0; i < spec.fds; ++i) {
				int fd = dup(lend_fd);
				if (fd < 0)
					die("dup");
				owned_slots[i] = fidl_bsd_fd_owned(fd);
			}
		}
		return { owned_slots.data(), owned_slots.size() };
	}
	void Issue(Op op, Slot *slot) override
	{
		if (sync_call) {
			struct Args {
				CClient *self;
				Op op;
				Slot *slot;
			} args { this, op, slot };
			int error = fidl_bsd_connection_call(
			    conn, 5000,
			    [](void *ctx) -> int {
				    auto *a = static_cast<Args *>(ctx);
				    a->self->IssueAsync(a->op, a->slot);
				    return 0;
			    },
			    &args);
			if (error) {
				errno = error;
				die("c sync call");
			}
			return;
		}
		IssueAsync(op, slot);
	}
	void IssueAsync(Op op, Slot *slot)
	{
		uint32_t txid;
		int err = 0;
		switch (op) {
		case Op::Small:
			err = bsd_runtime_test_Service_RoundTrip(conn,
			    &small_request, Done, slot, &txid);
			break;
		case Op::Medium:
			err = bsd_runtime_test_Service_RoundTrip(conn,
			    &medium_request, Done, slot, &txid);
			break;
		case Op::Take:
			err = bsd_runtime_test_Service_Take(conn, &lent, Done,
			    slot, &txid);
			break;
		case Op::Many: {
			bsd_runtime_test_ManyResources request = ManyRequest();
			CallWire<bsd_runtime_test_ManyResources>(kMany, &request,
			    CWEnc_bsd_runtime_test_ManyResources,
			    CWDec_bsd_runtime_test_ManyResources, slot,
			    spec.dir == Dir::Both ? spec.fds : 0,
			    spec.dir == Dir::Both &&
				spec.transfer == Transfer::Move);
			break;
		}
		case Op::Large:
			CallWire<bsd_runtime_test_Large>(kLarge, &large_value,
			    CWEnc_bsd_runtime_test_Large,
			    CWDec_bsd_runtime_test_Large, slot, 0);
			break;
		case Op::Burst:
			CallWire<bsd_runtime_test_Response>(kBurst, &small_request,
			    CWEnc_bsd_runtime_test_Request,
			    CWDec_bsd_runtime_test_Response, slot, 0);
			break;
		}
		if (err) {
			errno = err;
			die("c send");
		}
	}
	void Pump() override
	{
		if (fidl_bsd_connection_poll(conn, 1000) != 0)
			die("c poll");
	}
	void Close() override
	{
		for (int fd : held)
			close(fd);
		held.clear();
		fidl_bsd_connection_destroy(conn);
		conn = nullptr;
	}
};

/*
 * Run `groups` groups of ops.  A one-op group runs pipelined with the
 * scenario's window and samples each request; a longer group runs
 * synchronously and samples the whole group (one iteration).
 */
static void
RunGroups(Client &client, Driver &driver, const std::vector<Op> &group,
    size_t groups, bool timing)
{
	driver.completed = 0;
	driver.inflight = 0;
	if (group.size() == 1) {
		driver.per_op_timing = timing;
		std::vector<Slot> slots(spec.window);
		size_t issued = 0;
		while (driver.completed < groups) {
			while (issued < groups && driver.inflight < spec.window) {
				Slot *slot = nullptr;
				for (auto &s : slots)
					if (!s.busy) {
						slot = &s;
						break;
					}
				slot->busy = true;
				slot->t0 = timing ? NowUs() : 0;
				++issued;
				++driver.inflight;
				client.Issue(group[0], slot);
			}
			/* A synchronous call has completed inside Issue. */
			if (driver.inflight > 0)
				client.Pump();
		}
		return;
	}
	driver.per_op_timing = false;
	Slot slot;
	for (size_t i = 0; i < groups; ++i) {
		double t0 = timing ? NowUs() : 0;
		for (Op op : group) {
			slot.busy = true;
			++driver.inflight;
			client.Issue(op, &slot);
			while (slot.busy)
				client.Pump();
		}
		if (timing)
			driver.samples.push_back(NowUs() - t0);
	}
}

/* ----------------------------------------------------------- ktrace */

struct SyscallCounts {
	std::map<int, uint64_t> by_code;
	uint64_t total = 0;
};
struct TraceResult {
	bool ok = false;
	bool dropped = false;
	std::string error;
	SyscallCounts client, server;
};

static const char *
SyscallName(int code, char *buf, size_t size)
{
	switch (code) {
	case SYS_read:
		return "read";
	case SYS_write:
		return "write";
	case SYS_close:
		return "close";
	case SYS_dup:
		return "dup";
	case SYS_ioctl:
		return "ioctl";
	case SYS_fcntl:
		return "fcntl";
	case SYS_kevent:
		return "kevent";
	case SYS_kqueue:
		return "kqueue";
	case SYS_kqueuex:
		return "kqueuex";
	case SYS_clock_gettime:
		return "clock_gettime";
	case SYS_madvise:
		return "madvise";
	case SYS_mmap:
		return "mmap";
	case SYS_munmap:
		return "munmap";
	case SYS_fstat:
		return "fstat";
	case SYS_sigprocmask:
		return "sigprocmask";
	case SYS__umtx_op:
		return "_umtx_op";
	case SYS_getpid:
		return "getpid";
	case SYS_poll:
		return "poll";
	case SYS_nanosleep:
		return "nanosleep";
	case SYS_sched_yield:
		return "sched_yield";
	case SYS_cap_ioctls_limit:
		return "cap_ioctls_limit";
	case SYS_cap_rights_limit:
		return "cap_rights_limit";
	case SYS___sysctl:
		return "__sysctl";
	case SYS_ktrace:
		return "ktrace";
	case SYS___cap_rights_get:
		return "__cap_rights_get";
	case SYS_pddupfd:
		return "pddupfd";
	case SYS_pdptrace:
		return "pdptrace";
	}
	static int channel_create = -1;
	if (channel_create == -1) {
		int value;
		size_t length = sizeof(value);
		channel_create = sysctlbyname(
				     "kern.mac_capability.channel_create_syscall",
				     &value, &length, nullptr, 0) == 0 ?
		    value :
		    -2;
	}
	if (code == channel_create)
		return "mac_capability_channel_create";
	snprintf(buf, size, "sys%d", code);
	return buf;
}

static void
ParseKtrace(const std::string &path, pid_t self, pid_t child,
    TraceResult &result)
{
	std::vector<unsigned char> buf;
	FILE *f = fopen(path.c_str(), "rb");
	if (f == nullptr) {
		result.error = std::string("open trace: ") + strerror(errno);
		return;
	}
	unsigned char chunk[65536];
	size_t n;
	while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
		buf.insert(buf.end(), chunk, chunk + n);
	fclose(f);
	size_t off = 0;
	while (off + sizeof(ktr_header_v0) <= buf.size()) {
		ktr_header h;
		size_t hsize = sizeof(ktr_header);
		ktr_header_v0 h0;
		memcpy(&h0, &buf[off], sizeof(h0));
		if ((h0.ktr_type & KTR_VERSIONED) &&
		    off + sizeof(ktr_header) <= buf.size()) {
			memcpy(&h, &buf[off], sizeof(h));
		} else {
			h = ktr_header {};
			h.ktr_len = h0.ktr_len;
			h.ktr_type = h0.ktr_type;
			h.ktr_pid = h0.ktr_pid;
			hsize = sizeof(ktr_header_v0);
		}
		if (h.ktr_len < 0)
			break;
		size_t next = off + hsize + static_cast<size_t>(h.ktr_len);
		if (next > buf.size())
			break;
		if (h.ktr_type & KTR_DROP)
			result.dropped = true;
		int type = h.ktr_type & ~KTR_TYPE;
		if (type == KTR_SYSCALL &&
		    h.ktr_len >= static_cast<int>(2 * sizeof(short))) {
			short code;
			memcpy(&code, &buf[off + hsize], sizeof(code));
			SyscallCounts *counts = h.ktr_pid == self ?
			    &result.client :
			    h.ktr_pid == child ? &result.server : nullptr;
			if (counts && code != SYS_ktrace) {
				counts->by_code[code]++;
				counts->total++;
			}
		}
		off = next;
	}
	result.ok = true;
}

/* Trace both processes over run(); then one untraced group so the server
 * returns to user mode and writes its last records. */
template <typename Run, typename Flush>
static TraceResult
TraceSyscalls(pid_t child, Run run, Flush flush)
{
	TraceResult result;
	const char *dir = getenv("IPC_BENCH_KTRACE_DIR");
	std::string path = std::string(dir && *dir ? dir : ".") +
	    "/ipc_bench.ktrace." + std::to_string(getpid());
	int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		result.error = std::string("create trace file: ") +
		    strerror(errno);
		return result;
	}
	close(fd);
	if (ktrace(path.c_str(), KTROP_SET, KTRFAC_SYSCALL, getpid()) != 0 ||
	    ktrace(path.c_str(), KTROP_SET, KTRFAC_SYSCALL, child) != 0) {
		result.error = std::string("ktrace: ") + strerror(errno);
		ktrace(path.c_str(), KTROP_CLEARFILE, 0, 0);
		unlink(path.c_str());
		return result;
	}
	run();
	if (ktrace(path.c_str(), KTROP_CLEARFILE, 0, 0) != 0) {
		result.error = std::string("ktrace clear: ") + strerror(errno);
		unlink(path.c_str());
		return result;
	}
	flush();
	ParseKtrace(path, getpid(), child, result);
	unlink(path.c_str());
	return result;
}

static std::string
SyscallJson(const SyscallCounts &counts, double per)
{
	std::vector<std::pair<int, uint64_t>> sorted(counts.by_code.begin(),
	    counts.by_code.end());
	std::sort(sorted.begin(), sorted.end(),
	    [](auto &a, auto &b) { return a.second > b.second; });
	std::string out = "{";
	char buf[64], name[32];
	uint64_t other = 0;
	for (size_t i = 0; i < sorted.size(); ++i) {
		if (i >= 10) {
			other += sorted[i].second;
			continue;
		}
		snprintf(buf, sizeof(buf), "%s\"%s\":%.3f", i ? "," : "",
		    SyscallName(sorted[i].first, name, sizeof(name)),
		    double(sorted[i].second) / per);
		out += buf;
	}
	if (other) {
		snprintf(buf, sizeof(buf), ",\"other\":%.3f", double(other) / per);
		out += buf;
	}
	return out + "}";
}

/* --------------------------------------------------------------- run */

static size_t
MessageBytes(const Spec &s, Op op)
{
	switch (op) {
	case Op::Small:
	case Op::Burst:
		return Encode(types::Request(small_text), 1, kRoundTrip).size();
	case Op::Medium:
		return Encode(types::Request(medium_text), 1, kRoundTrip).size();
	case Op::Take:
		return Encode(types::ReadOnly(Descriptor(dup(lend_fd))), 1,
		    kRoundTrip)
		    .size();
	case Op::Many:
		return Encode(types::ManyResources(DupDescriptors(s.fds)), 1,
		    kMany)
		    .size();
	case Op::Large:
		return Encode(types::Large(large_bytes), 1, kLarge).size();
	}
	return 0;
}

static std::string
RunOne(const Spec &s, Mode m, uint64_t calls, uint64_t warmup, int trial)
{
	spec = s;
	mode = m;
	served = 0;
	served_end_taken = false;
	c_pending = nullptr;
	/* Request text is bounded at 256; Large carries its payload as bytes. */
	small_text.assign(s.large ? 8 : s.payload, 'x');
	medium_text.assign(256, 'y');
	large_bytes.clear();
	if (s.large)
		large_bytes.assign(s.payload, 0x5a);
	else if (s.mixed)
		large_bytes.assign(14304, 0x5a);

	std::vector<Op> group;
	if (s.mixed)
		group = { Op::Small, Op::Small, Op::Small, Op::Small, Op::Medium,
			Op::Medium, Op::Many, Op::Large, Op::Burst };
	else if (s.take)
		group = { Op::Take };
	else if (s.fds)
		group = { Op::Many };
	else if (s.large)
		group = { Op::Large };
	else
		group = { Op::Small };
	const size_t per_group = group.size();
	size_t groups, warm_groups, trace_groups;
	const char *unit = "call";
	if (s.burst_on_roundtrip) {
		groups = std::max<size_t>(20, calls / 100);
		warm_groups = std::max<size_t>(2, warmup / 100);
		trace_groups = std::min<size_t>(groups, 5);
		unit = "burst";
	} else if (s.mixed) {
		groups = std::max<size_t>(1, calls / per_group);
		warm_groups = std::max<size_t>(1, warmup / per_group);
		trace_groups = std::min<size_t>(groups, 100);
		unit = "iteration";
	} else {
		groups = calls;
		warm_groups = warmup;
		trace_groups = std::min<size_t>(calls, 1000);
	}
	warmup_requests = warm_groups * per_group;
	measured_requests = groups * per_group;

	int client_cpu = -1, server_cpu = -1;
	if (const char *cpus = getenv("IPC_BENCH_CPUS")) {
		client_cpu = atoi(cpus);
		const char *comma = strchr(cpus, ',');
		server_cpu = comma ? atoi(comma + 1) : client_cpu;
	}
	Pin(client_cpu);
	/*
	 * A caller asleep in the kernel does not drain events, so a provider
	 * that sends a burst of them before replying needs them to fit the
	 * receive queue: the event scenarios keep the split path.
	 */
	sync_call = spec.window == 1 && (spec.events == 0 || spec.mixed) &&
	    getenv("IPC_BENCH_NO_CALL") == nullptr;

	int ends[2], report[2], lend[2];
	if (mac_capability_channel_create(ends) != 0 || pipe(report) != 0 ||
	    pipe(lend) != 0)
		die("setup");
	lend_fd = lend[0];
	if (getenv("IPC_BENCH_LEGACY") != nullptr) {
		static const cap_ioctl_t older[] = { MAC_CAPABILITY_GETINFO,
			MAC_CAPABILITY_SENDMSG, MAC_CAPABILITY_RECVMSG,
			MAC_CAPABILITY_RECVMSG_V2, MAC_CAPABILITY_RECVMSG_V3 };
		if (cap_ioctls_limit(ends[0], older, std::size(older)) != 0 ||
		    cap_ioctls_limit(ends[1], older, std::size(older)) != 0)
			die("legacy allowlist");
	}
	template_fds.clear();
	for (size_t i = 0; i < s.fds; ++i) {
		int fd = dup(lend_fd);
		if (fd < 0)
			die("dup");
		template_fds.push_back(fd);
	}
	pid_t child = fork();
	if (child < 0)
		die("fork");
	if (child == 0) {
		Pin(server_cpu);
		close(ends[0]);
		close(report[0]);
		if (m == Mode::Raw)
			RawServer().Run(ends[1], report[1]);
		else if (m == Mode::Cpp)
			ServeCpp(ends[1], report[1]);
		else
			ServeC(ends[1], report[1]);
		_exit(0);
	}
	close(ends[1]);
	close(report[1]);

	size_t message_bytes = MessageBytes(s, group.size() == 1 ? group[0] :
								     Op::Small);
	Driver driver;
	driver.samples.reserve(groups);
	g_driver = &driver;
	std::unique_ptr<Client> client;
	if (m == Mode::Raw)
		client = std::make_unique<RawClient>(ends[0]);
	else if (m == Mode::Cpp)
		client = std::make_unique<CppClient>(ends[0]);
	else
		client = std::make_unique<CClient>(ends[0]);
	g_client = client.get();

	RunGroups(*client, driver, group, warm_groups, false);
	Counters start = Snapshot();
	double begin = NowUs();
	RunGroups(*client, driver, group, groups, true);
	double elapsed = (NowUs() - begin) / 1e6;
	Counters end = Snapshot();

	TraceResult trace = TraceSyscalls(
	    child, [&] { RunGroups(*client, driver, group, trace_groups, false); },
	    [&] { RunGroups(*client, driver, group, 1, false); });
	size_t total_groups = warm_groups + groups + trace_groups + 1;
	uint64_t expected_events = 0;
	if (s.burst_on_roundtrip)
		expected_events = uint64_t(total_groups) * s.events;
	else if (s.mixed)
		expected_events = uint64_t(total_groups) * s.events;
	if (client->events != expected_events) {
		fprintf(stderr, "ipc_bench: %s/%s: %ju events, expected %ju\n",
		    s.name.c_str(), ModeName(m), (uintmax_t)client->events,
		    (uintmax_t)expected_events);
		exit(1);
	}

	client->Close();
	client.reset();
	for (int fd : template_fds)
		close(fd);
	template_fds.clear();
	close(lend[0]);
	close(lend[1]);
	uint64_t server[3] = {};
	if (read(report[0], server, sizeof(server)) != sizeof(server))
		die("server report");
	close(report[0]);
	int status;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		die("server exit");
	if (server[2] != total_groups * per_group) {
		fprintf(stderr, "ipc_bench: server served %ju of %ju requests\n",
		    (uintmax_t)server[2], (uintmax_t)(total_groups * per_group));
		exit(1);
	}

	auto &samples = driver.samples;
	std::sort(samples.begin(), samples.end());
	auto pct = [&](double p) {
		return samples[std::min(samples.size() - 1,
		    static_cast<size_t>(p * samples.size()))];
	};
	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	std::string mode_name = ModeName(m);
	if (getenv("IPC_BENCH_LEGACY") != nullptr)
		mode_name += "-legacy";
	if (getenv("IPC_BENCH_NO_CALL") != nullptr)
		mode_name += "-nocall";
	const char *dir_name = s.dir == Dir::Both ? "both" :
	    s.dir == Dir::Request			 ? "request" :
							 "none";
	const char *transfer_name = s.transfer == Transfer::Move ? "move" :
	    s.transfer == Transfer::Borrow			 ? "borrow" :
								 "none";
	const double calls_measured = double(measured_requests);
	const size_t trace_requests = trace_groups * per_group;
	char buf[4096];
	std::string json;
	snprintf(buf, sizeof(buf),
	    "{\"schema\":2,\"scenario\":\"%s\",\"name\":\"%s\",\"mode\":\"%s\","
	    "\"payload\":%zu,\"message_bytes\":%zu,\"window\":%zu,\"fds\":%zu,"
	    "\"fd_direction\":\"%s\",\"fd_transfer\":\"%s\","
	    "\"events_per_burst\":%zu,\"sample_unit\":\"%s\","
	    "\"requests_per_sample\":%zu,\"samples\":%zu,\"calls\":%ju,"
	    "\"seconds\":%.6f,\"calls_per_second\":%.1f,",
	    s.scenario.c_str(), s.name.c_str(), mode_name.c_str(), s.payload,
	    message_bytes, s.window, s.fds, dir_name, transfer_name, s.events,
	    unit, per_group, samples.size(), (uintmax_t)measured_requests,
	    elapsed, calls_measured / elapsed);
	json += buf;
	if (s.events) {
		snprintf(buf, sizeof(buf), "\"events_per_second\":%.1f,",
		    double(groups) * s.events / elapsed);
		json += buf;
	}
	snprintf(buf, sizeof(buf),
	    "\"p50_us\":%.2f,\"p90_us\":%.2f,\"p99_us\":%.2f,\"max_us\":%.2f,"
	    "\"client_allocations_per_call\":%.2f,\"client_bytes_per_call\":%.1f,"
	    "\"server_allocations_per_call\":%.2f,\"server_bytes_per_call\":%.1f,"
	    "\"client_maxrss_kib\":%ld,\"trial\":%d,",
	    pct(0.50), pct(0.90), pct(0.99), samples.back(),
	    double(end.allocations - start.allocations) / calls_measured,
	    double(end.bytes - start.bytes) / calls_measured,
	    double(server[0]) / calls_measured, double(server[1]) / calls_measured,
	    usage.ru_maxrss, trial);
	json += buf;
	if (trace.ok) {
		snprintf(buf, sizeof(buf),
		    "\"syscall_trace_calls\":%zu,\"syscall_trace_dropped\":%s,"
		    "\"client_syscalls_per_call\":%.3f,"
		    "\"server_syscalls_per_call\":%.3f,",
		    trace_requests, trace.dropped ? "true" : "false",
		    double(trace.client.total) / trace_requests,
		    double(trace.server.total) / trace_requests);
		json += buf;
		json += "\"client_syscalls\":" +
		    SyscallJson(trace.client, trace_requests) +
		    ",\"server_syscalls\":" +
		    SyscallJson(trace.server, trace_requests) + ",";
	} else {
		snprintf(buf, sizeof(buf),
		    "\"client_syscalls_per_call\":null,"
		    "\"server_syscalls_per_call\":null,\"syscall_trace_error\":"
		    "\"%s\",\"syscall_trace_hint\":\"ktrace -t c -i -f "
		    "ipc_bench.ktrace ipc_bench run %s %s %zu 0 && kdump -f "
		    "ipc_bench.ktrace | grep -c ' CALL '\",",
		    trace.error.c_str(), s.name.c_str(), ModeName(m),
		    trace_requests);
		json += buf;
	}
	if (client_cpu >= 0)
		snprintf(buf, sizeof(buf), "\"cpus\":\"%d,%d\"}", client_cpu,
		    server_cpu);
	else
		snprintf(buf, sizeof(buf), "\"cpus\":null}");
	json += buf;
	return json;
}

/* ------------------------------------------------------------- suite */

struct Entry {
	Spec spec;
	Mode mode;
};

static Spec
Base(const char *scenario, const std::string &name)
{
	Spec s;
	s.scenario = scenario;
	s.name = name;
	return s;
}

static std::vector<Entry>
Suite()
{
	std::vector<Entry> out;
	auto all = [&](Spec s) {
		for (Mode m : { Mode::Raw, Mode::Cpp, Mode::C })
			out.push_back({ s, m });
	};
	for (size_t payload : { size_t(8), size_t(256) }) {
		Spec s = Base("roundtrip", "roundtrip-" + std::to_string(payload));
		s.payload = payload;
		all(s);
	}
	for (size_t window : { size_t(1), size_t(8), size_t(64) }) {
		Spec s = Base("pipeline", "pipeline-" + std::to_string(window));
		s.window = window;
		all(s);
	}
	{
		Spec s = Base("take", "take-1");
		s.take = true;
		s.fds = 1;
		s.dir = Dir::Request;
		s.transfer = Transfer::Move;
		out.push_back({ s, Mode::Cpp });
		s.transfer = Transfer::Borrow;
		out.push_back({ s, Mode::C });
	}
	for (size_t fds : { size_t(1), size_t(8), size_t(32) })
		for (Dir dir : { Dir::Request, Dir::Both }) {
			std::string base = "fds-" + std::to_string(fds) + "-" +
			    (dir == Dir::Both ? "both" : "request");
			Spec s = Base("fds", base + "-move");
			s.fds = fds;
			s.dir = dir;
			s.payload = 0;
			s.transfer = Transfer::Move;
			out.push_back({ s, Mode::Raw });
			out.push_back({ s, Mode::Cpp });
			out.push_back({ s, Mode::C });
			s.name = base + "-borrow";
			s.transfer = Transfer::Borrow;
			out.push_back({ s, Mode::Raw });
			out.push_back({ s, Mode::C });
		}
	{
		Spec s = Base("events", "events-1000");
		s.events = 1000;
		s.burst_on_roundtrip = true;
		all(s);
	}
	for (size_t bytes : { size_t(4096), size_t(14304) }) {
		Spec s = Base("large", "large-" + std::to_string(bytes));
		s.large = true;
		s.payload = bytes;
		all(s);
	}
	{
		Spec s = Base("mixed", "mixed");
		s.mixed = true;
		s.fds = 1;
		s.dir = Dir::Both;
		s.events = 64;
		s.transfer = Transfer::Borrow;
		out.push_back({ s, Mode::Raw });
		s.transfer = Transfer::Move;
		out.push_back({ s, Mode::Cpp });
		s.transfer = Transfer::Borrow;
		out.push_back({ s, Mode::C });
	}
	return out;
}

static int
Usage()
{
	fprintf(stderr,
	    "usage: ipc_bench raw|cpp|c|cppfd|cfd PAYLOAD CALLS WARMUP\n"
	    "       ipc_bench suite CALLS WARMUP [TRIAL]\n"
	    "       ipc_bench run NAME raw|cpp|c CALLS WARMUP [TRIAL]\n"
	    "       ipc_bench list\n"
	    "  cppfd, cfd: each call sends one descriptor (Take)\n"
	    "  IPC_BENCH_NO_CALL=1 keeps send/wait/receive for synchronous calls\n"
	    "  IPC_BENCH_LEGACY=1 allowlists the older channel ioctls, forcing\n"
	    "  userland descriptor checks; IPC_BENCH_CPUS=C[,S] pins the client\n"
	    "  and server; IPC_BENCH_KTRACE_DIR holds the syscall trace file\n");
	return 2;
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		return Usage();
	std::string command = argv[1];
	if (command == "list") {
		for (auto &e : Suite())
			printf("%s %s\n", e.spec.name.c_str(), ModeName(e.mode));
		return 0;
	}
	if (command == "suite") {
		if (argc < 4 || argc > 5)
			return Usage();
		uint64_t calls = strtoull(argv[2], nullptr, 10);
		uint64_t warmup = strtoull(argv[3], nullptr, 10);
		int trial = argc == 5 ? atoi(argv[4]) : 0;
		for (auto &e : Suite()) {
			puts(RunOne(e.spec, e.mode, calls, warmup, trial).c_str());
			fflush(stdout);
		}
		return 0;
	}
	if (command == "run") {
		if (argc < 6 || argc > 7)
			return Usage();
		std::string name = argv[2], mode_name = argv[3];
		uint64_t calls = strtoull(argv[4], nullptr, 10);
		uint64_t warmup = strtoull(argv[5], nullptr, 10);
		int trial = argc == 7 ? atoi(argv[6]) : 0;
		for (auto &e : Suite())
			if (e.spec.name == name && mode_name == ModeName(e.mode)) {
				puts(RunOne(e.spec, e.mode, calls, warmup, trial)
					.c_str());
				return 0;
			}
		fprintf(stderr, "ipc_bench: unknown scenario %s %s\n",
		    name.c_str(), mode_name.c_str());
		return 2;
	}
	/* The original interface: one synchronous round trip per call. */
	if (argc != 5)
		return Usage();
	size_t payload = strtoul(argv[2], nullptr, 10);
	uint64_t calls = strtoull(argv[3], nullptr, 10);
	uint64_t warmup = strtoull(argv[4], nullptr, 10);
	Spec s = Base("roundtrip", "roundtrip-" + std::to_string(payload));
	s.payload = payload;
	Mode m;
	if (command == "raw")
		m = Mode::Raw;
	else if (command == "cpp" || command == "cppfd")
		m = Mode::Cpp;
	else if (command == "c" || command == "cfd")
		m = Mode::C;
	else
		return Usage();
	if (command == "cppfd" || command == "cfd") {
		s = Base("take", "take-1");
		s.payload = payload;
		s.take = true;
		s.fds = 1;
		s.dir = Dir::Request;
		s.transfer = m == Mode::Cpp ? Transfer::Move : Transfer::Borrow;
	}
	puts(RunOne(s, m, calls, warmup, 0).c_str());
	return 0;
}
