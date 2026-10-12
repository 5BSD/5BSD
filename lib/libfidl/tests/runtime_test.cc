/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <algorithm>
#include <fcntl.h>
#include <fidl/bsd.runtime.test/c/bsd.h>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
#include <fidl/bsd/c_bridge.h>
#include <fidl/bsd/runtime.h>
#include <gtest/gtest.h>
#include <random>
#include <signal.h>
#include <unistd.h>

#include "allocation_fault.h"

using namespace fidl::bsd;
namespace types = bsd_runtime_test;
namespace bindings = bsd_runtime_test::bsd;
constexpr uint64_t ordinal = 0x123456789ULL;

struct Pair {
	std::unique_ptr<Connection> client, server;
	explicit Pair(const channel_options *options = nullptr)
	{
		int fds[2];
		if (mac_capability_channel_create(fds))
			throw std::runtime_error("native channel create");
		auto c = Connection::Create(fds[0], CHANNEL_ROLE_CLIENT,
		    options);
		auto s = Connection::Create(fds[1], CHANNEL_ROLE_PROVIDER);
		if (!c.is_ok() || !s.is_ok())
			throw std::runtime_error("Connection::Create");
		client = std::move(c.value());
		server = std::move(s.value());
	}
	void Pump(unsigned n = 8)
	{
		for (unsigned i = 0; i < n; ++i) {
			server->Poll(5);
			client->Poll(5);
		}
	}
};
struct Pipe {
	Descriptor read, write;
	Pipe()
	{
		int fds[2];
		if (pipe(fds))
			throw std::runtime_error("pipe");
		read.reset(fds[0]);
		write.reset(fds[1]);
	}
};
static std::vector<uint8_t>
Bytes(Outgoing &packet)
{
	auto v = packet.view();
	auto *b = static_cast<const uint8_t *>(v.data);
	return { b, b + v.length };
}
static int
RawSend(Connection &from, const std::vector<uint8_t> &bytes,
    const std::vector<int> &fds = {}, uint64_t token = 0)
{
	mac_capability_sendmsg_args send {};
	send.payload = bytes.data();
	send.payload_len = bytes.size();
	send.fds = fds.data();
	send.nfds = fds.size();
	send.reply_token = token;
	return ioctl(from.fd(), MAC_CAPABILITY_SENDMSG, &send);
}
static std::unique_ptr<Incoming>
Receive(Pair &pair)
{
	std::unique_ptr<Incoming> result;
	pair.server->SetEventHandler(
	    [&](auto message) { result = std::move(message); });
	for (int i = 0; i < 100 && !result && !pair.server->error(); ++i)
		pair.server->Poll(5);
	pair.server->SetEventHandler({});
	return result;
}
static bool
Eof(Pipe &pipe)
{
	fcntl(pipe.read.get(), F_SETFL, O_NONBLOCK);
	char c;
	return read(pipe.read.get(), &c, 1) == 0;
}

TEST(Codec, GeneratedType)
{
	auto packet = Outgoing::Encode(types::Request("hello"), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	EXPECT_EQ(packet.value()->view().length, 40u);
	Pair pair;
	ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value())), 0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto value = message->template Decode<types::Request>();
	ASSERT_TRUE(value.is_ok());
	EXPECT_EQ(value->text(), "hello");
	EXPECT_TRUE(message->template Decode<types::Request>().is_error());
}
TEST(Codec, EncodeBoundsAndUtf8)
{
	EXPECT_TRUE(
	    Outgoing::Encode(types::Request(std::string(257, 'a')), 0, ordinal)
		.is_error());
	EXPECT_TRUE(Outgoing::Encode(types::Request(std::string("\xc0\x80", 2)),
	    0, ordinal)
		.is_error());
	auto value = Outgoing::Encode(types::Large(std::vector<uint8_t>(15000)),
	    0, ordinal);
	ASSERT_TRUE(value.is_error());
	EXPECT_EQ(value.error_value(), EMSGSIZE);
}
TEST(Codec, OptionalAbsentAndRequiredAbsent)
{
	EXPECT_TRUE(Outgoing::Encode(types::Resource(Descriptor()), 0, ordinal)
		.is_error());
	Pair pair;
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::OptionalResource(Descriptor())),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto value = message->Decode<types::OptionalResource>();
	ASSERT_TRUE(value.is_ok());
	EXPECT_FALSE(value->fd());
}
TEST(Codec, DescriptorMovesAndCarriesData)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(write(pipe.write.get(), "x", 1), 1);
	int old = pipe.read.get();
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.read))),
	    0);
	EXPECT_FALSE(pipe.read);
	EXPECT_EQ(fcntl(old, F_GETFD), -1);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto value = message->Decode<types::Resource>();
	ASSERT_TRUE(value.is_ok());
	char c;
	EXPECT_EQ(read(value->fd().get(), &c, 1), 1);
	EXPECT_EQ(c, 'x');
}
TEST(Codec, ReadOnlyAttenuation)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::ReadOnly(std::move(pipe.read))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto value = message->Decode<types::ReadOnly>();
	ASSERT_TRUE(value.is_ok());
	cap_rights_t rights;
	ASSERT_EQ(cap_rights_get(value->fd().get(), &rights), 0);
	EXPECT_TRUE(cap_rights_is_set(&rights, CAP_READ));
	EXPECT_FALSE(cap_rights_is_set(&rights, CAP_WRITE));
	EXPECT_FALSE(cap_rights_is_set(&rights, CAP_FSTAT));
}
TEST(Codec, MissingRightsRejectedOnSend)
{
	Pipe pipe;
	int fd = pipe.read.get();
	cap_rights_t rights;
	cap_rights_init(&rights);
	ASSERT_EQ(cap_rights_limit(fd, &rights), 0);
	auto packet = Outgoing::Encode(types::ReadOnly(std::move(pipe.read)), 0,
	    ordinal);
	ASSERT_TRUE(packet.is_error());
	EXPECT_EQ(packet.error_value(), ENOTCAPABLE);
	EXPECT_EQ(fcntl(fd, F_GETFD), -1);
}
TEST(Codec, MissingRightsRejectedOnConnectionSend)
{
	// A connection leaves the check to the send system call; the result
	// and the descriptor's fate match the encode-time check.
	Pair pair;
	Pipe pipe;
	int fd = pipe.read.get();
	cap_rights_t rights;
	cap_rights_init(&rights);
	ASSERT_EQ(cap_rights_limit(fd, &rights), 0);
	EXPECT_EQ(pair.client->Send(ordinal,
		      types::ReadOnly(std::move(pipe.read))),
	    ENOTCAPABLE);
	EXPECT_EQ(fcntl(fd, F_GETFD), -1);
	int fds[2];
	ASSERT_EQ(pipe2(fds, O_CLOEXEC), 0);
	Descriptor keep(fds[1]);
	EXPECT_EQ(pair.client->Send(ordinal,
		      types::SocketResource(Descriptor(fds[0]))),
	    EFTYPE);
	EXPECT_EQ(fcntl(fds[0], F_GETFD), -1);
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Codec, MissingRightsRejectedOnReceive)
{
	Pair pair;
	Pipe pipe;
	cap_rights_t rights;
	cap_rights_init(&rights, CAP_WRITE);
	ASSERT_EQ(cap_rights_limit(pipe.write.get(), &rights), 0);
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::ReadOnly>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, TypeMismatchRejectedOnSend)
{
	Pipe pipe;
	int fd = pipe.read.get();
	auto packet = Outgoing::Encode(types::SocketResource(
					   std::move(pipe.read)),
	    0, ordinal);
	ASSERT_TRUE(packet.is_error());
	EXPECT_EQ(packet.error_value(), EFTYPE);
	EXPECT_EQ(fcntl(fd, F_GETFD), -1);
}
TEST(Codec, SocketAndChannelTypes)
{
	Pair pair;
	int fds[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
	Descriptor peer(fds[1]);
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::SocketResource(Descriptor(fds[0]))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::SocketResource>().is_ok());
	int channels[2];
	ASSERT_EQ(mac_capability_channel_create(channels), 0);
	Descriptor other(channels[1]);
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::ChannelResource(Descriptor(channels[0]))),
	    0);
	message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::ChannelResource>().is_ok());
}
TEST(Codec, TransferOnceIsPreserved)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(cap_xfer_limit(pipe.read.get(), CAP_XFER_ONCE), 0);
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.read))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto value = message->Decode<types::Resource>();
	ASSERT_TRUE(value.is_ok());
	EXPECT_EQ(pair.server->Send(ordinal, std::move(value.value())),
	    ENOTCAPABLE);
}
TEST(Codec, SendFailureClosesMovedDescriptor)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(cap_xfer_limit(pipe.write.get(), CAP_XFER_NONE), 0);
	EXPECT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    ENOTCAPABLE);
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, TooManyDescriptorsAndEncodeFailureCleanUp)
{
	Pipe pipe;
	std::vector<Descriptor> handles;
	for (int i = 0; i < 33; ++i)
		handles.emplace_back(dup(pipe.write.get()));
	pipe.write.reset();
	auto packet = Outgoing::Encode(types::ManyResources(std::move(handles)),
	    0, ordinal);
	ASSERT_TRUE(packet.is_error());
	EXPECT_EQ(packet.error_value(), EMSGSIZE);
	EXPECT_TRUE(Eof(pipe));
	Pipe second;
	handles.clear();
	for (int i = 0; i < 41; ++i)
		handles.emplace_back(dup(second.write.get()));
	second.write.reset();
	EXPECT_TRUE(Outgoing::Encode(types::ManyResources(std::move(handles)),
	    0, ordinal)
		.is_error());
	EXPECT_TRUE(Eof(second));
}
TEST(Codec, UnclaimedAttachmentClosed)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, ExtraAttachmentRejectedAndClosed)
{
	Pair pair;
	Pipe pipe;
	auto packet = Outgoing::Encode(types::Request("x"), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value()),
		      { pipe.write.get() }),
	    0);
	pipe.write.reset();
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->template Decode<types::Request>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, MissingAttachmentRejected)
{
	Pair pair;
	Pipe pipe;
	auto packet = Outgoing::Encode(types::Resource(std::move(pipe.read)), 0,
	    ordinal);
	ASSERT_TRUE(packet.is_ok());
	ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value())), 0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::Resource>().is_error());
}
TEST(Codec, InvalidHandleMarkerClosesAttachment)
{
	Pair pair;
	Pipe pipe;
	auto packet = Outgoing::Encode(types::Resource(std::move(pipe.write)),
	    0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto bytes = Bytes(*packet.value());
	bytes[16] = 3;
	ASSERT_EQ(RawSend(*pair.client, bytes,
		      { packet.value()->view().fds[0] }),
	    0);
	packet.value().reset();
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::Resource>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, InvalidPaddingClosesDecodedDescriptor)
{
	Pair pair;
	Pipe pipe;
	auto packet = Outgoing::Encode(types::Resource(std::move(pipe.write)),
	    0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto bytes = Bytes(*packet.value());
	bytes[20] = 1;
	ASSERT_EQ(RawSend(*pair.client, bytes,
		      { packet.value()->view().fds[0] }),
	    0);
	packet.value().reset();
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::Resource>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, MalformedBodies)
{
	auto packet = Outgoing::Encode(types::Request("abc"), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto valid = Bytes(*packet.value());
	std::vector<std::vector<uint8_t>> variants;
	variants.push_back(valid);
	variants.back().resize(32); // Missing string bytes.
	variants.push_back(valid);
	variants.back()[16] = 255;
	variants.back()[17] = 255; // Count overflow.
	variants.push_back(valid);
	variants.back()[24] = 0; // Invalid presence marker.
	variants.push_back(valid);
	variants.back()[35] = 1; // Nonzero padding.
	variants.push_back(valid);
	variants.back()[32] = 0xff; // Invalid UTF-8.
	variants.push_back(valid);
	variants.back().resize(48); // Trailing bytes.
	for (auto &bytes : variants) {
		Pair pair;
		ASSERT_EQ(RawSend(*pair.client, bytes), 0);
		auto message = Receive(pair);
		ASSERT_TRUE(message);
		EXPECT_TRUE(
		    message->template Decode<types::Request>().is_error());
	}
}
TEST(Codec, InvalidBoolean)
{
	auto packet = Outgoing::Encode(types::Flag(true), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto bytes = Bytes(*packet.value());
	bytes[16] = 2;
	Pair pair;
	ASSERT_EQ(RawSend(*pair.client, bytes), 0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::Flag>().is_error());
}
TEST(Codec, InvalidBooleanVectorClosesDescriptor)
{
	Pipe pipe;
	types::Collection collection;
	collection.descriptors().push_back(std::move(pipe.write));
	collection.switches() = { true, false, true, true };
	auto packet = Outgoing::Encode(std::move(collection), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto bytes = Bytes(*packet.value());
	// The switches body is the only aligned 1,0,1,1 + padding block.
	const uint8_t body[] = { 1, 0, 1, 1, 0, 0, 0, 0 };
	auto found = std::search(bytes.begin(), bytes.end(), std::begin(body),
	    std::end(body));
	ASSERT_NE(found, bytes.end());
	ASSERT_EQ((found - bytes.begin()) % 8, 0);
	found[1] = 2;
	Pair pair;
	ASSERT_EQ(RawSend(*pair.client, bytes,
		      { packet.value()->view().fds[0] }),
	    0);
	packet.value().reset();
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::Collection>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Protocol, BadHeadersClosePeer)
{
	auto packet = Outgoing::Encode(types::Empty(), 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto valid = Bytes(*packet.value());
	std::vector<std::vector<uint8_t>> variants;
	variants.push_back(valid);
	variants.back().resize(8);
	for (int offset : { 0, 4, 7, 8 }) {
		variants.push_back(valid);
		variants.back()[offset] ^= 0xff;
	}
	// An arbitrary ordinal is legal at framing level; dispatch checks it
	// instead.
	variants.pop_back();
	for (auto &bytes : variants) {
		Pair pair;
		ASSERT_EQ(RawSend(*pair.client, bytes), 0);
		auto message = Receive(pair);
		EXPECT_FALSE(message);
		EXPECT_EQ(pair.server->error(), EPROTO);
	}
}
struct Server : bindings::ServiceServer {
	Connection &connection;
	unsigned requests = 0, notifications = 0;
	std::vector<std::unique_ptr<Incoming>> held;
	explicit Server(Connection &c)
	    : connection(c)
	{
	}
	bool hold = false;
	void RoundTrip(types::Request request,
	    std::unique_ptr<Incoming> context) override
	{
		++requests;
		if (hold) {
			held.push_back(std::move(context));
			return;
		}
		EXPECT_EQ(ReplyRoundTrip(connection, *context,
			      types::Response(request.text())),
		    0);
	}
	void Take(types::ReadOnly request,
	    std::unique_ptr<Incoming> context) override
	{
		char byte = 0;
		EXPECT_EQ(read(request.fd().get(), &byte, 1), 1);
		EXPECT_EQ(ReplyTake(connection, *context,
			      types::Response(std::string(1, byte))),
		    0);
	}
	void Notify(types::Request, std::unique_ptr<Incoming>) override
	{
		++notifications;
	}
	void Attach()
	{
		connection.SetRequestHandler(
		    [this](auto m) { Dispatch(connection, std::move(m)); });
		connection.SetEventHandler(
		    [this](auto m) { Dispatch(connection, std::move(m)); });
	}
};
TEST(Protocol, GeneratedRoundTrip)
{
	Pair pair;
	Server server(*pair.server);
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	unsigned calls = 0;
	auto call = client.RoundTrip(types::Request("hello"),
	    [&](Result<types::Response> r) {
		    ++calls;
		    ASSERT_TRUE(r.is_ok());
		    EXPECT_EQ(r->text(), "hello");
	    });
	ASSERT_TRUE(call.is_ok());
	pair.Pump();
	EXPECT_EQ(calls, 1u);
	EXPECT_EQ(server.requests, 1u);
}
TEST(Protocol, GeneratedOneWayAndEvents)
{
	Pair pair;
	Server server(*pair.server);
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	struct Events : bindings::ServiceEvents {
		unsigned calls = 0;
		void Changed(types::Response value,
		    const Incoming &context) override
		{
			++calls;
			EXPECT_EQ(value.text(), "change");
			EXPECT_EQ(context.header().txid, 0u);
		}
	} events;
	pair.client->SetEventHandler(
	    [&](auto m) { events.Dispatch(*pair.client, std::move(m)); });
	EXPECT_EQ(client.Notify(types::Request("notify")), 0);
	EXPECT_EQ(Server::Changed(*pair.server, types::Response("change")), 0);
	pair.Pump();
	EXPECT_EQ(server.notifications, 1u);
	EXPECT_EQ(events.calls, 1u);
}
TEST(Protocol, OutOfOrderReplies)
{
	Pair pair;
	Server server(*pair.server);
	server.hold = true;
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	std::vector<int> order;
	auto a = client.RoundTrip(types::Request("a"), [&](auto r) {
		ASSERT_TRUE(r.is_ok());
		EXPECT_EQ(r->text(), "a");
		order.push_back(1);
	});
	auto b = client.RoundTrip(types::Request("b"), [&](auto r) {
		ASSERT_TRUE(r.is_ok());
		EXPECT_EQ(r->text(), "b");
		order.push_back(2);
	});
	ASSERT_TRUE(a.is_ok());
	ASSERT_TRUE(b.is_ok());
	pair.Pump(2);
	ASSERT_EQ(server.held.size(), 2u);
	ASSERT_NE(channel_message_token(server.held[0]->native()),
	    channel_message_token(server.held[1]->native()));
	EXPECT_EQ(server.ReplyRoundTrip(*pair.server, *server.held[1],
		      types::Response("b")),
	    0);
	EXPECT_EQ(server.ReplyRoundTrip(*pair.server, *server.held[0],
		      types::Response("a")),
	    0);
	EXPECT_EQ(server.ReplyRoundTrip(*pair.server, *server.held[0],
		      types::Response("duplicate")),
	    EALREADY);
	pair.Pump();
	EXPECT_EQ(order, (std::vector<int> { 2, 1 }));
}
TEST(Protocol, CancellationAndLateReply)
{
	Pair pair;
	Server server(*pair.server);
	server.hold = true;
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	unsigned calls = 0;
	auto call = client.RoundTrip(types::Request("x"), [&](auto r) {
		++calls;
		ASSERT_TRUE(r.is_error());
		EXPECT_EQ(r.error_value(), ECANCELED);
	});
	ASSERT_TRUE(call.is_ok());
	pair.Pump(2);
	ASSERT_EQ(server.held.size(), 1u);
	EXPECT_EQ(pair.client->Cancel(call.value()), 0);
	EXPECT_EQ(pair.client->Cancel(call.value()), EALREADY);
	EXPECT_EQ(server.ReplyRoundTrip(*pair.server, *server.held[0],
		      types::Response("late")),
	    0);
	pair.Pump();
	EXPECT_EQ(calls, 1u);
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Protocol, PendingLimit)
{
	channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	options.max_pending_requests = 1;
	Pair pair(&options);
	Server server(*pair.server);
	server.hold = true;
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	auto a = client.RoundTrip(types::Request("a"), [](auto) { });
	ASSERT_TRUE(a.is_ok());
	auto b = client.RoundTrip(types::Request("b"), [](auto) { });
	ASSERT_TRUE(b.is_error());
	EXPECT_EQ(b.error_value(), ENOBUFS);
}
TEST(Protocol, PeerDeathCompletesPending)
{
	Pair pair;
	bindings::ServiceClient client(*pair.client);
	unsigned calls = 0;
	auto a = client.RoundTrip(types::Request("a"), [&](auto r) {
		++calls;
		EXPECT_TRUE(r.is_error());
	});
	ASSERT_TRUE(a.is_ok());
	pair.server.reset();
	for (int i = 0; i < 50 && !calls; ++i)
		pair.client->Poll(5);
	EXPECT_EQ(calls, 1u);
	EXPECT_NE(pair.client->error(), 0);
}
TEST(Protocol, CloseFromCallbackCompletesOthers)
{
	Pair pair;
	Server server(*pair.server);
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	unsigned calls = 0;
	auto a = client.RoundTrip(types::Request("a"), [&](auto r) {
		++calls;
		EXPECT_TRUE(r.is_ok());
		pair.client->Close();
	});
	auto b = client.RoundTrip(types::Request("b"), [&](auto r) {
		++calls;
		EXPECT_TRUE(r.is_error());
	});
	ASSERT_TRUE(a.is_ok());
	ASSERT_TRUE(b.is_ok());
	pair.Pump();
	EXPECT_EQ(calls, 2u);
}
TEST(Protocol, WrongReplyOrdinalOrTransaction)
{
	for (bool wrong_id : { false, true }) {
		Pair pair;
		std::unique_ptr<Incoming> request;
		unsigned calls = 0;
		pair.server->SetRequestHandler(
		    [&](auto m) { request = std::move(m); });
		auto call = pair.client->Call<types::Request, types::Response>(
		    ordinal, types::Request("x"), [&](auto r) {
			    ++calls;
			    ASSERT_TRUE(r.is_error());
			    EXPECT_EQ(r.error_value(), EPROTO);
		    });
		ASSERT_TRUE(call.is_ok());
		pair.Pump(2);
		ASSERT_TRUE(request);
		auto packet = Outgoing::Encode(types::Response("x"),
		    request->header().txid + (wrong_id ? 1 : 0),
		    ordinal + (wrong_id ? 0 : 1));
		ASSERT_TRUE(packet.is_ok());
		ASSERT_EQ(RawSend(*pair.server, Bytes(*packet.value()), {},
			      channel_message_token(request->native())),
		    0);
		pair.Pump();
		EXPECT_EQ(calls, 1u);
		EXPECT_EQ(pair.client->error(), EPROTO);
	}
}
TEST(Protocol, UnknownMethodAndWrongDirection)
{
	Pair pair;
	Server server(*pair.server);
	server.Attach();
	ASSERT_EQ(pair.client->Send(ordinal, types::Empty()), 0);
	pair.Pump();
	EXPECT_EQ(pair.server->error(), EPROTO);
}
TEST(Lifecycle, QueueBoundsAndAttachmentCleanup)
{
	channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	options.max_queued_messages = 2;
	options.max_queued_fds = 2;
	Pair pair(&options);
	Pipe pipe;
	bool bounded = false;
	for (unsigned i = 0; i < MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH +
		MAC_CAPABILITY_DEFAULT_TX_LIMIT + 32;
	    ++i) {
		int fd = dup(pipe.write.get());
		ASSERT_GE(fd, 0);
		int e = pair.client->Send(ordinal,
		    types::Resource(Descriptor(fd)));
		if (e) {
			EXPECT_EQ(e, ENOBUFS);
			bounded = true;
			break;
		}
	}
	EXPECT_TRUE(bounded);
	pipe.write.reset();
	pair.client.reset();
	pair.server.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, ForkCapabilityModeGeneratedDescriptorCall)
{
	int ends[2];
	ASSERT_EQ(mac_capability_channel_create(ends), 0);
	Pipe pipe;
	ASSERT_EQ(write(pipe.write.get(), "F", 1), 1);
	pipe.write.reset();
	ASSERT_EQ(cap_xfer_limit(pipe.read.get(), CAP_XFER_ONCE), 0);
	pid_t child = fork();
	ASSERT_GE(child, 0);
	if (child == 0) {
		alarm(10);
		close(ends[0]);
		pipe.read.reset();
		if (cap_enter() != 0)
			_exit(10);
		auto connection = Connection::Create(ends[1],
		    CHANNEL_ROLE_PROVIDER);
		if (!connection.is_ok())
			_exit(11);
		Server server(*connection.value());
		server.Attach();
		bool done = false;
		connection.value()->SetRequestHandler([&](auto m) {
			auto *process = channel_message_process(m->native());
			if (!process || process->pid != getppid())
				_exit(12);
			server.Dispatch(*connection.value(), std::move(m));
			done = true;
		});
		while (!done && !connection.value()->error())
			connection.value()->Poll(100);
		_exit(done && !::testing::Test::HasFailure() ? 0 : 13);
	}
	close(ends[1]);
	auto c = Connection::Create(ends[0], CHANNEL_ROLE_CLIENT);
	ASSERT_TRUE(c.is_ok());
	bindings::ServiceClient client(*c.value());
	unsigned calls = 0;
	auto result = client.Take(types::ReadOnly(std::move(pipe.read)),
	    [&](auto r) {
		    ++calls;
		    ASSERT_TRUE(r.is_ok());
		    EXPECT_EQ(r->text(), "F");
	    });
	ASSERT_TRUE(result.is_ok());
	for (int i = 0; i < 100 && !calls; ++i)
		c.value()->Poll(20);
	int status;
	ASSERT_EQ(waitpid(child, &status, 0), child);
	EXPECT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
	EXPECT_EQ(calls, 1u);
}
TEST(Lifecycle, DescriptorZero)
{
	pid_t child = fork();
	ASSERT_GE(child, 0);
	if (child == 0) {
		alarm(10);
		Pair pair;
		Pipe pipe;
		if (dup2(pipe.read.get(), 0) != 0)
			_exit(1);
		pipe.read.reset();
		if (pair.client->Send(ordinal, types::Resource(Descriptor(0))))
			_exit(2);
		if (fcntl(0, F_GETFD) != -1)
			_exit(3);
		auto message = Receive(pair);
		if (!message)
			_exit(4);
		auto value = message->Decode<types::Resource>();
		if (!value.is_ok())
			_exit(5);
		_exit(0);
	}
	int status;
	ASSERT_EQ(waitpid(child, &status, 0), child);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}
TEST(Codec, DeterministicMalformedInputCorpus)
{
	auto packet = Outgoing::Encode(types::Request("fuzz corpus"), 0,
	    ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto baseline = Bytes(*packet.value());
	std::mt19937 random(0x5b5d);
	for (unsigned i = 0; i < 512; ++i) {
		auto bytes = baseline;
		for (unsigned j = 0; j < 1 + random() % 5; ++j)
			bytes[16 + random() % (bytes.size() - 16)] = random();
		if (i % 3 == 0)
			bytes.resize(16 + random() % (bytes.size() - 15));
		Pair pair;
		ASSERT_EQ(RawSend(*pair.client, bytes), 0);
		auto message = Receive(pair);
		ASSERT_TRUE(message);
		auto result = message->template Decode<types::Request>();
		if (result.is_ok())
			EXPECT_LE(result->text().size(), 256u);
	}
}
namespace fidl::bsd {
struct ConnectionTestPeer {
	static void LastId(Connection &c) { c.next_id_ = UINT32_MAX; }
};
}
TEST(Protocol, TransactionExhaustionNeverWraps)
{
	Pair pair;
	ConnectionTestPeer::LastId(*pair.client);
	bindings::ServiceClient client(*pair.client);
	auto a = client.RoundTrip(types::Request("last"), [](auto) { });
	ASSERT_TRUE(a.is_ok());
	EXPECT_EQ(a.value(), UINT32_MAX);
	ASSERT_EQ(pair.client->Cancel(a.value()), 0);
	auto b = client.RoundTrip(types::Request("wrap"), [](auto) { });
	ASSERT_TRUE(b.is_error());
	EXPECT_EQ(b.error_value(), EOVERFLOW);
}
TEST(Protocol, EpitaphCompletesPendingAndShutdown)
{
	Pair pair;
	unsigned callbacks = 0;
	auto call = pair.client->Call<types::Request, types::Response>(ordinal,
	    types::Request("x"), [&](auto result) {
		    ++callbacks;
		    ASSERT_TRUE(result.is_error());
		    EXPECT_EQ(result.error_value(), EPIPE);
	    });
	ASSERT_TRUE(call.is_ok());
	std::unique_ptr<Incoming> request;
	pair.server->SetRequestHandler([&](auto m) { request = std::move(m); });
	pair.Pump(2);
	ASSERT_TRUE(request);
	ASSERT_EQ(pair.server->Shutdown(ZX_ERR_NOT_SUPPORTED), 0);
	EXPECT_EQ(pair.server->Send(ordinal, types::Empty()), ESHUTDOWN);
	for (int i = 0; i < 100 && !callbacks; ++i) {
		pair.server->Poll(1);
		pair.client->Poll(5);
	}
	EXPECT_EQ(callbacks, 1u);
	ASSERT_TRUE(pair.client->peer_epitaph());
	EXPECT_EQ(*pair.client->peer_epitaph(), ZX_ERR_NOT_SUPPORTED);
	pair.server->Poll(10);
	EXPECT_NE(pair.server->error(), 0);
}
TEST(Protocol, MalformedReplyBodyClosesConnection)
{
	Pair pair;
	unsigned callbacks = 0;
	std::unique_ptr<Incoming> request;
	pair.server->SetRequestHandler([&](auto m) { request = std::move(m); });
	auto call = pair.client->Call<types::Request, types::Response>(ordinal,
	    types::Request("x"), [&](auto result) {
		    ++callbacks;
		    EXPECT_TRUE(result.is_error());
	    });
	ASSERT_TRUE(call.is_ok());
	pair.Pump(2);
	ASSERT_TRUE(request);
	auto packet = Outgoing::Encode(types::Response("ok"),
	    request->header().txid, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto bytes = Bytes(*packet.value());
	bytes[32] = 0xff;
	ASSERT_EQ(RawSend(*pair.server, bytes, {},
		      channel_message_token(request->native())),
	    0);
	pair.Pump();
	EXPECT_EQ(callbacks, 1u);
	EXPECT_EQ(pair.client->error(), EPROTO);
}
TEST(Protocol, CallbackExceptionCannotEscapeCDispatch)
{
	Pair pair;
	Server server(*pair.server);
	server.Attach();
	bindings::ServiceClient client(*pair.client);
	auto call = client.RoundTrip(types::Request("x"),
	    [](auto) { throw std::runtime_error("callback"); });
	ASSERT_TRUE(call.is_ok());
	EXPECT_NO_THROW(pair.Pump());
	EXPECT_EQ(pair.client->error(), ECANCELED);
}
TEST(Codec, UnknownTableEnvelopeClosesDescriptor)
{
	Pair pair;
	Pipe pipe;
	// A two-slot table, with an unknown inline resource envelope in slot
	// two.
	std::vector<uint8_t> bytes(48);
	fidl_message_header_t h;
	fidl_init_txn_header(&h, 0, ordinal, 0);
	memcpy(bytes.data(), &h, 16);
	uint64_t count = 2, present = UINT64_MAX;
	memcpy(bytes.data() + 16, &count, 8);
	memcpy(bytes.data() + 24, &present, 8);
	uint32_t handle = FIDL_HANDLE_PRESENT;
	memcpy(bytes.data() + 40, &handle, 4);
	bytes[44] = 1;
	bytes[46] = 1;
	ASSERT_EQ(RawSend(*pair.client, bytes, { pipe.write.get() }), 0);
	pipe.write.reset();
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	auto result = message->Decode<types::Extensible>();
	ASSERT_TRUE(result.is_ok());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, CancellationOfQueuedRequestClosesAttachment)
{
	Pair pair;
	unsigned i = 0;
	while (!pair.client->wants_write() && i++ < 1024)
		ASSERT_EQ(pair.client->Send(ordinal, types::Empty()), 0);
	ASSERT_TRUE(pair.client->wants_write());
	Pipe pipe;
	unsigned calls = 0;
	auto call = pair.client->Call<types::Resource, types::Response>(ordinal,
	    types::Resource(std::move(pipe.write)), [&](auto result) {
		    ++calls;
		    ASSERT_TRUE(result.is_error());
		    EXPECT_EQ(result.error_value(), ECANCELED);
	    });
	ASSERT_TRUE(call.is_ok());
	EXPECT_FALSE(Eof(pipe));
	ASSERT_EQ(pair.client->Cancel(call.value()), 0);
	EXPECT_EQ(calls, 1u);
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, LateReplyClosesAllAttachments)
{
	Pair pair;
	std::unique_ptr<Incoming> request;
	pair.server->SetRequestHandler([&](auto m) { request = std::move(m); });
	auto call = pair.client->Call<types::Request, types::Response>(ordinal,
	    types::Request("x"), [](auto) { });
	ASSERT_TRUE(call.is_ok());
	pair.Pump(2);
	ASSERT_TRUE(request);
	ASSERT_EQ(pair.client->Cancel(call.value()), 0);
	Pipe pipe;
	auto packet = Outgoing::Encode(types::Resource(std::move(pipe.write)),
	    request->header().txid, ordinal);
	ASSERT_TRUE(packet.is_ok());
	ASSERT_EQ(RawSend(*pair.server, Bytes(*packet.value()),
		      { packet.value()->view().fds[0] },
		      channel_message_token(request->native())),
	    0);
	packet.value().reset();
	pair.Pump();
	EXPECT_TRUE(Eof(pipe));
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Codec, ReceiverRejectsWrongDescriptorType)
{
	Pair pair;
	Pipe pipe;
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::SocketResource>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, NonSendableDescriptorRejected)
{
	Pair pair;
	Pipe pipe;
	unsigned delivered = 0;
	pair.server->SetEventHandler([&](auto) { ++delivered; });
	ASSERT_EQ(cap_xfer_limit(pipe.write.get(), CAP_XFER_NONE), 0);
	EXPECT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    ENOTCAPABLE);
	pair.Pump(2);
	EXPECT_EQ(delivered, 0u);
	EXPECT_TRUE(Eof(pipe));
	EXPECT_EQ(pair.client->error(), 0);
	EXPECT_EQ(pair.client->Send(ordinal, types::Request("still usable")),
	    0);
	pair.Pump(2);
	EXPECT_EQ(delivered, 1u);
}
TEST(Codec, NonPassableDescriptorRejected)
{
	Pair pair;
	Descriptor queue(kqueue());
	ASSERT_TRUE(queue);
	int old = queue.get();
	unsigned delivered = 0;
	pair.server->SetEventHandler([&](auto) { ++delivered; });
	EXPECT_EQ(pair.client->Send(ordinal, types::Resource(std::move(queue))),
	    EINVAL);
	EXPECT_EQ(fcntl(old, F_GETFD), -1);
	EXPECT_EQ(errno, EBADF);
	pair.Pump(2);
	EXPECT_EQ(delivered, 0u);
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Codec, KernelTransferCeilingWinsOverSchema)
{
	Pair pair;
	Pipe pipe;
	cap_rights_t ceiling;
	cap_rights_init(&ceiling, CAP_WRITE);
	ASSERT_EQ(cap_xfer_rights_limit(pipe.write.get(), &ceiling), 0);
	ASSERT_EQ(pair.client->Send(ordinal,
		      types::Resource(std::move(pipe.write))),
	    0);
	auto message = Receive(pair);
	ASSERT_TRUE(message);
	EXPECT_TRUE(message->Decode<types::ReadOnly>().is_error());
	message.reset();
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, MalformedHeaderStillClosesAttachments)
{
	Pair pair;
	Pipe pipe;
	std::vector<uint8_t> bytes(8, 0);
	ASSERT_EQ(RawSend(*pair.client, bytes, { pipe.write.get() }), 0);
	pipe.write.reset();
	EXPECT_FALSE(Receive(pair));
	EXPECT_EQ(pair.server->error(), EPROTO);
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, MalformedEpitaphClosesAttachments)
{
	Pair pair;
	Pipe pipe;
	std::vector<uint8_t> bytes(24);
	fidl_message_header_t h;
	fidl_init_txn_header(&h, 0, kFidlOrdinalEpitaph, 0);
	memcpy(bytes.data(), &h, 16);
	ASSERT_EQ(RawSend(*pair.server, bytes, { pipe.write.get() }), 0);
	pipe.write.reset();
	for (int i = 0; i < 50 && !pair.client->error(); ++i)
		pair.client->Poll(5);
	EXPECT_EQ(pair.client->error(), EPROTO);
	EXPECT_TRUE(Eof(pipe));
}
TEST(Codec, ResourceMutationCorpusDoesNotLeak)
{
	std::mt19937 random(0x5b5d);
	for (unsigned i = 0; i < 256; ++i) {
		Pair pair;
		Pipe pipe;
		auto packet = Outgoing::Encode(types::Resource(
						   std::move(pipe.write)),
		    0, ordinal);
		ASSERT_TRUE(packet.is_ok());
		auto bytes = Bytes(*packet.value());
		bytes[16 + random() % 8] = random();
		ASSERT_EQ(RawSend(*pair.client, bytes,
			      { packet.value()->view().fds[0] }),
		    0);
		packet.value().reset();
		auto message = Receive(pair);
		ASSERT_TRUE(message);
		{
			auto value = message->Decode<types::Resource>();
		}
		message.reset();
		EXPECT_TRUE(Eof(pipe));
	}
}

TEST(Lifecycle, HandlerCanReplaceItself)
{
	Pair pair;
	struct State {
		bool *destroyed;
		~State() { *destroyed = true; }
	};
	bool destroyed = false;
	bool invoked = false;
	auto state = std::make_shared<State>();
	state->destroyed = &destroyed;
	pair.server->SetEventHandler([&, state](auto message) {
		pair.server->SetEventHandler({});
		EXPECT_FALSE(destroyed);
		EXPECT_TRUE(message->template Decode<types::Request>().is_ok());
		invoked = true;
	});
	state.reset();
	ASSERT_EQ(pair.client->Send(ordinal, types::Request("replace")), 0);
	pair.Pump();
	EXPECT_TRUE(invoked);
	EXPECT_TRUE(destroyed);
}

TEST(Lifecycle, RequestCannotBeRepliedOnAnotherConnection)
{
	Pair pair, other;
	std::unique_ptr<Incoming> retained;
	pair.server->SetRequestHandler(
	    [&](auto message) { retained = std::move(message); });
	bool completed = false;
	auto call = pair.client->Call<types::Request, types::Response>(ordinal,
	    types::Request("request"), [&](auto response) {
		    ASSERT_TRUE(response.is_ok());
		    EXPECT_EQ(response->text(), "right connection");
		    completed = true;
	    });
	ASSERT_TRUE(call.is_ok());
	pair.Pump();
	ASSERT_TRUE(retained);
	EXPECT_EQ(other.server->Reply(*retained, types::Response("wrong")),
	    EINVAL);
	EXPECT_FALSE(retained->replied());
	EXPECT_EQ(pair.server->Reply(*retained,
		      types::Response("right connection")),
	    0);
	EXPECT_TRUE(retained->replied());
	pair.Pump();
	EXPECT_TRUE(completed);
}

TEST(Codec, EmptyTransactionHasOnlyHeader)
{
	auto packet = Outgoing::Encode(Empty {}, 0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	EXPECT_EQ(packet.value()->view().length, sizeof(fidl_message_header_t));
	Pair pair;
	ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value())), 0);
	auto incoming = Receive(pair);
	ASSERT_TRUE(incoming);
	EXPECT_TRUE(incoming->Decode<Empty>().is_ok());
}
TEST(Codec, EmptyTransactionRejectsBytesAndDescriptors)
{
	for (bool attachment : { false, true }) {
		Pair pair;
		Pipe pipe;
		auto packet = Outgoing::Encode(Empty {}, 0, ordinal);
		ASSERT_TRUE(packet.is_ok());
		auto bytes = Bytes(*packet.value());
		if (!attachment)
			bytes.resize(bytes.size() + 8);
		ASSERT_EQ(RawSend(*pair.client, bytes,
			      attachment ?
				  std::vector<int> { pipe.write.get() } :
				  std::vector<int> {}),
		    0);
		pipe.write.reset();
		auto incoming = Receive(pair);
		ASSERT_TRUE(incoming);
		EXPECT_TRUE(incoming->Decode<Empty>().is_error());
		incoming.reset();
		EXPECT_TRUE(Eof(pipe));
	}
}
TEST(Protocol, GeneratedEmptyAndAnonymousPayloads)
{
	Pair pair;
	struct Server : bindings::ShapesServer {
		Connection &connection;
		explicit Server(Connection &c)
		    : connection(c)
		{
		}
		void Ping(Empty, std::unique_ptr<Incoming> request) override
		{
			EXPECT_EQ(ReplyPing(connection, *request, Empty {}), 0);
		}
		void Echo(types::ShapesEchoRequest value,
		    std::unique_ptr<Incoming> request) override
		{
			EXPECT_EQ(ReplyEcho(connection, *request,
				      types::ShapesEchoResponse(value.value())),
			    0);
		}
	} server(*pair.server);
	pair.server->SetRequestHandler([&](auto request) {
		server.Dispatch(*pair.server, std::move(request));
	});
	bindings::ShapesClient client(*pair.client);
	int completed = 0;
	ASSERT_TRUE(client
		.Ping(Empty {},
		    [&](auto value) {
			    EXPECT_TRUE(value.is_ok());
			    ++completed;
		    })
		.is_ok());
	ASSERT_TRUE(client
		.Echo(types::ShapesEchoRequest(42),
		    [&](auto value) {
			    ASSERT_TRUE(value.is_ok());
			    EXPECT_EQ(value->value(), 42u);
			    ++completed;
		    })
		.is_ok());
	pair.Pump();
	EXPECT_EQ(completed, 2);
}

TEST(Lifecycle, MetadataAllocationFailureClosesMovedDescriptor)
{
	Pipe pipe;
	auto resource = types::Resource(std::move(pipe.write));
	fidl::bsd::testing::FailMetadataAllocation();
	auto packet = Outgoing::Encode(std::move(resource), 0, ordinal);
	bool triggered = fidl::bsd::testing::DisableAllocationFault();
	ASSERT_TRUE(triggered);
	ASSERT_TRUE(packet.is_error());
	EXPECT_EQ(packet.error_value(), ENOMEM);
	EXPECT_TRUE(Eof(pipe));
}
TEST(Lifecycle, EncodeAllocationFailuresCloseMovedDescriptors)
{
	unsigned failures = 0;
	unsigned successes = 0;
	for (int count = 0; count < 16; ++count) {
		Pipe pipe;
		auto resource = types::Resource(std::move(pipe.write));
		fidl::bsd::testing::FailNewAfter(count);
		auto packet = Outgoing::Encode(std::move(resource), 0, ordinal);
		bool triggered = fidl::bsd::testing::DisableAllocationFault();
		if (triggered) {
			++failures;
			ASSERT_TRUE(packet.is_error());
			EXPECT_EQ(packet.error_value(), ENOMEM);
		} else {
			++successes;
			ASSERT_TRUE(packet.is_ok());
			packet.value().reset();
		}
		EXPECT_TRUE(Eof(pipe)) << "allocation index " << count;
	}
	EXPECT_GT(failures, 2u);
	EXPECT_GT(successes, 0u);
}

TEST(Lifecycle, DecodeAllocationFailuresCloseReceivedDescriptors)
{
	unsigned failures = 0, successes = 0;
	bool failed_before_transfer = false, failed_after_transfer = false;
	for (int count = 0; count < 12; ++count) {
		Pair pair;
		Pipe pipe;
		// Larger than inline decode storage, so decoding allocates
		// before descriptors are taken as well as after.
		auto packet = Outgoing::Encode(
		    types::DecodeAllocation(std::string(600, 'x'),
			std::move(pipe.write),
			std::vector<uint32_t> { 1, 2, 3 }),
		    0, ordinal);
		ASSERT_TRUE(packet.is_ok());
		auto view = packet.value()->view();
		ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value()),
			      { view.fds[0] }),
		    0);
		packet.value().reset();
		auto incoming = Receive(pair);
		ASSERT_TRUE(incoming);
		fidl::bsd::testing::FailNewAfter(count);
		auto result = incoming->Decode<types::DecodeAllocation>();
		bool triggered = fidl::bsd::testing::DisableAllocationFault();
		if (triggered) {
			++failures;
			if (channel_message_borrow_fd(incoming->native(), 0) >=
			    0)
				failed_before_transfer = true;
			else
				failed_after_transfer = true;
			ASSERT_TRUE(result.is_error());
			EXPECT_EQ(result.error_value(), ENOMEM);
		} else {
			++successes;
			ASSERT_TRUE(result.is_ok());
			EXPECT_EQ(result->prefix().size(), 600u);
			EXPECT_EQ(result->items().size(), 3u);
			result->fd().reset();
		}
		incoming.reset();
		EXPECT_TRUE(Eof(pipe)) << "decode allocation index " << count;
	}
	EXPECT_GE(failures, 2u);
	EXPECT_TRUE(failed_before_transfer);
	EXPECT_TRUE(failed_after_transfer);
	EXPECT_GT(successes, 0u);
}

static_assert(
    !std::is_convertible_v<ClientEnd<types::Shapes>, ServerEnd<types::Shapes>>);
TEST(Protocol, TypedEndpointRoundTripIsUsable)
{
	Pair pair;
	struct Server : bindings::EndpointExchangeServer {
		Connection &connection;
		explicit Server(Connection &c)
		    : connection(c)
		{
		}
		void RoundTrip(types::EndpointRequest value,
		    std::unique_ptr<Incoming> request) override
		{
			EXPECT_EQ(ReplyRoundTrip(connection, *request,
				      std::move(value)),
			    0);
		}
	} server(*pair.server);
	pair.server->SetRequestHandler([&](auto request) {
		server.Dispatch(*pair.server, std::move(request));
	});
	int ends[2];
	ASSERT_EQ(mac_capability_channel_create(ends), 0);
	auto receiving = Connection::Create(ends[1], CHANNEL_ROLE_PROVIDER);
	ASSERT_TRUE(receiving.is_ok());
	bool received = false;
	receiving.value()->SetEventHandler([&](auto request) {
		auto value = request->template Decode<types::Request>();
		ASSERT_TRUE(value.is_ok());
		EXPECT_EQ(value->text(), "typed endpoint");
		received = true;
	});
	bindings::EndpointExchangeClient client(*pair.client);
	Descriptor returned;
	ASSERT_TRUE(client
		.RoundTrip(types::EndpointRequest(
			       ClientEnd<types::Shapes>(Descriptor(ends[0]))),
		    [&](auto response) {
			    ASSERT_TRUE(response.is_ok());
			    returned = response->ep().take_descriptor();
		    })
		.is_ok());
	pair.Pump();
	ASSERT_TRUE(returned);
	auto sending = Connection::Create(returned.release(),
	    CHANNEL_ROLE_CLIENT);
	ASSERT_TRUE(sending.is_ok());
	ASSERT_EQ(sending.value()->Send(ordinal,
		      types::Request("typed endpoint")),
	    0);
	for (int i = 0; i < 10 && !received; ++i)
		receiving.value()->Poll(5);
	EXPECT_TRUE(received);
}
TEST(Codec, OptionalEndpointAndServerEndpoint)
{
	auto absent = Outgoing::Encode(types::OptionalEndpointRequest {}, 0,
	    ordinal);
	ASSERT_TRUE(absent.is_ok());
	Pair pair;
	ASSERT_EQ(RawSend(*pair.client, Bytes(*absent.value())), 0);
	auto incoming = Receive(pair);
	ASSERT_TRUE(incoming);
	auto value = incoming->Decode<types::OptionalEndpointRequest>();
	ASSERT_TRUE(value.is_ok());
	EXPECT_FALSE(value->ep());
	EXPECT_TRUE(
	    Outgoing::Encode(types::EndpointRequest {}, 0, ordinal).is_error());
	int ends[2];
	ASSERT_EQ(mac_capability_channel_create(ends), 0);
	Descriptor peer(ends[0]);
	auto packet = Outgoing::Encode(types::ServerEndpointRequest(
					   ServerEnd<types::Shapes>(
					       Descriptor(ends[1]))),
	    0, ordinal);
	ASSERT_TRUE(packet.is_ok());
	auto view = packet.value()->view();
	ASSERT_EQ(RawSend(*pair.client, Bytes(*packet.value()),
		      { view.fds[0] }),
	    0);
	incoming = Receive(pair);
	ASSERT_TRUE(incoming);
	auto server = incoming->Decode<types::ServerEndpointRequest>();
	ASSERT_TRUE(server.is_ok());
	EXPECT_TRUE(server->ep());
}
TEST(Codec, EndpointRejectsWrongNativeTypeAndClosesIt)
{
	Pipe pipe;
	auto packet = Outgoing::Encode(types::EndpointRequest(
					   ClientEnd<types::Shapes>(
					       std::move(pipe.write))),
	    0, ordinal);
	EXPECT_TRUE(packet.is_error());
	EXPECT_TRUE(Eof(pipe));
	Pair pair;
	Pipe incoming_pipe;
	auto raw = Outgoing::Encode(types::Resource(
					std::move(incoming_pipe.write)),
	    0, ordinal);
	ASSERT_TRUE(raw.is_ok());
	ASSERT_EQ(RawSend(*pair.client, Bytes(*raw.value()),
		      { raw.value()->view().fds[0] }),
	    0);
	raw.value().reset();
	auto incoming = Receive(pair);
	ASSERT_TRUE(incoming);
	EXPECT_TRUE(incoming->Decode<types::EndpointRequest>().is_error());
	incoming.reset();
	EXPECT_TRUE(Eof(incoming_pipe));
}

TEST(Lifecycle, CCollectionAllocationFailureCompletesOnceAndClosesDescriptors)
{
	unsigned failures = 0, successes = 0;
	for (int count = 0; count < 40; ++count) {
		Pair pair;
		Pipe pipe;
		fidl_bsd_connection client { std::move(pair.client) };
		fidl_bsd_connection server { std::move(pair.server) };
		bsd_runtime_test_Collections_server handlers {};
		handlers.Echo = [](void *, fidl_bsd_connection *connection,
				    fidl_bsd_request *request,
				    bsd_runtime_test_Collection *value) {
			EXPECT_EQ(bsd_runtime_test_Collections_Echo_reply(
				      connection, request, value),
			    0);
		};
		ASSERT_EQ(bsd_runtime_test_Collections_bind(&server, &handlers,
			      nullptr),
		    0);
		bsd_runtime_test_DictionaryEntry entry {};
		entry.key = "key";
		entry.key_size = 3;
		entry.value =
		    "this value exceeds the small string optimization";
		entry.value_size = strlen(entry.value);
		bsd_runtime_test_Collection value {};
		int descriptor = pipe.write.get();
		value.descriptors = &descriptor;
		value.descriptors_size = 1;
		value.entries = &entry;
		value.entries_size = 1;
		struct Completion {
			unsigned calls = 0;
			int error = 0;
			bool payload = false;
		} result;
		uint32_t txid;
		ASSERT_EQ(bsd_runtime_test_Collections_Echo(
			      &client, &value,
			      [](void *context, int error,
				  bsd_runtime_test_Collection *payload) {
				      auto *result = static_cast<Completion *>(
					  context);
				      ++result->calls;
				      result->error = error;
				      result->payload = payload != nullptr;
			      },
			      &result, &txid),
		    0);
		server.value->Poll(20);
		pipe.write.reset();
		fidl::bsd::testing::FailNewAfter(count);
		client.value->Poll(20);
		bool triggered = fidl::bsd::testing::DisableAllocationFault();
		ASSERT_EQ(result.calls, 1u) << "allocation index " << count;
		if (triggered) {
			++failures;
			EXPECT_EQ(result.error, ENOMEM)
			    << "allocation index " << count;
			EXPECT_FALSE(result.payload);
		} else {
			++successes;
			EXPECT_EQ(result.error, 0);
			EXPECT_TRUE(result.payload);
		}
		EXPECT_TRUE(Eof(pipe)) << "allocation index " << count;
	}
	// The C reply path decodes into an on-stack arena and may receive a
	// reply like this one without allocating at all; any allocation it
	// does make is failed above and must complete once with ENOMEM.
	EXPECT_GT(failures + successes, 0u);
	EXPECT_GT(successes, 0u);
}

template <typename GeneratedServer>
static void
UnknownRequests(bool accepts_one_way, bool accepts_two_way)
{
	for (bool flexible : { false, true }) {
		for (bool two_way : { false, true }) {
			Pair pair;
			Pipe pipe;
			struct Server : GeneratedServer {
				unsigned unknown = 0;
				bool was_two_way = false;
				void OnUnknownMethod(uint64_t got,
				    bool two) override
				{
					EXPECT_EQ(got, ordinal);
					++unknown;
					was_two_way = two;
				}
			} server;
			auto dispatch = [&](auto incoming) {
				server.Dispatch(*pair.server,
				    std::move(incoming));
			};
			pair.server->SetRequestHandler(dispatch);
			pair.server->SetEventHandler(dispatch);
			bool accepted = flexible &&
			    (two_way ? accepts_two_way : accepts_one_way);
			unsigned callbacks = 0;
			if (two_way) {
				auto call = pair.client->Call<types::Resource,
				    types::FlexibleEchoResult>(
				    ordinal,
				    types::Resource(std::move(pipe.write)),
				    [&](auto result) {
					    ++callbacks;
					    if (accepted) {
						    ASSERT_TRUE(result.is_ok());
						    ASSERT_TRUE(result
							    ->framework_err());
						    EXPECT_EQ(
							result->framework_err()
							    .value(),
							fidl::internal::
							    FrameworkErr::
								kUnknownMethod);
					    } else {
						    EXPECT_TRUE(
							result.is_error());
					    }
				    },
				    flexible);
				ASSERT_TRUE(call.is_ok());
			} else {
				ASSERT_EQ(pair.client->Send(ordinal,
					      types::Resource(
						  std::move(pipe.write)),
					      flexible),
				    0);
			}
			pair.Pump(3);
			EXPECT_EQ(server.unknown, accepted ? 1u : 0u);
			if (accepted)
				EXPECT_EQ(server.was_two_way, two_way);
			EXPECT_EQ(pair.server->error(), accepted ? 0 : EPROTO);
			EXPECT_EQ(callbacks, two_way ? 1u : 0u);
			EXPECT_TRUE(Eof(pipe));
		}
	}
}
TEST(Protocol, UnknownRequestOpennessMatrix)
{
	UnknownRequests<bindings::ClosedSurfaceServer>(false, false);
	UnknownRequests<bindings::AjarSurfaceServer>(true, false);
	UnknownRequests<bindings::OpenSurfaceServer>(true, true);
}
template <typename GeneratedEvents>
static void
UnknownEvents(bool allows_flexible)
{
	for (bool flexible : { false, true }) {
		Pair pair;
		Pipe pipe;
		struct Events : GeneratedEvents {
			unsigned unknown = 0;
			void OnUnknownEvent(uint64_t got) override
			{
				EXPECT_EQ(got, ordinal);
				++unknown;
			}
		} events;
		pair.client->SetEventHandler([&](auto incoming) {
			events.Dispatch(*pair.client, std::move(incoming));
		});
		ASSERT_EQ(pair.server->Send(ordinal,
			      types::Resource(std::move(pipe.write)), flexible),
		    0);
		pair.Pump(2);
		bool accepted = flexible && allows_flexible;
		EXPECT_EQ(events.unknown, accepted ? 1u : 0u);
		EXPECT_EQ(pair.client->error(), accepted ? 0 : EPROTO);
		EXPECT_TRUE(Eof(pipe));
	}
}
TEST(Protocol, UnknownEventOpennessMatrix)
{
	UnknownEvents<bindings::ClosedSurfaceEvents>(false);
	UnknownEvents<bindings::AjarSurfaceEvents>(true);
	UnknownEvents<bindings::OpenSurfaceEvents>(true);
}
TEST(Protocol, FlexibleUnknownMethodIsNonterminal)
{
	Pair pair;
	bindings::OpenSurfaceServer server;
	pair.server->SetRequestHandler([&](auto message) {
		server.Dispatch(*pair.server, std::move(message));
	});
	bindings::FlexibleClient client(*pair.client);
	unsigned completed = 0;
	for (unsigned i = 0; i < 2; ++i) {
		auto call = client.Echo(types::Request("future method"),
		    [&](auto result) {
			    ASSERT_TRUE(result.is_error());
			    EXPECT_EQ(result.error_value(), EOPNOTSUPP);
			    ++completed;
		    });
		ASSERT_TRUE(call.is_ok());
		pair.Pump(2);
		EXPECT_EQ(pair.client->error(), 0);
		EXPECT_EQ(pair.server->error(), 0);
	}
	EXPECT_EQ(completed, 2u);
}
TEST(Protocol, DefaultClientDiscardsKnownEvents)
{
	Pair pair;
	bindings::FlexibleClient client(*pair.client);
	ASSERT_EQ(bindings::FlexibleServer::Changed(*pair.server,
		      types::Response("ignored")),
	    0);
	pair.Pump(2);
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Protocol, KnownInteractionIgnoresStrictnessAndReservedFlags)
{
	Pair pair;
	bindings::FlexibleClient client(*pair.client);
	unsigned decoded = 0, completed = 0;
	pair.server->SetRequestHandler([&](auto message) {
		auto *header = static_cast<fidl_message_header_t *>(
		    const_cast<void *>(
			channel_message_data(message->native())));
		header->dynamic_flags = 0x7f; // strict plus unused flags,
					      // though the schema is flexible.
		header->at_rest_flags[0] |= 0x80;
		header->at_rest_flags[1] = 0xff;
		auto request = message->template Decode<types::Request>();
		ASSERT_TRUE(request.is_ok());
		++decoded;
		EXPECT_EQ(bindings::FlexibleServer::ReplyEcho(*pair.server,
			      *message,
			      types::FlexibleEchoResult::WithResponse(
				  types::Response("ok"))),
		    0);
	});
	ASSERT_TRUE(client
		.Echo(types::Request("input"),
		    [&](auto result) {
			    ASSERT_TRUE(result.is_ok());
			    ASSERT_TRUE(result->response());
			    EXPECT_EQ(result->response()->text(), "ok");
			    ++completed;
		    })
		.is_ok());
	pair.Pump(2);
	EXPECT_EQ(decoded, 1u);
	EXPECT_EQ(completed, 1u);
	EXPECT_EQ(pair.client->error(), 0);
}
TEST(Protocol, MalformedFrameworkErrorClosesAndCompletesOnce)
{
	for (bool attachment : { false, true }) {
		Pair pair;
		Pipe pipe;
		unsigned completed = 0;
		bindings::FlexibleClient client(*pair.client);
		pair.server->SetRequestHandler([&](auto message) {
			auto packet = Outgoing::Encode(
			    types::FlexibleEchoResult::WithFrameworkErr(
				fidl::internal::FrameworkErr::kUnknownMethod),
			    message->header().txid, message->header().ordinal,
			    true);
			ASSERT_TRUE(packet.is_ok());
			auto bytes = Bytes(*packet.value());
			ASSERT_EQ(bytes.size(), 32u);
			if (!attachment) {
				int32_t invalid = 42;
				memcpy(bytes.data() + 24, &invalid, 4);
			}
			EXPECT_EQ(RawSend(*pair.server, bytes,
				      attachment ?
					  std::vector<int> {
					      pipe.write.get() } :
					  std::vector<int> {},
				      channel_message_token(message->native())),
			    0);
			pipe.write.reset();
		});
		ASSERT_TRUE(client
			.Echo(types::Request("input"),
			    [&](auto result) {
				    ASSERT_TRUE(result.is_error());
				    EXPECT_EQ(result.error_value(), EPROTO);
				    ++completed;
			    })
			.is_ok());
		pair.Pump(2);
		EXPECT_EQ(completed, 1u);
		EXPECT_EQ(pair.client->error(), EPROTO);
		EXPECT_TRUE(Eof(pipe));
	}
}

TEST(Protocol, UnknownReplyChecksConnectionAndSingleCompletion)
{
	Pair pair, other;
	bindings::FlexibleClient client(*pair.client);
	unsigned requests = 0, completed = 0;
	pair.server->SetRequestHandler([&](auto message) {
		EXPECT_EQ(other.server->HandleUnknown(*message,
			      fidl::bsd::Openness::Open),
		    EINVAL);
		EXPECT_EQ(pair.server->HandleUnknown(*message,
			      fidl::bsd::Openness::Open),
		    0);
		EXPECT_EQ(pair.server->HandleUnknown(*message,
			      fidl::bsd::Openness::Open),
		    EALREADY);
		++requests;
	});
	ASSERT_TRUE(client
		.Echo(types::Request("unknown"),
		    [&](auto result) {
			    ASSERT_TRUE(result.is_error());
			    EXPECT_EQ(result.error_value(), EOPNOTSUPP);
			    ++completed;
		    })
		.is_ok());
	pair.Pump(3);
	EXPECT_EQ(requests, 1u);
	EXPECT_EQ(completed, 1u);
	EXPECT_EQ(pair.client->error(), 0);
	EXPECT_EQ(pair.server->error(), 0);
	EXPECT_EQ(other.server->error(), 0);
}
