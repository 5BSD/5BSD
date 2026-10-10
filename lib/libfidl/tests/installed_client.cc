/* SPDX-License-Identifier: BSD-2-Clause */
// Build against installed headers and a shared library, without source
// includes.
#include <cstdlib>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
namespace b = bsd_runtime_test::bsd;
using namespace fidl::bsd;
struct Server : b::ShapesServer {
	Connection &connection;
	explicit Server(Connection &c)
	    : connection(c)
	{
	}
	void Ping(Empty, std::unique_ptr<Incoming> request) override
	{
		if (ReplyPing(connection, *request, Empty {}))
			std::abort();
	}
	void Echo(bsd_runtime_test::ShapesEchoRequest value,
	    std::unique_ptr<Incoming> request) override
	{
		if (ReplyEcho(connection, *request,
			bsd_runtime_test::ShapesEchoResponse(value.value())))
			std::abort();
	}
};
int
main()
{
	int ends[2];
	if (mac_capability_channel_create(ends))
		return 1;
	auto client = Connection::Create(ends[0], CHANNEL_ROLE_CLIENT);
	auto server = Connection::Create(ends[1], CHANNEL_ROLE_PROVIDER);
	if (client.is_error() || server.is_error())
		return 2;
	Server handler(*server.value());
	server.value()->SetRequestHandler([&](auto request) {
		handler.Dispatch(*server.value(), std::move(request));
	});
	b::ShapesClient peer(*client.value());
	bool completed = false;
	if (peer.Ping(Empty {},
		    [&](auto response) { completed = response.is_ok(); })
		.is_error())
		return 3;
	for (int i = 0; i < 100 && !completed; ++i) {
		if (server.value()->Poll(10) || client.value()->Poll(10))
			return 4;
	}
	return completed ? 0 : 5;
}
