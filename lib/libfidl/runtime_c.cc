/* SPDX-License-Identifier: BSD-2-Clause */
#include <fidl/bsd/c_bridge.h>
using fidl::bsd::CBoundary;
extern "C" {
uint32_t
fidl_bsd_runtime_abi_version(void)
{
	return FIDL_BSD_ABI_VERSION;
}
int
fidl_bsd_connection_create(int fd, enum fidl_bsd_role role,
    fidl_bsd_connection **result)
{
	return fidl_bsd_connection_create_with_options(fd, role, nullptr,
	    result);
}
int
fidl_bsd_connection_create_with_options(int fd, enum fidl_bsd_role role,
    const fidl_bsd_options *options, fidl_bsd_connection **result)
{
	if (!result)
		return EINVAL;
	*result = nullptr;
	if (role != FIDL_BSD_CLIENT && role != FIDL_BSD_SERVER)
		return EINVAL;
	channel_options limits = CHANNEL_OPTIONS_INITIALIZER(
	    static_cast<channel_role>(role));
	if (options) {
		if (options->size != sizeof(*options) ||
		    options->reserved != 0 ||
		    options->max_pending_requests > SIZE_MAX ||
		    options->max_queued_messages > SIZE_MAX ||
		    options->max_queued_bytes > SIZE_MAX ||
		    options->max_queued_fds > SIZE_MAX)
			return EINVAL;
		limits.max_pending_requests = options->max_pending_requests;
		limits.max_queued_messages = options->max_queued_messages;
		limits.max_queued_bytes = options->max_queued_bytes;
		limits.max_queued_fds = options->max_queued_fds;
	}
	return CBoundary([&]() -> int {
		auto c = std::make_unique<fidl_bsd_connection>();
		auto native = fidl::bsd::Connection::Create(fd,
		    static_cast<channel_role>(role), &limits);
		if (native.is_error())
			return native.error_value();
		c->value = std::move(native.value());
		c->value->LockSentDescriptorInheritance();
		*result = c.release();
		return 0;
	});
}
int
fidl_bsd_connection_peer_epitaph(const fidl_bsd_connection *connection,
    int32_t *status)
{
	if (!connection || !status)
		return EINVAL;
	auto value = connection->value->peer_epitaph();
	if (!value)
		return ENOENT;
	*status = *value;
	return 0;
}

void
fidl_bsd_connection_destroy(fidl_bsd_connection *c)
{
	if (!c)
		return;
	// Complete pending calls while the handle is still valid; their
	// callbacks may query or close this connection.
	c->value->Close(ECANCELED);
	delete c;
}
void
fidl_bsd_connection_close(fidl_bsd_connection *c, int error)
{
	if (c)
		c->value->Close(error);
}
int
fidl_bsd_connection_poll(fidl_bsd_connection *c, int timeout)
{
	return c ? CBoundary([&] { return c->value->Poll(timeout); }) : EINVAL;
}
int
fidl_bsd_connection_dispatch(fidl_bsd_connection *c)
{
	return c ? CBoundary([&] { return c->value->Dispatch(); }) : EINVAL;
}
int
fidl_bsd_connection_fd(const fidl_bsd_connection *c)
{
	return c ? c->value->fd() : -1;
}
int
fidl_bsd_connection_wants_write(const fidl_bsd_connection *c)
{
	return c ? c->value->wants_write() : 0;
}
int
fidl_bsd_connection_error(const fidl_bsd_connection *c)
{
	return c ? c->value->error() : EINVAL;
}
int
fidl_bsd_connection_cancel(fidl_bsd_connection *c, uint32_t id)
{
	return c ? CBoundary([&] { return c->value->Cancel(id); }) : EINVAL;
}
int
fidl_bsd_connection_shutdown(fidl_bsd_connection *c, int32_t status)
{
	return c ? CBoundary([&] { return c->value->Shutdown(status); }) :
		   EINVAL;
}
void
fidl_bsd_request_retain(fidl_bsd_request *request)
{
	if (request)
		++request->references;
}
void
fidl_bsd_request_release(fidl_bsd_request *request)
{
	if (request && --request->references == 0)
		delete request;
}
int
fidl_bsd_take_fd(int *fd)
{
	if (!fd)
		return -1;
	return std::exchange(*fd, -1);
}
const channel_message *
fidl_bsd_request_native(const fidl_bsd_request *request)
{
	return request ? request->value->native() : nullptr;
}
}
