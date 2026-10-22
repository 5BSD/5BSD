/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>

#include <fidl/bsd/c_bridge.h>
#include <errno.h>
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
		c->requests =
		    std::make_shared<fidl::bsd::Slab<fidl_bsd_request>>(
			limits.max_pending_requests);
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
fidl_bsd_connection_preserve_sent_inheritance(fidl_bsd_connection *c)
{
	if (c)
		c->value->PreserveSentDescriptorInheritance();
}
int
fidl_bsd_connection_call(fidl_bsd_connection *c, uint32_t timeout_ms,
    int (*issue)(void *), void *context)
{
	if (!c || !issue)
		return EINVAL;
	return CBoundary([&] {
		return c->value->CallSync(
		    timeout_ms > INT_MAX ? INT_MAX : static_cast<int>(timeout_ms),
		    issue, context);
	});
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
	if (!request || --request->references != 0)
		return;
	// The slab outlives its connection while any context refers to it.
	auto slab = std::move(request->slab);
	if (!slab) {
		delete request;
		return;
	}
	request->~fidl_bsd_request();
	slab->Put(request);
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
int
fidl_bsd_connections_wait(int kq, fidl_bsd_connection_slot *slots,
    size_t count, int listener, int timeout_ms, int *listener_ready)
{
	struct kevent changes[513], events[513];
	unsigned char ready[256] = {};
	struct timespec timeout;
	int nchanges = 0, n;
	if (listener_ready == nullptr || kq < 0 || count > 256 ||
	    (count != 0 && slots == nullptr) || timeout_ms < -1)
		return EINVAL;
	*listener_ready = 0;
	if (listener >= 0) {
		EV_SET(&changes[nchanges], listener, EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, nullptr);
		nchanges++;
	}
	for (size_t i = 0; i < count; i++) {
		slots[i].error = 0;
		fidl_bsd_connection *c = slots[i].connection;
		if (c == nullptr)
			continue;
		if (int error = c->value->error()) {
			slots[i].error = error;
			timeout_ms = 0;
			continue;
		}
		int fd = c->value->fd();
		void *tag = reinterpret_cast<void *>(static_cast<uintptr_t>(i + 1));
		EV_SET(&changes[nchanges], fd, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0, tag);
		nchanges++;
		EV_SET(&changes[nchanges], fd, EVFILT_WRITE,
		    EV_ADD | (c->value->wants_write() ? EV_ENABLE : EV_DISABLE),
		    0, 0, tag);
		nchanges++;
	}
	timeout.tv_sec = timeout_ms < 0 ? 0 : timeout_ms / 1000;
	timeout.tv_nsec = timeout_ms < 0 ? 0 : (timeout_ms % 1000) * 1000000L;
	n = kevent(kq, changes, nchanges, events, 513,
	    timeout_ms == -1 ? nullptr : &timeout);
	if (n == -1)
		return errno == EINTR ? 0 : errno;
	for (int e = 0; e < n; e++) {
		uintptr_t tag = reinterpret_cast<uintptr_t>(events[e].udata);
		if (tag == 0) {
			// As service_channels_wait(3): a failed listener ends
			// the provider loop.
			if (events[e].flags & (EV_ERROR | EV_EOF))
				return EPIPE;
			*listener_ready = 1;
			continue;
		}
		if (tag > count)
			return EPROTO;
		if (events[e].flags & EV_ERROR)
			slots[tag - 1].error = events[e].data != 0 ?
			    static_cast<int>(events[e].data) : EIO;
		ready[tag - 1] = 1;
	}
	for (size_t i = 0; i < count; i++) {
		if (slots[i].connection == nullptr || slots[i].error != 0 ||
		    !ready[i])
			continue;
		slots[i].error = fidl_bsd_connection_dispatch(
		    slots[i].connection);
	}
	return 0;
}
}
