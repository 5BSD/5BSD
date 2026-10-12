/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <fcntl.h>
#include <fidl/bsd/runtime.h>
#include <limits>
#include <new>

#include "fidl_probes.h"

namespace fidl::bsd {
static_assert(kMaxMessageBytes == MAC_CAPABILITY_MAX_MSG);
static_assert(kMaxDescriptors == MAC_CAPABILITY_MAX_FDS);
namespace {
// Wire type and rights to the expectation the send system call checks.
// Explicit mappings, never casts of rights masks.  Rights of exactly zero
// have no spec form (zero keeps rights) and are narrowed in userland.
int
DescriptorSpec(uint32_t type, uint32_t rights, channel_fd_spec *spec)
{
	*spec = {};
	switch (type) {
	case ZX_OBJ_TYPE_NONE:
		spec->type = CHANNEL_FD_TYPE_ANY;
		break;
	case ZX_OBJ_TYPE_SOCKET:
		spec->type = CHANNEL_FD_TYPE_SOCKET;
		break;
	case ZX_OBJ_TYPE_CHANNEL:
		spec->type = CHANNEL_FD_TYPE_CHANNEL;
		break;
	default:
		return EOPNOTSUPP;
	}
	if (rights == ZX_RIGHT_SAME_RIGHTS)
		return 0;
	if (type == ZX_OBJ_TYPE_CHANNEL ||
	    (rights & ~(ZX_RIGHT_READ | ZX_RIGHT_WRITE)) != 0)
		return EOPNOTSUPP;
	if (rights & ZX_RIGHT_READ)
		spec->rights |= CHANNEL_FD_RIGHT_READ;
	if (rights & ZX_RIGHT_WRITE)
		spec->rights |= CHANNEL_FD_RIGHT_WRITE;
	return 0;
}
void
CloseSlot(fidl_handle_t slot)
{
	if (slot != 0 && slot - 1 <= static_cast<uint32_t>(INT_MAX))
		close(static_cast<int>(slot - 1));
}
void
CloseSlots(const fidl_handle_t *slots, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		CloseSlot(slots[i]);
}
zx_status_t
EncodeHandle(internal::HandleAttributes attr, uint32_t index, void *metadata,
    const char **)
{
	static_cast<Transport::HandleMetadata *>(
	    metadata)[index] = { attr.obj_type, attr.rights };
	return ZX_OK;
}
// Check a received descriptor against the kernel's report of its type and
// rights.  Narrowing costs one cap_rights_limit(2), and none when the sender
// already narrowed it to exactly the rights required here.
int
CheckReported(int fd, uint32_t type, uint32_t rights,
    const channel_fd_info &info)
{
	channel_fd_spec spec;
	int error = DescriptorSpec(type, rights, &spec);
	if (error)
		return error;
	if (spec.type != CHANNEL_FD_TYPE_ANY && info.type != spec.type)
		return EFTYPE;
	if (rights == ZX_RIGHT_SAME_RIGHTS)
		return 0;
	uint32_t needed = spec.rights |
	    (spec.type == CHANNEL_FD_TYPE_SOCKET ? CHANNEL_FD_RIGHT_FSTAT : 0);
	const uint32_t known = CHANNEL_FD_RIGHT_READ | CHANNEL_FD_RIGHT_WRITE |
	    CHANNEL_FD_RIGHT_FSTAT;
	if ((info.rights & needed) != needed)
		return ENOTCAPABLE;
	if ((info.rights & CHANNEL_FD_RIGHTS_EXACT) &&
	    (info.rights & known) == needed)
		return 0;
	cap_rights_t limit;
	cap_rights_init(&limit);
	if (needed & CHANNEL_FD_RIGHT_FSTAT)
		cap_rights_set(&limit, CAP_FSTAT);
	if (needed & CHANNEL_FD_RIGHT_READ)
		cap_rights_set(&limit, CAP_READ);
	if (needed & CHANNEL_FD_RIGHT_WRITE)
		cap_rights_set(&limit, CAP_WRITE);
	return cap_rights_limit(fd, &limit) == 0 ? 0 : errno;
}
zx_status_t
DecodeHandle(fidl_handle_t *slot, internal::HandleAttributes attr,
    uint32_t index, const void *metadata, const char **error)
{
	// Never trust peer metadata.  Incoming fills the metadata array with
	// the kernel's report of each installed descriptor, when available;
	// otherwise query the descriptor.  An untyped SAME_RIGHTS slot has
	// nothing to check: the kernel just installed a valid descriptor.
	int result;
	const auto &reported =
	    static_cast<const Transport::HandleMetadata *>(metadata)[index];
	if (*slot == 0 || *slot - 1 > static_cast<uint32_t>(INT_MAX))
		result = EBADF;
	else if (attr.obj_type == ZX_OBJ_TYPE_NONE &&
	    attr.rights == ZX_RIGHT_SAME_RIGHTS)
		result = 0;
	else if (reported.obj_type & kKernelReported)
		result = CheckReported(static_cast<int>(*slot - 1),
		    attr.obj_type, attr.rights,
		    { reported.obj_type & ~kKernelReported,
			reported.rights });
	else
		result = ValidateDescriptor(static_cast<int>(*slot - 1),
		    attr.obj_type, attr.rights);
	if (!result)
		return ZX_OK;
	*error = "native descriptor type or rights constraint failed";
	return ZX_ERR_INVALID_ARGS; // Decoder retains and closes this slot on
				    // failure.
}
const internal::CodingConfig coding = {
	.handle_metadata_stride = sizeof(Transport::HandleMetadata),
	.encode_process_handle = EncodeHandle,
	.decode_process_handle = DecodeHandle,
	.close = CloseSlot,
	.close_many = CloseSlots,
};
}
// The codec uses this transport's ownership hooks. I/O is supplied by
// Connection through libchannel, not by Fuchsia's WireClient or dispatcher.
const internal::TransportVTable Transport::VTable = {
	.type = static_cast<internal::fidl_transport_type>(3),
	.encoding_configuration = &coding,
};

int
ValidateDescriptor(int fd, uint32_t type, uint32_t rights)
{
	cap_rights_t actual;
	if (cap_rights_get(fd, &actual) != 0)
		return errno;
	switch (type) {
	case ZX_OBJ_TYPE_NONE:
		break;
	case ZX_OBJ_TYPE_SOCKET: {
		struct stat st;
		if (fstat(fd, &st) != 0)
			return errno;
		if (!S_ISSOCK(st.st_mode))
			return EFTYPE;
		break;
	}
	case ZX_OBJ_TYPE_CHANNEL: {
		mac_capability_info_args info {};
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0)
			return errno;
		if (strncmp(info.name, "channel", sizeof(info.name)) != 0)
			return EFTYPE;
		break;
	}
	default:
		return EOPNOTSUPP;
	}
	if (type == ZX_OBJ_TYPE_CHANNEL && rights != ZX_RIGHT_SAME_RIGHTS)
		return EOPNOTSUPP;
	// These are explicit wire-to-Capsicum mappings, never casts of rights
	// masks.
	if (rights == ZX_RIGHT_SAME_RIGHTS)
		return 0;
	if (rights & ~(ZX_RIGHT_READ | ZX_RIGHT_WRITE))
		return EOPNOTSUPP;
	cap_rights_t needed;
	cap_rights_init(&needed);
	if (type == ZX_OBJ_TYPE_SOCKET)
		cap_rights_set(&needed, CAP_FSTAT);
	if (rights & ZX_RIGHT_READ)
		cap_rights_set(&needed, CAP_READ);
	if (rights & ZX_RIGHT_WRITE)
		cap_rights_set(&needed, CAP_WRITE);
	if (!cap_rights_contains(&actual, &needed))
		return ENOTCAPABLE;
	// Narrow the moved capability; never amplify it. Transfer ceilings
	// remain kernel state and cannot be minted by a FIDL annotation.
	if (cap_rights_limit(fd, &needed) != 0)
		return errno;
	return 0;
}

int
Outgoing::PrepareEmpty(uint32_t txid, uint64_t ordinal)
{
	return PrepareEmpty(txid, ordinal, false);
}
int
Outgoing::PrepareEmpty(uint32_t txid, uint64_t ordinal, bool flexible)
{
	if (ordinal == 0 || ordinal == kFidlOrdinalEpitaph)
		return EINVAL;
	fidl_message_header_t header;
	fidl_init_txn_header(&header, txid, ordinal,
	    flexible ? FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_FLEXIBLE_METHOD :
		       FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_STRICT_METHOD);
	bytes_.resize(sizeof(header));
	memcpy(bytes_.data(), &header, sizeof(header));
	return 0;
}
int
Outgoing::Prepare(fidl::OutgoingMessage &body, uint32_t txid, uint64_t ordinal)
{
	return Prepare(body, txid, ordinal, false);
}
int
Outgoing::Prepare(fidl::OutgoingMessage &body, uint32_t txid, uint64_t ordinal,
    bool flexible)
{
	const uint32_t size = body.CountBytes();
	if (size > MAC_CAPABILITY_MAX_MSG - sizeof(fidl_message_header_t) ||
	    body.handle_actual() > MAC_CAPABILITY_MAX_FDS || ordinal == 0 ||
	    ordinal == kFidlOrdinalEpitaph)
		return EMSGSIZE;
	bytes_.resize(sizeof(fidl_message_header_t) + size);
	fidl_message_header_t header;
	fidl_init_txn_header(&header, txid, ordinal,
	    flexible ? FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_FLEXIBLE_METHOD :
		       FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_STRICT_METHOD);
	memcpy(bytes_.data(), &header, sizeof(header));
	size_t offset = sizeof(header);
	for (uint32_t i = 0; i < body.iovec_actual(); ++i) {
		memcpy(bytes_.data() + offset, body.iovecs()[i].buffer,
		    body.iovecs()[i].capacity);
		offset += body.iovecs()[i].capacity;
	}
	fds_.reserve(body.handle_actual());
	specs_.reserve(body.handle_actual());
	owners_.reserve(body.handle_actual());
	auto *metadata = body.handle_metadata<Transport>();
	for (uint32_t i = 0; i < body.handle_actual(); ++i) {
		auto slot = body.handles()[i];
		if (slot == 0 || slot - 1 > static_cast<uint32_t>(INT_MAX))
			return EBADF;
		int fd = static_cast<int>(slot - 1);
		channel_fd_spec spec {};
		int error = DescriptorSpec(metadata[i].obj_type,
		    metadata[i].rights, &spec);
		if (!error && (!defer_checks_ || metadata[i].rights == 0))
			error = ValidateDescriptor(fd, metadata[i].obj_type,
			    metadata[i].rights);
		if (error)
			return error;
		fds_.push_back(fd);
		specs_.push_back(spec);
	}
	// All allocations and checks precede ownership transfer.
	for (int fd : fds_)
		owners_.emplace_back(fd);
	body.ReleaseHandles();
	return 0;
}

int
Outgoing::RawStart(uint32_t txid, uint64_t ordinal, bool flexible)
{
	Reset();
	return PrepareEmpty(txid, ordinal, flexible);
}
size_t
Outgoing::RawAlloc(size_t size)
{
	const size_t offset = RawLength();
	const size_t aligned = (size + 7) & ~size_t(7);
	if (size > MAC_CAPABILITY_MAX_MSG || aligned >
	    MAC_CAPABILITY_MAX_MSG - sizeof(fidl_message_header_t) - offset)
		return SIZE_MAX;
	bytes_.resize(bytes_.size() + aligned);
	return offset;
}
int
Outgoing::RawHandle(int fd, uint32_t type, uint32_t rights)
{
	if (fds_.size() >= MAC_CAPABILITY_MAX_FDS)
		return EMSGSIZE;
	channel_fd_spec spec {};
	int error = DescriptorSpec(type, rights, &spec);
	if (error)
		return error;
	fds_.reserve(fds_.size() + 1);
	specs_.reserve(specs_.size() + 1);
	owners_.reserve(owners_.size() + 1);
	int copy = fcntl(fd, F_DUPFD_CLOFORK, 0);
	if (copy < 0)
		return errno;
	owners_.emplace_back(copy);
	if (!defer_checks_ || rights == 0) {
		error = ValidateDescriptor(copy, type, rights);
		if (error) {
			owners_.pop_back();
			return error;
		}
	}
	fds_.push_back(copy);
	specs_.push_back(spec);
	return 0;
}
int
CheckReceivedDescriptor(int fd, uint32_t type, uint32_t rights,
    uint32_t reported_type, uint32_t reported_rights)
{
	if (type == ZX_OBJ_TYPE_NONE && rights == ZX_RIGHT_SAME_RIGHTS)
		return 0;
	if (reported_type & kKernelReported)
		return CheckReported(fd, type, rights,
		    { reported_type & ~kKernelReported, reported_rights });
	return ValidateDescriptor(fd, type, rights);
}

fidl_message_header_t
Incoming::header() const
{
	fidl_message_header_t result {};
	if (message_ && channel_message_length(native()) >= sizeof(result))
		memcpy(&result, channel_message_data(native()), sizeof(result));
	return result;
}
int
Incoming::Validate(uint64_t ordinal, std::optional<uint32_t> txid) const
{
	if (!message_ ||
	    channel_message_length(native()) < sizeof(fidl_message_header_t) ||
	    channel_message_length(native()) > MAC_CAPABILITY_MAX_MSG ||
	    channel_message_fd_count(native()) > MAC_CAPABILITY_MAX_FDS) {
		FIDL_BSD_VALIDATION_FAILED(reinterpret_cast<uintptr_t>(this), 0,
		    ordinal, 1);
		return EPROTO;
	}
	auto h = header();
	if (fidl_validate_txn_header(&h) != ZX_OK || h.ordinal != ordinal ||
	    ordinal == 0 ||
	    (h.at_rest_flags[0] &
		FIDL_MESSAGE_HEADER_AT_REST_FLAGS_0_USE_VERSION_V2) == 0 ||
	    (txid && h.txid != *txid)) {
		FIDL_BSD_VALIDATION_FAILED(reinterpret_cast<uintptr_t>(this),
		    h.txid, h.ordinal, 2);
		return EPROTO;
	}
	bool event = channel_message_kind(native()) == CHANNEL_MESSAGE_EVENT;
	if ((h.txid == 0) != event) {
		FIDL_BSD_VALIDATION_FAILED(reinterpret_cast<uintptr_t>(this),
		    h.txid, h.ordinal, 3);
		return EPROTO;
	}
	return 0;
}

Result<std::unique_ptr<Connection>>
Connection::Create(int fd, channel_role role, const channel_options *supplied)
{
	try {
		auto result = std::unique_ptr<Connection>(
		    new Connection(nullptr, role));
		// Recycling a completed call must never allocate.
		result->free_pending_.reserve(kPendingPoolLimit);
		channel_options options = CHANNEL_OPTIONS_INITIALIZER(role);
		if (supplied)
			options = *supplied;
		if (options.role != role)
			return fit::error(EINVAL);
		if (channel_create(fd, &options, &result->channel_) != 0)
			return fit::error(errno);
		channel_set_request_handler(result->channel_, OnMessage,
		    result.get());
		channel_set_event_handler(result->channel_, OnMessage,
		    result.get());
		return fit::ok(std::move(result));
	} catch (const std::bad_alloc &) {
		return fit::error(ENOMEM);
	}
}
Connection::~Connection()
{
	Close();
}
void
Connection::Close(int error)
{
	if (!error_)
		error_ = error ? error : ECANCELED;
	FIDL_BSD_CLOSE(reinterpret_cast<uintptr_t>(this), error_);
	channel *old = std::exchange(channel_, nullptr);
	if (old)
		channel_destroy(old);
}
int
Connection::HandleUnknown(Incoming &request, Openness openness)
{
	auto h = request.header();
	if (error())
		return error();
	if (closing_)
		return ESHUTDOWN;
	if (request.origin_ != identity_)
		return EINVAL;
	if (request.Validate(h.ordinal, h.txid) ||
	    !(h.dynamic_flags &
		FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_FLEXIBLE_METHOD) ||
	    openness == Openness::Closed ||
	    (h.txid &&
		(openness != Openness::Open || role_ != CHANNEL_ROLE_PROVIDER)))
		return EPROTO;
	if (!h.txid)
		return 0;
	if (request.replied_)
		return EALREADY;
	// Standard FIDL v2 result union: tag 3, inline framework error, no
	// handles. Keep native reply-token matching; no Zircon transaction
	// object is used.
	struct {
		fidl_message_header_t header;
		fidl_union_t body;
	} reply {};
	static_assert(sizeof(reply) == 32);
	fidl_init_txn_header(&reply.header, h.txid, h.ordinal,
	    FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_FLEXIBLE_METHOD);
	reply.body.tag = 3;
	reply.body.envelope.flags = FIDL_ENVELOPE_FLAGS_INLINING_MASK;
	int32_t status = FIDL_FRAMEWORK_ERR_UNKNOWN_METHOD;
	memcpy(reply.body.envelope.inline_value, &status, sizeof(status));
	channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply));
	if (channel_send_reply(request.native(), &view) != 0)
		return errno;
	request.replied_ = true;
	return 0;
}
int
Connection::Shutdown(zx_status_t epitaph)
{
	if (error())
		return error();
	if (role_ != CHANNEL_ROLE_PROVIDER)
		return EINVAL;
	if (closing_)
		return EALREADY;
	struct {
		fidl_message_header_t header;
		int32_t status;
		uint32_t padding;
	} packet {};
	static_assert(sizeof(packet) == 24);
	fidl_init_txn_header(&packet.header, 0, kFidlOrdinalEpitaph,
	    FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_STRICT_METHOD);
	packet.status = epitaph;
	channel_outgoing view = CHANNEL_OUTGOING_INITIALIZER(&packet,
	    sizeof(packet));
	if (channel_send_event(channel_, &view) != 0)
		return errno;
	closing_ = true;
	return 0;
}
uint32_t
Connection::AllocateId()
{
	// Never reuse on a connection, including after cancellation. Reconnect
	// on exhaustion; native random 64-bit reply tokens remain opaque to
	// this layer.
	if (next_id_ == 0)
		return 0;
	return next_id_++;
}
std::unique_ptr<Connection::Pending>
Connection::TakePending()
{
	if (free_pending_.empty())
		return std::make_unique<Pending>();
	auto pending = std::move(free_pending_.back());
	free_pending_.pop_back();
	return pending;
}
void
Connection::RecyclePending(std::unique_ptr<Pending> pending)
{
	pending->completion = nullptr;
	pending->request = nullptr;
	pending->prev = pending->next = nullptr;
	// Capacity is reserved at creation, so this never allocates.
	if (free_pending_.size() < free_pending_.capacity())
		free_pending_.push_back(std::move(pending));
}
void
Connection::Unlink(Pending *pending)
{
	if (pending->prev)
		pending->prev->next = pending->next;
	else
		active_ = pending->next;
	if (pending->next)
		pending->next->prev = pending->prev;
	pending->prev = pending->next = nullptr;
}
int
Connection::SendRequest(uint32_t id, uint64_t ordinal, Outgoing &packet,
    Completion completion)
{
	auto pending = TakePending();
	pending->owner = this;
	pending->id = id;
	pending->ordinal = ordinal;
	pending->completion = std::move(completion);
	auto view = packet.MoveView(lock_inherit_);
	auto *raw = pending.get();
	FIDL_BSD_TRANSPORT(reinterpret_cast<uintptr_t>(this),
	    reinterpret_cast<uintptr_t>(channel_), id, ordinal);
	FIDL_BSD_REQUEST_START(reinterpret_cast<uintptr_t>(this), id, ordinal,
	    view.length, view.nfds);
	if (channel_send_request(channel_, &view, OnReply, raw,
		&raw->request) != 0) {
		int error = errno;
		FIDL_BSD_REQUEST_DONE(reinterpret_cast<uintptr_t>(this), id,
		    ordinal, error);
		RecyclePending(std::move(pending));
		return error;
	}
	packet.Sent();
	// Owned by the list until OnReply completes it.
	raw->next = active_;
	if (active_)
		active_->prev = raw;
	active_ = raw;
	pending.release();
	return 0;
}
void
Connection::OnReply(channel_request *request, channel_message *message,
    int error, void *context)
{
	auto *pending = static_cast<Pending *>(context);
	auto *self = pending->owner;
	std::unique_ptr<Pending> owned_pending(pending);
	self->Unlink(pending);
	channel_request_release(request);
	// A reply is decoded inside its completion, so it lives on this stack.
	Incoming incoming { Message(message) };
	if (error && self->error_)
		error = self->error_;
	if (!error)
		error = incoming.Validate(pending->ordinal, pending->id);
	if (!error)
		FIDL_BSD_MESSAGE_TOKEN(reinterpret_cast<uintptr_t>(self),
		    pending->id, pending->ordinal,
		    channel_message_token(message));
	FIDL_BSD_REQUEST_DONE(reinterpret_cast<uintptr_t>(self), pending->id,
	    pending->ordinal, error);
	if (error == EPROTO || error == ENOMEM)
		self->Close(error);
	try {
		pending->completion(error, error ? nullptr : &incoming);
	} catch (...) {
		// User callbacks may not unwind across the C dispatch boundary.
		self->Close(ECANCELED);
	}
	self->RecyclePending(std::move(owned_pending));
}
void
Connection::OnMessage(channel *, channel_message *message, void *context)
{
	Message owned(message);
	auto *self = static_cast<Connection *>(context);
	try {
		auto incoming = std::make_unique<Incoming>(std::move(owned));
		incoming->origin_ = self->identity_;
		auto h = incoming->header();
		if (incoming->Validate(h.ordinal, std::nullopt)) {
			self->Close(EPROTO);
			return;
		}
		FIDL_BSD_TRANSPORT(reinterpret_cast<uintptr_t>(self),
		    reinterpret_cast<uintptr_t>(self->channel_), h.txid,
		    h.ordinal);
		FIDL_BSD_MESSAGE_TOKEN(reinterpret_cast<uintptr_t>(self),
		    h.txid, h.ordinal,
		    channel_message_token(incoming->native()));
		FIDL_BSD_MESSAGE(reinterpret_cast<uintptr_t>(self), h.txid,
		    h.ordinal);
		if (h.ordinal == kFidlOrdinalEpitaph) {
			if (self->role_ != CHANNEL_ROLE_CLIENT || h.txid != 0 ||
			    channel_message_length(incoming->native()) != 24 ||
			    channel_message_fd_count(incoming->native()) != 0) {
				FIDL_BSD_REJECT(reinterpret_cast<uintptr_t>(
						    self),
				    h.txid, h.ordinal, 4);
				self->Close(EPROTO);
				return;
			}
			int32_t status;
			uint32_t padding;
			const auto *data = static_cast<const uint8_t *>(
			    channel_message_data(incoming->native()));
			memcpy(&status, data + 16, 4);
			memcpy(&padding, data + 20, 4);
			if (padding != 0) {
				FIDL_BSD_REJECT(reinterpret_cast<uintptr_t>(
						    self),
				    h.txid, h.ordinal, 4);
				self->Close(EPROTO);
				return;
			}
			FIDL_BSD_EPITAPH(reinterpret_cast<uintptr_t>(self),
			    status);
			self->peer_epitaph_ = status;
			self->Close(EPIPE);
			return;
		}
		if (self->closing_) {
			FIDL_BSD_REJECT(reinterpret_cast<uintptr_t>(self),
			    h.txid, h.ordinal, 5);
			self->Close(EPROTO);
			return;
		}
		// Hold the callback alive if it replaces or clears itself.
		auto handler = h.txid ? self->request_handler_ :
					self->event_handler_;
		if (!handler) {
			FIDL_BSD_REJECT(reinterpret_cast<uintptr_t>(self),
			    h.txid, h.ordinal, 6);
			self->Close(EPROTO);
			return;
		}
		handler(std::move(incoming));
	} catch (const std::bad_alloc &) {
		self->Close(ENOMEM);
	} catch (...) {
		self->Close(ECANCELED);
	}
}
#define FIDL_DISPATCH_RETURN(value) do { \
	int trace_error = (value); \
	FIDL_BSD_DISPATCH_DONE(reinterpret_cast<uintptr_t>(this), trace_error); \
	return trace_error; \
} while (0)
int
Connection::Dispatch()
{
	FIDL_BSD_DISPATCH_START(reinterpret_cast<uintptr_t>(this));
	if (error())
		FIDL_DISPATCH_RETURN(error());
	if (channel_dispatch(channel_) < 0) {
		int e = errno;
		Close(e);
		FIDL_DISPATCH_RETURN(e);
	}
	if (error())
		FIDL_DISPATCH_RETURN(error());
	if (channel_flush(channel_) != 0) {
		int e = errno;
		Close(e);
		FIDL_DISPATCH_RETURN(e);
	}
	FIDL_DISPATCH_RETURN(error());
}
#undef FIDL_DISPATCH_RETURN

int
Connection::Poll(int timeout_ms)
{
	if (error())
		return error();
	if (channel_wait(channel_, channel_wants_write(channel_), timeout_ms) <
	    0) {
		int e = errno;
		Close(e);
		return e;
	}
	return Dispatch();
}
int
Connection::Cancel(uint32_t id)
{
	for (auto *p = active_; p; p = p->next)
		if (p->id == id)
			return channel_request_cancel(p->request) == 0 ? 0 :
									 errno;
	return EALREADY;
}
}
