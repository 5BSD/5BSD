/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_RUNTIME_H
#define FIDL_BSD_RUNTIME_H
#include <fidl/bsd/descriptor.h>
#include <fidl/bsd/empty.h>
#include <lib/fidl/cpp/natural_types.h>
#include <lib/fidl/txn_header.h>
extern "C" {
#include <channel.h>
}
#include <array>
#include <bit>
#include <lib/fit/function.h>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace fidl::bsd {
inline constexpr size_t kMaxMessageBytes = 14336;
inline constexpr size_t kMaxDescriptors = 32;
// Message bodies up to this many 8-byte words decode without a heap buffer.
inline constexpr size_t kInlineDecodeWords = 64;
static_assert(std::endian::native == std::endian::little,
    "FIDL currently requires little-endian 5BSD");
struct Transport {
	using HandleMetadata = fidl_channel_handle_metadata_t;
	static const internal::TransportVTable VTable;
};
int ValidateDescriptor(int fd, uint32_t type, uint32_t rights);
// Check a received descriptor against a field's type and rights, using the
// kernel's report when the metadata carries one (as the codec does).
int CheckReceivedDescriptor(int fd, uint32_t type, uint32_t rights,
    uint32_t reported_type, uint32_t reported_rights);
// Incoming marks metadata entries that carry the kernel's descriptor report
// (obj_type: tag | CHANNEL_FD_TYPE_*, rights: CHANNEL_FD_RIGHT* bits).
inline constexpr uint32_t kKernelReported = 0x80000000u;
struct MessageDeleter {
	void operator()(channel_message *m) const { channel_message_free(m); }
};
using Message = std::unique_ptr<channel_message, MessageDeleter>;

// Values are errno codes. Decode errors are EPROTO; encode constraints EINVAL.
template <typename T> using Result = fit::result<int, T>;

enum class Openness { Closed, Ajar, Open };

class Outgoing {
    public:
	template <typename T>
	static Result<std::unique_ptr<Outgoing>> Encode(T value, uint32_t txid,
	    uint64_t ordinal, bool flexible = false)
	{
		try {
			auto packet = std::make_unique<Outgoing>();
			int error = packet->EncodeInto(std::move(value), txid,
			    ordinal, flexible);
			if (error)
				return fit::error(error);
			return fit::ok(std::move(packet));
		} catch (const std::bad_alloc &) {
			return fit::error(ENOMEM);
		}
	}
	// Encode into this packet, replacing any previous contents but keeping
	// buffer capacity; a connection reuses one packet for every send.
	template <typename T>
	int EncodeInto(T value, uint32_t txid, uint64_t ordinal,
	    bool flexible = false)
	{
		try {
			Reset();
			if constexpr (std::is_same_v<T, Empty>) {
				return PrepareEmpty(txid, ordinal, flexible);
			} else {
				auto encoded =
				    internal::EncodeWithTransport<Transport>(
					std::move(value));
				auto &message = encoded.message();
				if (!message.ok())
					return message.status() ==
						ZX_ERR_NO_MEMORY ?
					    ENOMEM :
					    EINVAL;
				return Prepare(message, txid, ordinal, flexible);
			}
		} catch (const std::bad_alloc &) {
			Reset();
			return ENOMEM;
		}
	}
	// Close attached descriptors and forget the payload; keep capacity.
	void Reset()
	{
		bytes_.clear();
		fds_.clear();
		specs_.clear();
		owners_.clear();
	}
	// The packet keeps its descriptors; the kernel re-checks each
	// descriptor's type and rights and narrows the delivered copy.
	channel_outgoing view() const
	{
		return { sizeof(channel_outgoing), bytes_.data(), bytes_.size(),
			fds_.data(), fds_.size(),
			specs_.empty() ? nullptr : specs_.data(), 0 };
	}
	// For one send that moves the descriptors: on success call Sent(),
	// on failure they still belong to this packet.  lock delivers them
	// with close-on-exec and close-on-fork locked.
	channel_outgoing MoveView(bool lock) const
	{
		auto result = view();
		result.flags = CHANNEL_SEND_MOVE |
		    (lock ? CHANNEL_SEND_LOCK_INHERIT : 0);
		return result;
	}
	void Sent()
	{
		for (auto &owner : owners_)
			(void)owner.release();
		Reset();
	}
	// Leave descriptor type and rights checks to the send system call
	// (a connection's own packet); standalone packets check on encode.
	void DeferDescriptorChecks() { defer_checks_ = true; }
	// Direct wire encoding, used by the generated C bindings
	// (<fidl/bsd/c_wire.h>): the caller writes the body in place, with
	// no natural-type objects.  Offsets are relative to the body; RawBody()
	// moves when RawAlloc() grows the packet.
	int RawStart(uint32_t txid, uint64_t ordinal, bool flexible);
	// Append size bytes, zeroed and padded to 8; SIZE_MAX if the message
	// would exceed the transport limit.
	size_t RawAlloc(size_t size);
	uint8_t *RawBody()
	{
		return bytes_.data() + sizeof(fidl_message_header_t);
	}
	size_t RawLength() const
	{
		return bytes_.size() - sizeof(fidl_message_header_t);
	}
	size_t RawHandleCount() const { return fds_.size(); }
	void RawSetTxid(uint32_t txid)
	{
		memcpy(bytes_.data(), &txid, sizeof(txid));
	}
	// Attach a private duplicate of a borrowed descriptor with the wire
	// type and rights (C callers lend descriptors).
	int RawHandle(int fd, uint32_t type, uint32_t rights);

    private:
	int Prepare(fidl::OutgoingMessage &, uint32_t, uint64_t);
	int Prepare(fidl::OutgoingMessage &, uint32_t, uint64_t, bool);
	int PrepareEmpty(uint32_t, uint64_t);
	int PrepareEmpty(uint32_t, uint64_t, bool);
	std::vector<uint8_t> bytes_;
	std::vector<int> fds_;
	std::vector<channel_fd_spec> specs_;
	std::vector<Descriptor> owners_;
	bool defer_checks_ = false;
};

// Keeps kernel metadata and native reply token in the original message.
class Incoming {
    public:
	explicit Incoming(Message message)
	    : message_(std::move(message))
	{
	}
	int Validate(uint64_t ordinal, std::optional<uint32_t> txid) const;
	fidl_message_header_t header() const;
	channel_message *native() const { return message_.get(); }
	bool replied() const { return replied_; }
	template <typename T> Result<T> Decode()
	{
		try {
			if (decoded_ ||
			    Validate(header().ordinal, std::nullopt))
				return fit::error(EPROTO);
			decoded_ = true;
			if constexpr (std::is_same_v<T, Empty>) {
				if (channel_message_length(native()) !=
					sizeof(fidl_message_header_t) ||
				    channel_message_fd_count(native()) != 0)
					return fit::error(EPROTO);
				return fit::ok(Empty {});
			} else {
				const size_t length = channel_message_length(
							  native()) -
				    sizeof(fidl_message_header_t);
				// Allocate before taking descriptors so
				// allocation failure cannot leak them.  The
				// codec needs 8-byte alignment; small bodies
				// use inline storage (decoded values own copies).
				uint64_t inline_storage[kInlineDecodeWords];
				std::unique_ptr<uint64_t[]> heap_storage;
				uint64_t *storage = inline_storage;
				if (length > sizeof(inline_storage)) {
					heap_storage =
					    std::make_unique_for_overwrite<
						uint64_t[]>((length + 7) / 8);
					storage = heap_storage.get();
				}
				if (length)
					memcpy(storage,
					    static_cast<const uint8_t *>(
						channel_message_data(
						    native())) +
						sizeof(fidl_message_header_t),
					    length);
				size_t count = channel_message_fd_count(
				    native());
				if (count > slots_.size())
					return fit::error(EPROTO);
				for (size_t i = 0; i < count; ++i) {
					int fd = channel_message_take_fd(
					    native(), i);
					if (fd < 0) {
						for (size_t j = 0; j < i; ++j)
							close(static_cast<int>(
							    slots_[j] - 1));
						return fit::error(EPROTO);
					}
					slots_[i] = static_cast<uint32_t>(fd) +
					    1;
					channel_fd_info info;
					metadata_[i] = {};
					if (channel_message_fd_info(native(), i,
						&info) == 0)
						metadata_[i] = {
							kKernelReported |
							    info.type,
							info.rights
						};
				}
				auto message =
				    fidl::EncodedMessage::Create<Transport>(
					{ reinterpret_cast<uint8_t *>(storage),
					    length },
					slots_.data(), metadata_.data(), count);
				auto result = fidl::StandaloneDecode<T>(
				    std::move(message),
				    internal::WireFormatMetadataForVersion(
					internal::WireFormatVersion::kV2));
				if (result.is_error())
					return fit::error(EPROTO);
				return fit::ok(std::move(result.value()));
			}
		} catch (const std::bad_alloc &) {
			return fit::error(ENOMEM);
		}
	}

    private:
	friend class Connection;
	std::shared_ptr<const unsigned char> origin_;
	bool replied_ = false;
	Message message_;
	bool decoded_ = false;
	std::array<fidl_handle_t, kMaxDescriptors> slots_ {};
	std::array<Transport::HandleMetadata, kMaxDescriptors> metadata_ {};
};

// One dispatch thread. References passed to callbacks last only for that
// callback. Deleting a Connection from one of its callbacks is not supported.
class Connection {
    public:
	// A completion receives the reply (null on error) for this call only.
	// Inline storage: issuing a call never allocates for its completion.
	static constexpr size_t kCompletionInlineBytes = 64;
	using Completion = fit::inline_function<void(int, Incoming *),
	    kCompletionInlineBytes>;
	using Handler = std::function<void(std::unique_ptr<Incoming>)>;
	static Result<std::unique_ptr<Connection>> Create(int fd,
	    channel_role role, const channel_options *options = nullptr);
	~Connection();
	Connection(const Connection &) = delete;
	Connection &operator=(const Connection &) = delete;
	int fd() const { return channel_fd(channel_); }
	int error() const
	{
		if (error_)
			return error_;
		return channel_error(channel_) == 0 ? 0 : errno;
	}
	bool wants_write() const
	{
		return channel_ && channel_wants_write(channel_) == 1;
	}
	int Poll(int timeout_ms);
	int Dispatch();
	int Cancel(uint32_t txid);
	void Close(int error = ECANCELED);
	// Begin server shutdown. Keep polling until the peer closes, or impose
	// a caller-selected deadline then Close(). A successful send is not
	// delivery.
	int Shutdown(zx_status_t epitaph);
	std::optional<zx_status_t> peer_epitaph() const
	{
		return peer_epitaph_;
	}
	void SetRequestHandler(Handler handler)
	{
		request_handler_ = std::move(handler);
	}
	void SetEventHandler(Handler handler)
	{
		event_handler_ = std::move(handler);
	}
	void EnsureEventHandler(Handler handler)
	{
		if (!event_handler_)
			event_handler_ = std::move(handler);
	}
	bool HasEventHandler() const { return bool(event_handler_); }
	// Applies unknown-interaction policy and sends a framework-error reply
	// for an accepted unknown two-way call. The caller owns payload
	// cleanup.
	int HandleUnknown(Incoming &, Openness);
	// Deliver every sent descriptor with close-on-exec and close-on-fork
	// locked (the C bindings lend private duplicates).
	void LockSentDescriptorInheritance() { lock_inherit_ = true; }
	// Deliver sent descriptors with their own close-on-exec/close-on-fork
	// state (for providers that harden what they hand out themselves).
	void PreserveSentDescriptorInheritance() { lock_inherit_ = false; }
	template <typename Req, typename Resp>
	Result<uint32_t> Call(uint64_t ordinal, Req value,
	    std::function<void(Result<Resp>)> callback, bool flexible = false)
	{
		if (!callback)
			return fit::error(EINVAL);
		if (role_ != CHANNEL_ROLE_CLIENT || error())
			return fit::error(error() ? error() : EINVAL);
		try {
			auto id = AllocateId();
			if (!id)
				return fit::error(EOVERFLOW);
			int err = scratch_.EncodeInto(std::move(value), id,
			    ordinal, flexible);
			if (err)
				return fit::error(err);
			err = SendRequest(id, ordinal, scratch_,
			    [this, callback = std::move(callback)](int error,
				Incoming *incoming) mutable {
				    if (error) {
					    callback(fit::error(error));
					    return;
				    }
				    auto result = [&]() -> Result<Resp> {
					    try {
						    return incoming
							->Decode<Resp>();
					    } catch (const std::bad_alloc &) {
						    return fit::error(ENOMEM);
					    }
				    }();
				    if (result.is_error())
					    Close(result.error_value());
				    callback(std::move(result));
			    });
			scratch_.Reset();
			if (err)
				return fit::error(err);
			return fit::ok(id);
		} catch (const std::bad_alloc &) {
			return fit::error(ENOMEM);
		}
	}
	// The same operations with a body written in place by encode(Outgoing&)
	// (the generated C bindings).  encode returns 0 or an errno value.
	template <typename F>
	Result<uint32_t> CallRaw(uint64_t ordinal, bool flexible, F &&encode,
	    Completion completion)
	{
		try {
			// Argument errors come first, as when the C bindings
			// converted to natural types before calling.
			int err = scratch_.RawStart(0, ordinal, flexible);
			if (!err)
				err = encode(scratch_);
			if (!err && (role_ != CHANNEL_ROLE_CLIENT || error()))
				err = error() ? error() : EINVAL;
			uint32_t id = 0;
			if (!err && !(id = AllocateId()))
				err = EOVERFLOW;
			if (!err) {
				scratch_.RawSetTxid(id);
				err = SendRequest(id, ordinal, scratch_,
				    std::move(completion));
			}
			scratch_.Reset();
			if (err)
				return fit::error(err);
			return fit::ok(id);
		} catch (const std::bad_alloc &) {
			scratch_.Reset();
			return fit::error(ENOMEM);
		}
	}
	template <typename F>
	int SendRaw(uint64_t ordinal, bool flexible, F &&encode)
	{
		if (error())
			return error();
		if (closing_)
			return ESHUTDOWN;
		int err = scratch_.RawStart(0, ordinal, flexible);
		if (!err)
			err = encode(scratch_);
		if (!err) {
			auto view = scratch_.MoveView(lock_inherit_);
			err = channel_send_event(channel_, &view) == 0 ? 0 :
									 errno;
			if (!err)
				scratch_.Sent();
		}
		scratch_.Reset();
		return err;
	}
	template <typename F>
	int ReplyRaw(Incoming &request, bool flexible, F &&encode)
	{
		if (role_ != CHANNEL_ROLE_PROVIDER || error())
			return error() ? error() : EINVAL;
		if (closing_)
			return ESHUTDOWN;
		if (request.origin_ != identity_)
			return EINVAL;
		if (request.replied_)
			return EALREADY;
		auto h = request.header();
		if (request.Validate(h.ordinal, h.txid) || h.txid == 0)
			return EPROTO;
		int err = scratch_.RawStart(h.txid, h.ordinal, flexible);
		if (!err)
			err = encode(scratch_);
		if (!err) {
			auto view = scratch_.MoveView(lock_inherit_);
			err = channel_send_reply(request.native(), &view) == 0 ?
			    0 :
			    errno;
			if (!err)
				scratch_.Sent();
		}
		scratch_.Reset();
		if (err)
			return err;
		request.replied_ = true;
		return 0;
	}
	template <typename T>
	int Send(uint64_t ordinal, T value, bool flexible = false)
	{
		if (error())
			return error();
		if (closing_)
			return ESHUTDOWN;
		int err = scratch_.EncodeInto(std::move(value), 0, ordinal,
		    flexible);
		if (err)
			return err;
		auto view = scratch_.MoveView(lock_inherit_);
		err = channel_send_event(channel_, &view) == 0 ? 0 : errno;
		if (!err)
			scratch_.Sent();
		scratch_.Reset();
		return err;
	}
	template <typename T>
	int Reply(Incoming &request, T value, bool flexible = false)
	{
		if (role_ != CHANNEL_ROLE_PROVIDER || error())
			return error() ? error() : EINVAL;
		if (closing_)
			return ESHUTDOWN;
		if (request.origin_ != identity_)
			return EINVAL;
		if (request.replied_)
			return EALREADY;
		auto h = request.header();
		if (request.Validate(h.ordinal, h.txid) || h.txid == 0)
			return EPROTO;
		int err = scratch_.EncodeInto(std::move(value), h.txid,
		    h.ordinal, flexible);
		if (err)
			return err;
		auto view = scratch_.MoveView(lock_inherit_);
		err = channel_send_reply(request.native(), &view) == 0 ? 0 :
									 errno;
		if (!err)
			scratch_.Sent();
		scratch_.Reset();
		if (err)
			return err;
		request.replied_ = true;
		return 0;
	}

    private:
	friend struct ConnectionTestPeer;
	// Outstanding calls form an intrusive list; completed records are
	// recycled so steady-state calls do not allocate bookkeeping.
	struct Pending {
		Connection *owner = nullptr;
		uint32_t id = 0;
		uint64_t ordinal = 0;
		channel_request *request = nullptr;
		Completion completion;
		Pending *prev = nullptr, *next = nullptr;
	};
	static constexpr size_t kPendingPoolLimit = 64;
	std::unique_ptr<Pending> TakePending();
	void RecyclePending(std::unique_ptr<Pending>);
	void Unlink(Pending *);
	Connection(channel *channel, channel_role role)
	    : channel_(channel)
	    , role_(role)
	{
		scratch_.DeferDescriptorChecks();
	}
	uint32_t AllocateId();
	int SendRequest(uint32_t, uint64_t, Outgoing &, Completion);
	static void OnReply(channel_request *, channel_message *, int, void *);
	static void OnMessage(channel *, channel_message *, void *);
	// An outstanding request retains this identity, preventing address
	// reuse from making a request belong to a later connection.
	std::shared_ptr<const unsigned char> identity_ =
	    std::make_shared<const unsigned char>(0);
	channel *channel_;
	channel_role role_;
	int error_ = 0;
	bool closing_ = false;
	std::optional<zx_status_t> peer_epitaph_;
	uint32_t next_id_ = 1;
	Pending *active_ = nullptr;
	std::vector<std::unique_ptr<Pending>> free_pending_;
	// Single dispatch thread: one encode is complete and sent (copied by
	// libchannel or the kernel) before any other send can start.
	Outgoing scratch_;
	Handler request_handler_, event_handler_;
	bool lock_inherit_ = false;
};
}
#endif
