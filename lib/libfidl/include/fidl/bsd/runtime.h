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
#include <algorithm>
#include <array>
#include <bit>
#include <lib/fit/function.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <new>
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

// Bounded object slab for one dispatch thread.  Blocks come from chunks
// allocated on demand, never beyond limit objects, and are reused through a
// free list, so steady-state traffic allocates nothing and the slab cannot
// grow past the bound it was sized from.  Take() returns nullptr at the
// limit (the caller then uses the heap exactly as before the slab existed)
// and throws std::bad_alloc when a chunk cannot be allocated.
template <typename T> class Slab {
    public:
	static constexpr size_t kChunk = 8;
	explicit Slab(size_t limit)
	    : limit_(limit)
	{
	}
	Slab(const Slab &) = delete;
	Slab &operator=(const Slab &) = delete;
	void *Take()
	{
		if (free_) {
			Block *block = free_;
			free_ = block->next;
			++live_;
			return block;
		}
		if (allocated_ >= limit_)
			return nullptr;
		size_t count = std::min(kChunk, limit_ - allocated_);
		chunks_.reserve(chunks_.size() + 1);
		auto chunk = std::make_unique<Block[]>(count);
		for (size_t i = 1; i < count; ++i) {
			chunk[i].next = free_;
			free_ = &chunk[i];
		}
		Block *block = &chunk[0];
		chunks_.push_back(std::move(chunk));
		allocated_ += count;
		++live_;
		return block;
	}
	void Put(void *storage) noexcept
	{
		auto *block = static_cast<Block *>(storage);
		block->next = free_;
		free_ = block;
		--live_;
	}
	size_t limit() const { return limit_; }
	// Objects currently taken, and blocks ever carved out of chunks.
	size_t live() const { return live_; }
	size_t allocated() const { return allocated_; }

    private:
	union Block {
		Block *next;
		alignas(T) std::byte storage[sizeof(T)];
	};
	static_assert(alignof(T) <= __STDCPP_DEFAULT_NEW_ALIGNMENT__);
	size_t limit_, allocated_ = 0, live_ = 0;
	Block *free_ = nullptr;
	std::vector<std::unique_ptr<Block[]>> chunks_;
};

// Values are errno codes. Decode errors are EPROTO; encode constraints EINVAL.
template <typename T> using Result = fit::result<int, T>;

enum class Openness { Closed, Ajar, Open };

class Outgoing {
    public:
	Outgoing() = default;
	~Outgoing() { Release(); }
	Outgoing(const Outgoing &) = delete;
	Outgoing &operator=(const Outgoing &) = delete;
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
	// Close attached descriptors and forget the payload; keep capacity
	// (and a reserved send buffer, see Attach).
	void Reset()
	{
		size_ = 0;
		bytes_.clear();
		fds_.clear();
		specs_.clear();
		owners_.clear();
	}
	// The packet keeps its descriptors; the kernel re-checks each
	// descriptor's type and rights and narrows the delivered copy.
	channel_outgoing view() const
	{
		return { sizeof(channel_outgoing), Data(), Size(), fds_.data(),
			fds_.size(), specs_.empty() ? nullptr : specs_.data(),
			0 };
	}
	// Encode into a send buffer the connection reserved from libchannel
	// (channel_outgoing_reserve): the body is written where the kernel
	// reads it and committed without a copy.  A body the buffer cannot
	// hold spills into the packet's own storage and the reservation is
	// returned; buffer() is then null and the packet is sent as before.
	void Attach(channel_outgoing_buffer *buffer)
	{
		Reset();
		Release();
		buffer_ = buffer;
		external_ = static_cast<uint8_t *>(
		    channel_outgoing_buffer_data(buffer));
		capacity_ = channel_outgoing_buffer_capacity(buffer);
	}
	channel_outgoing_buffer *buffer() const { return buffer_; }
	// A commit consumed the reservation: the body now belongs to libchannel.
	void Committed()
	{
		buffer_ = nullptr;
		external_ = nullptr;
		capacity_ = size_ = 0;
	}
	// Return a reservation the packet still holds (nothing was attached
	// to it; valid after the channel is gone).
	void Release()
	{
		if (buffer_)
			channel_outgoing_abort(buffer_);
		Committed();
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
	// Hand the attached descriptors to a send whose completion may run
	// before the packet is reset (Connection::CallSync): the payload a
	// view points at stays, the descriptors stop being the packet's.
	void ReleaseDescriptors()
	{
		for (auto &owner : owners_)
			(void)owner.release();
		owners_.clear();
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
	uint8_t *RawBody() { return Data() + sizeof(fidl_message_header_t); }
	size_t RawLength() const
	{
		return Size() - sizeof(fidl_message_header_t);
	}
	size_t RawHandleCount() const { return fds_.size(); }
	void RawSetTxid(uint32_t txid)
	{
		memcpy(Data(), &txid, sizeof(txid));
	}
	// Attach a private duplicate of a borrowed descriptor with the wire
	// type and rights (C callers lend descriptors).
	int RawHandle(int fd, uint32_t type, uint32_t rights);
	// Attach an owned descriptor: on success the packet owns it (the send
	// moves it and closes the original); on failure it stays the caller's.
	int RawHandleMove(int fd, uint32_t type, uint32_t rights);

    private:
	int Prepare(fidl::OutgoingMessage &, uint32_t, uint64_t);
	int Prepare(fidl::OutgoingMessage &, uint32_t, uint64_t, bool);
	int PrepareEmpty(uint32_t, uint64_t);
	int PrepareEmpty(uint32_t, uint64_t, bool);
	// The payload: the reserved buffer while one is attached and large
	// enough, else the packet's own vector.
	uint8_t *Data() { return external_ ? external_ : bytes_.data(); }
	const uint8_t *Data() const
	{
		return external_ ? external_ : bytes_.data();
	}
	size_t Size() const { return external_ ? size_ : bytes_.size(); }
	// Grow or shrink the payload to size bytes, zero-filling new ones.
	void Resize(size_t size)
	{
		if (external_) {
			if (size <= capacity_) {
				if (size > size_)
					memset(external_ + size_, 0,
					    size - size_);
				size_ = size;
				return;
			}
			// Spill: keep what was encoded, give the buffer back.
			bytes_.assign(external_, external_ + size_);
			Release();
		}
		bytes_.resize(size);
	}
	std::vector<uint8_t> bytes_;
	channel_outgoing_buffer *buffer_ = nullptr;
	uint8_t *external_ = nullptr;
	size_t capacity_ = 0, size_ = 0;
	std::vector<int> fds_;
	std::vector<channel_fd_spec> specs_;
	std::vector<Descriptor> owners_;
	bool defer_checks_ = false;
};

class Connection;
struct ConnectionIdentity;
// Keeps kernel metadata and native reply token in the original message.
class Incoming {
    public:
	explicit Incoming(Message message)
	    : message_(std::move(message))
	{
	}
	// A connection hands out Incoming objects from its slab; delete
	// returns them there (the retained identity keeps the slab alive
	// past the connection) or to the heap when they came from plain new.
	static void operator delete(Incoming *, std::destroying_delete_t);
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
	std::shared_ptr<const ConnectionIdentity> origin_;
	Slab<Incoming> *slab_ = nullptr;
	bool replied_ = false;
	Message message_;
	bool decoded_ = false;
	std::array<fidl_handle_t, kMaxDescriptors> slots_ {};
	std::array<Transport::HandleMetadata, kMaxDescriptors> metadata_ {};
};
// Retained by every outstanding request and received message of a
// connection: an address alone cannot make a request belong to a later
// connection, and received messages can return to the slab after it is gone.
struct ConnectionIdentity {
	explicit ConnectionIdentity(size_t limit)
	    : incoming(limit)
	{
	}
	mutable Slab<Incoming> incoming;
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
	// One synchronous call (fidl_bsd_connection_call): issue() makes one
	// two-way call on this connection.  When no call is outstanding and no
	// output is queued, request and reply go through channel_call_request(3)
	// in one system call and the call's completion runs before issue()
	// returns; otherwise the call is sent as usual and this polls until it
	// completes.  Returns issue()'s error, the completion's error (a
	// timeout cancels only this call), or EINVAL when issue() made no call.
	// The completion must not destroy the connection, as for any callback.
	int CallSync(int timeout_ms, int (*issue)(void *), void *context);
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
			ReserveScratch();
			int err = scratch_.EncodeInto(std::move(value), id,
			    ordinal, flexible);
			if (err) {
				FinishScratch();
				return fit::error(err);
			}
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
			FinishScratch();
			if (err)
				return fit::error(err);
			return fit::ok(id);
		} catch (const std::bad_alloc &) {
			// The packet may still hold the moved descriptors.
			FinishScratch();
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
			ReserveScratch();
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
			FinishScratch();
			if (err)
				return fit::error(err);
			return fit::ok(id);
		} catch (const std::bad_alloc &) {
			FinishScratch();
			return fit::error(ENOMEM);
		}
	}
	// As in CallRaw, the body is encoded before the connection state is
	// checked: every descriptor a C caller handed over is then either
	// attached to the packet (closed by Reset on failure) or closed by the
	// encoder, whatever the outcome.
	template <typename F>
	int SendRaw(uint64_t ordinal, bool flexible, F &&encode)
	{
		ReserveScratch();
		int err = scratch_.RawStart(0, ordinal, flexible);
		if (!err)
			err = encode(scratch_);
		if (!err && error())
			err = error();
		if (!err && closing_)
			err = ESHUTDOWN;
		if (!err)
			err = SendEvent(scratch_);
		FinishScratch();
		return err;
	}
	// ordinal, when nonzero, is the method the reply must answer.
	template <typename F>
	int ReplyRaw(Incoming &request, bool flexible, F &&encode,
	    uint64_t ordinal = 0)
	{
		auto h = request.header();
		// A header the validation below rejects still gets a packet
		// to encode into (the txid and ordinal are then irrelevant).
		ReserveScratch();
		int err = scratch_.RawStart(h.txid ? h.txid : 1,
		    h.ordinal && h.ordinal != kFidlOrdinalEpitaph ? h.ordinal :
								     1,
		    flexible);
		if (!err)
			err = encode(scratch_);
		if (!err && (role_ != CHANNEL_ROLE_PROVIDER || error()))
			err = error() ? error() : EINVAL;
		if (!err && closing_)
			err = ESHUTDOWN;
		if (!err && request.origin_ != identity_)
			err = EINVAL;
		if (!err && request.replied_)
			err = EALREADY;
		if (!err &&
		    ((ordinal && h.ordinal != ordinal) ||
			request.Validate(h.ordinal, h.txid) || h.txid == 0))
			err = EPROTO;
		if (!err)
			err = SendReply(request, scratch_);
		FinishScratch();
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
		ReserveScratch();
		int err = scratch_.EncodeInto(std::move(value), 0, ordinal,
		    flexible);
		if (!err)
			err = SendEvent(scratch_);
		FinishScratch();
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
		ReserveScratch();
		int err = scratch_.EncodeInto(std::move(value), h.txid,
		    h.ordinal, flexible);
		if (!err)
			err = SendReply(request, scratch_);
		FinishScratch();
		if (err)
			return err;
		request.replied_ = true;
		return 0;
	}

    private:
	friend struct ConnectionTestPeer;
	// Outstanding calls form an intrusive list; their records come from
	// a slab bounded by the pending-request limit, so steady-state calls
	// do not allocate bookkeeping and the slab cannot outgrow the queue.
	struct Pending {
		Connection *owner = nullptr;
		uint32_t id = 0;
		uint64_t ordinal = 0;
		channel_request *request = nullptr;
		Completion completion;
		Pending *prev = nullptr, *next = nullptr;
		bool pooled = false;
		bool sync = false;	// the CallSync() call in progress
		static void operator delete(Pending *, std::destroying_delete_t);
	};
	std::unique_ptr<Pending> TakePending();
	void Unlink(Pending *);
	std::unique_ptr<Incoming> NewIncoming(Message);
	Connection(channel *channel, channel_role role, size_t limit)
	    : identity_(std::make_shared<const ConnectionIdentity>(limit))
	    , channel_(channel)
	    , role_(role)
	    , pending_(limit)
	{
		scratch_.DeferDescriptorChecks();
	}
	uint32_t AllocateId();
	// Sends encode into a buffer reserved from libchannel so the body is
	// committed without a copy (Outgoing::Attach).  libchannel recycles
	// one released block of up to 4 KiB per channel, so reservations of
	// that size never allocate at steady state; a larger body spills
	// into the packet's own storage and is sent as before.
	static constexpr size_t kReserveBytes = 4096;
	void ReserveScratch();
	// After a send attempt: a reservation the send did not consume is
	// returned and the packet reset (closing descriptors it still owns).
	void FinishScratch()
	{
		scratch_.Release();
		scratch_.Reset();
	}
	int SendEvent(Outgoing &);
	int SendReply(Incoming &, Outgoing &);
	int SendRequest(uint32_t, uint64_t, Outgoing &, Completion);
	static void OnReply(channel_request *, channel_message *, int, void *);
	static void OnMessage(channel *, channel_message *, void *);
	// Retained by every outstanding request and received message (see
	// ConnectionIdentity); it also holds the Incoming slab.
	std::shared_ptr<const ConnectionIdentity> identity_;
	channel *channel_;
	channel_role role_;
	int error_ = 0;
	bool closing_ = false;
	std::optional<zx_status_t> peer_epitaph_;
	uint32_t next_id_ = 1;
	Pending *active_ = nullptr;
	Slab<Pending> pending_;
	// Single dispatch thread: one encode is complete and sent (copied by
	// libchannel or the kernel) before any other send can start.
	Outgoing scratch_;
	Handler request_handler_, event_handler_;
	bool lock_inherit_ = false;
	// CallSync() state: the window the next SendRequest consumes, the id
	// it issued, and that call's completion.
	int sync_timeout_ms_ = -1;
	uint32_t sync_id_ = 0;
	bool sync_done_ = false;
	int sync_result_ = 0;
};
}
#endif
