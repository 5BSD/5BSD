/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_C_WIRE_H
#define FIDL_BSD_C_WIRE_H
// Direct FIDL v2 wire coding for the generated C bindings.
//
// The C ABI's structures are encoded into a connection's reusable packet
// and decoded from the received message without natural-type objects: no
// per-call heap allocation for messages whose decoded views fit the
// on-stack arena.  Encoding and validation follow the natural codec rule
// for rule (sdk/lib/fidl/cpp natural_coding_traits.h, natural_types.h);
// lib/libfidl/tests/c_wire_test.cc checks the two against each other.
#include <fidl/bsd/c_bridge.h>
#include <lib/utf-utils/utf-utils.h>
#include <zircon/fidl.h>

#include <cstring>
#include <memory>
#include <vector>

namespace fidl::bsd::cwire {
inline constexpr uint64_t kAllocPresent = UINT64_MAX;
inline constexpr size_t kDepthMax = FIDL_RECURSION_DEPTH;

// An empty string is valid whatever its pointer: C callers pass NULL with
// size 0 for "", which utfutils_is_valid_utf8() rejects.
inline bool
ValidUtf8(const char *data, size_t size)
{
	return size == 0 || utfutils_is_valid_utf8(data, size);
}

// Writes one message body into an Outgoing packet (offsets from the body).
// The first failure is kept; encoding continues harmlessly after it.
class Encoder {
    public:
	explicit Encoder(Outgoing &out)
	    : out_(out)
	{
	}
	int error() const { return error_; }
	void Fail(int error)
	{
		if (!error_)
			error_ = error;
	}
	size_t Alloc(size_t size)
	{
		size_t offset = out_.RawAlloc(size);
		if (offset == SIZE_MAX) {
			Fail(EMSGSIZE);
			return 0;
		}
		return offset;
	}
	size_t Length() const { return out_.RawLength(); }
	size_t Handles() const { return out_.RawHandleCount(); }
	template <typename T> void Put(size_t offset, T value)
	{
		if (!error_)
			memcpy(out_.RawBody() + offset, &value, sizeof(value));
	}
	void PutBytes(size_t offset, const void *data, size_t size)
	{
		if (!error_ && size)
			memcpy(out_.RawBody() + offset, data, size);
	}
	template <typename T> T Get(size_t offset)
	{
		T value {};
		memcpy(&value, out_.RawBody() + offset, sizeof(value));
		return value;
	}
	void Handle(size_t offset, int fd, uint32_t type, uint32_t rights,
	    bool optional)
	{
		if (error_)
			return;
		if (fd < 0) {
			if (!optional)
				Fail(EINVAL);
			else
				Put<uint32_t>(offset, FIDL_HANDLE_ABSENT);
			return;
		}
		int error = out_.RawHandle(fd, type, rights);
		if (error) {
			Fail(error);
			return;
		}
		Put<uint32_t>(offset, FIDL_HANDLE_PRESENT);
	}
	// A string body after its 16-byte header at offset.
	void String(size_t offset, const char *data, size_t size,
	    size_t limit, size_t depth)
	{
		if (size > limit || (size && !data) || !ValidUtf8(data, size) ||
		    depth + 1 > kDepthMax) {
			Fail(EINVAL);
			return;
		}
		Put<uint64_t>(offset, size);
		Put<uint64_t>(offset + 8, kAllocPresent);
		PutBytes(Alloc(size), data, size);
	}
	// Begin an envelope at offset for a member of inline size; returns
	// where the member's inline part goes.  Finish with EndEnvelope.
	struct Envelope {
		size_t offset, length, handles;
		bool inlined;
	};
	Envelope BeginEnvelope(size_t offset, size_t inline_size)
	{
		Envelope e { offset, Length(), Handles(), inline_size <= 4 };
		return e;
	}
	size_t EnvelopeTarget(const Envelope &e, size_t inline_size)
	{
		return e.inlined ? e.offset : Alloc(inline_size);
	}
	void EndEnvelope(const Envelope &e)
	{
		uint16_t handles = static_cast<uint16_t>(Handles() - e.handles);
		if (e.inlined) {
			Put<uint16_t>(e.offset + 4, handles);
			Put<uint16_t>(e.offset + 6,
			    FIDL_ENVELOPE_FLAGS_INLINING_MASK);
		} else {
			Put<uint32_t>(e.offset,
			    static_cast<uint32_t>(Length() - e.length));
			Put<uint16_t>(e.offset + 4, handles);
			Put<uint16_t>(e.offset + 6, 0);
		}
	}

    private:
	Outgoing &out_;
	int error_ = 0;
};

// Decoded views live in this arena; small messages never touch the heap.
class Arena {
    public:
	Arena() = default;
	Arena(const Arena &) = delete;
	Arena &operator=(const Arena &) = delete;
	void *Allocate(size_t size)
	{
		size = (size + 15) & ~size_t(15);
		if (size <= sizeof(inline_) - used_) {
			void *p = inline_ + used_;
			used_ += size;
			memset(p, 0, size);
			return p;
		}
		auto block = std::make_unique<unsigned char[]>(size);
		void *p = block.get();
		heap_.push_back(std::move(block));
		return p;
	}
	template <typename T> T *New(size_t count)
	{
		if (!count)
			return nullptr;
		if (count > SIZE_MAX / sizeof(T))
			throw std::bad_alloc();
		return static_cast<T *>(Allocate(count * sizeof(T)));
	}

    private:
	alignas(16) unsigned char inline_[2048];
	size_t used_ = 0;
	std::vector<std::unique_ptr<unsigned char[]>> heap_;
};

// Reads one message body; descriptors are taken from the message up front
// (as the natural decoder does) and handed to C slots as fields decode.
// Descriptors left in C slots are closed when the decoder is destroyed;
// a callback keeps one by fidl_bsd_take_fd(), which sets its slot to -1.
class Decoder {
    public:
	Decoder(Arena &arena)
	    : arena_(arena)
	{
	}
	Decoder(const Decoder &) = delete;
	Decoder &operator=(const Decoder &) = delete;
	~Decoder()
	{
		for (size_t i = 0; i < claimed_; ++i)
			if (*claimed_slot_[i] != -1)
				close(claimed_fd_[i]);
		for (size_t i = 0; i < count_; ++i)
			if (fds_[i] >= 0)
				close(fds_[i]);
	}
	// A body with descriptors (fds/metadata may be null when count is 0).
	// The decoder owns the descriptors.  Bodies must be 8-byte aligned;
	// Begin copies a misaligned one into the arena.
	void Begin(const uint8_t *body, size_t length, const int *fds,
	    const uint32_t *types, const uint32_t *rights, size_t count)
	{
		count_ = count;
		for (size_t i = 0; i < count; ++i) {
			fds_[i] = fds[i];
			types_[i] = types ? types[i] : 0;
			rights_[i] = rights ? rights[i] : 0;
		}
		if (reinterpret_cast<uintptr_t>(body) % 8 != 0 && length) {
			auto *copy = static_cast<uint8_t *>(
			    arena_.Allocate(length));
			memcpy(copy, body, length);
			body = copy;
		}
		body_ = body;
		length_ = length;
	}
	// Take the message's descriptors and borrow its body.
	int Begin(Incoming &incoming)
	{
		channel_message *m = incoming.native();
		size_t count = channel_message_fd_count(m);
		size_t length = channel_message_length(m);
		if (count > kMaxDescriptors ||
		    length < sizeof(fidl_message_header_t))
			return EPROTO;
		for (size_t i = 0; i < count; ++i) {
			int fd = channel_message_take_fd(m, i);
			if (fd < 0) {
				for (size_t j = 0; j < i; ++j)
					close(fds_[j]);
				return EPROTO;
			}
			fds_[i] = fd;
			types_[i] = rights_[i] = 0;
			channel_fd_info info;
			if (channel_message_fd_info(m, i, &info) == 0) {
				types_[i] = kKernelReported | info.type;
				rights_[i] = info.rights;
			}
			count_ = i + 1;
		}
		const uint8_t *body = static_cast<const uint8_t *>(
					  channel_message_data(m)) +
		    sizeof(fidl_message_header_t);
		length -= sizeof(fidl_message_header_t);
		if (reinterpret_cast<uintptr_t>(body) % 8 != 0 && length) {
			auto *copy = static_cast<uint8_t *>(
			    arena_.Allocate(length));
			memcpy(copy, body, length);
			body = copy;
		}
		body_ = body;
		length_ = length;
		return 0;
	}
	bool ok() const { return ok_; }
	bool Fail()
	{
		ok_ = false;
		return false;
	}
	Arena &arena() { return arena_; }
	// The natural decoder's Alloc: claim size bytes of out-of-line data,
	// whose padding to 8 must be zero.
	bool Claim(size_t size, size_t *offset)
	{
		if (!ok_)
			return false;
		if (size > UINT32_MAX)
			return Fail();
		size_t end = next_ + size;
		size_t aligned = (end + 7) & ~size_t(7);
		if (aligned > length_)
			return Fail();
		for (size_t i = end; i < aligned; ++i)
			if (body_[i] != 0)
				return Fail();
		*offset = next_;
		next_ = aligned;
		return true;
	}
	template <typename T> T Get(size_t offset) const
	{
		T value;
		memcpy(&value, body_ + offset, sizeof(value));
		return value;
	}
	const uint8_t *Ptr(size_t offset) const { return body_ + offset; }
	size_t Length() const { return next_; }
	size_t Handles() const { return index_; }
	// Decode the descriptor marker at offset into *slot.
	bool Handle(size_t offset, int *slot, uint32_t type, uint32_t rights,
	    bool optional)
	{
		*slot = -1;
		if (!ok_)
			return false;
		uint32_t marker = Get<uint32_t>(offset);
		if (marker == FIDL_HANDLE_ABSENT)
			return optional ? true : Fail();
		if (marker != FIDL_HANDLE_PRESENT || index_ >= count_)
			return Fail();
		int fd = fds_[index_];
		if (CheckReceivedDescriptor(fd, type, rights, types_[index_],
			rights_[index_]))
			return Fail();
		fds_[index_++] = -1;
		claimed_slot_[claimed_] = slot;
		claimed_fd_[claimed_++] = fd;
		*slot = fd;
		return true;
	}
	// Skip count descriptors of an unknown envelope, closing them.
	bool SkipHandles(size_t count)
	{
		if (count > count_ - index_)
			return Fail();
		for (size_t end = index_ + count; index_ < end; ++index_) {
			close(fds_[index_]);
			fds_[index_] = -1;
		}
		return true;
	}
	// A string at offset: its header and body (copied, NUL-terminated).
	bool String(size_t offset, const char **data, size_t *size,
	    bool *present, size_t limit, size_t depth)
	{
		if (!ok_)
			return false;
		uint64_t count = Get<uint64_t>(offset);
		uint64_t marker = Get<uint64_t>(offset + 8);
		if (present) {
			*present = false;
			if (marker == 0) {
				if (count != 0)
					return Fail();
				*data = nullptr;
				*size = 0;
				return true;
			}
		}
		if (depth + 1 > kDepthMax || count > limit ||
		    marker != kAllocPresent)
			return Fail();
		size_t base;
		if (!Claim(count, &base))
			return false;
		const char *bytes = reinterpret_cast<const char *>(body_ +
		    base);
		if (!ValidUtf8(bytes, count))
			return Fail();
		char *copy = static_cast<char *>(arena_.Allocate(count + 1));
		memcpy(copy, bytes, count);
		copy[count] = '\0';
		*data = copy;
		*size = count;
		if (present)
			*present = true;
		return true;
	}
	// A vector header at offset; *base is its body's offset.
	bool VectorHeader(size_t offset, size_t stride, size_t limit,
	    bool *present, size_t depth, size_t *count, size_t *base)
	{
		if (!ok_)
			return false;
		uint64_t n = Get<uint64_t>(offset);
		uint64_t marker = Get<uint64_t>(offset + 8);
		*count = 0;
		if (present) {
			*present = false;
			if (marker == 0) {
				if (n != 0)
					return Fail();
				*base = 0;
				return true;
			}
		}
		if (n > limit || marker != kAllocPresent ||
		    depth + 1 > kDepthMax)
			return Fail();
		size_t bytes;
		if (__builtin_mul_overflow(n, stride, &bytes) ||
		    !Claim(bytes, base))
			return Fail();
		*count = n;
		if (present)
			*present = true;
		return true;
	}
	// The natural decoder's unknown-envelope rule.
	bool UnknownEnvelope(size_t offset, bool required)
	{
		uint32_t bytes = Get<uint32_t>(offset);
		uint16_t handles = Get<uint16_t>(offset + 4);
		uint16_t flags = Get<uint16_t>(offset + 6);
		if (Get<uint64_t>(offset) == 0)
			return required ? Fail() : true;
		if (flags == 0) {
			if (bytes % 8 != 0)
				return Fail();
			size_t ignored;
			if (!Claim(bytes, &ignored))
				return false;
		} else if (flags != FIDL_ENVELOPE_FLAGS_INLINING_MASK)
			return Fail();
		return SkipHandles(handles);
	}
	// Known-member envelope at offset: where its inline part is, and the
	// state EndEnvelope checks the header against.
	struct Envelope {
		size_t offset, length, handles, inline_size;
		bool inlined;
	};
	bool BeginEnvelope(size_t offset, size_t inline_size, Envelope *e,
	    size_t *target)
	{
		e->offset = offset;
		e->inline_size = inline_size;
		e->inlined = inline_size <= 4;
		e->handles = index_;
		uint16_t flags = Get<uint16_t>(offset + 6);
		if (e->inlined) {
			if (flags != FIDL_ENVELOPE_FLAGS_INLINING_MASK)
				return Fail();
			*target = offset;
			e->length = next_;
			return true;
		}
		if (flags != 0)
			return Fail();
		e->length = next_;
		return Claim(inline_size, target);
	}
	bool EndEnvelope(const Envelope &e)
	{
		if (!ok_)
			return false;
		if (index_ != e.handles + Get<uint16_t>(e.offset + 4))
			return Fail();
		if (e.inlined) {
			uint32_t padding = e.inline_size >= 4 ? 0 :
							      ~((1u << (8 * e.inline_size)) - 1);
			if (Get<uint32_t>(e.offset) & padding)
				return Fail();
		} else if (next_ != e.length + Get<uint32_t>(e.offset))
			return Fail();
		return true;
	}
	// Every byte and descriptor must have been consumed.
	bool Finish()
	{
		if (!ok_ || next_ != length_ || index_ != count_)
			return Fail();
		return true;
	}

    private:
	Arena &arena_;
	const uint8_t *body_ = nullptr;
	size_t length_ = 0, next_ = 0, index_ = 0, count_ = 0, claimed_ = 0;
	bool ok_ = true;
	int fds_[kMaxDescriptors];
	uint32_t types_[kMaxDescriptors], rights_[kMaxDescriptors];
	int *claimed_slot_[kMaxDescriptors];
	int claimed_fd_[kMaxDescriptors];
};
}
#endif
