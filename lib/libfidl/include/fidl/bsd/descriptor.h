/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_DESCRIPTOR_H
#define FIDL_BSD_DESCRIPTOR_H
#include <lib/fidl/cpp/natural_coding_traits.h>
#include <unistd.h>
#include <utility>

namespace fidl::bsd {
// The internal codec slot is fd + 1; zero is absent. Never sent on the wire.
class Descriptor final {
    public:
	Descriptor() = default;
	explicit Descriptor(int fd)
	    : fd_(fd)
	{
	}
	~Descriptor() { reset(); }
	Descriptor(const Descriptor &) = delete;
	Descriptor &operator=(const Descriptor &) = delete;
	Descriptor(Descriptor &&other) noexcept
	    : fd_(other.release())
	{
	}
	Descriptor &operator=(Descriptor &&other) noexcept
	{
		if (this != &other)
			reset(other.release());
		return *this;
	}
	int get() const { return fd_; }
	explicit operator bool() const { return fd_ >= 0; }
	int release() { return std::exchange(fd_, -1); }
	void reset(int fd = -1)
	{
		if (fd_ >= 0)
			close(fd_);
		fd_ = fd;
	}

    private:
	int fd_ = -1;
};
}
namespace fidl::internal {
template <typename Constraint>
struct NaturalCodingTraits<::fidl::bsd::Descriptor, Constraint> {
	static constexpr size_t kInlineSize = sizeof(fidl_handle_t);
	static constexpr bool kIsMemcpyCompatible = false;
	static void Encode(NaturalEncoder *encoder,
	    ::fidl::bsd::Descriptor *value, size_t offset, size_t)
	{
		int fd = value->release();
		encoder->EncodeHandle(fd < 0 ? 0 :
					       static_cast<uint32_t>(fd) + 1,
		    { .obj_type = Constraint::obj_type,
			.rights = Constraint::rights },
		    offset, Constraint::is_optional);
	}
	static void Decode(NaturalDecoder *decoder,
	    ::fidl::bsd::Descriptor *value, size_t offset, size_t)
	{
		fidl_handle_t slot = 0;
		decoder->DecodeHandle(&slot,
		    { .obj_type = Constraint::obj_type,
			.rights = Constraint::rights },
		    offset, Constraint::is_optional);
		value->reset(slot == 0 ? -1 : static_cast<int>(slot - 1));
	}
};
}
#endif
