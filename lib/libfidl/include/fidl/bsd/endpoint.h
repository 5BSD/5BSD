/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_ENDPOINT_H
#define FIDL_BSD_ENDPOINT_H
#include <fidl/bsd/descriptor.h>
namespace fidl::bsd {
enum class EndpointRole { Client, Server };
// Compile-time protocol/direction information does not grant authority.
// The native codec verifies the actual attachment is a capability channel.
template <typename Protocol, EndpointRole Role> class Endpoint {
    public:
	using ProtocolType = Protocol;
	static constexpr EndpointRole kRole = Role;
	Endpoint() = default;
	explicit Endpoint(Descriptor descriptor)
	    : descriptor_(std::move(descriptor))
	{
	}
	Endpoint(Endpoint &&) noexcept = default;
	Endpoint &operator=(Endpoint &&) noexcept = default;
	Endpoint(const Endpoint &) = delete;
	Endpoint &operator=(const Endpoint &) = delete;
	int get() const { return descriptor_.get(); }
	explicit operator bool() const { return bool(descriptor_); }
	int release() { return descriptor_.release(); }
	void reset(int fd = -1) { descriptor_.reset(fd); }
	Descriptor take_descriptor() { return Descriptor(release()); }
	Descriptor &descriptor() { return descriptor_; }

    private:
	Descriptor descriptor_;
};
template <typename Protocol>
using ClientEnd = Endpoint<Protocol, EndpointRole::Client>;
template <typename Protocol>
using ServerEnd = Endpoint<Protocol, EndpointRole::Server>;
}
namespace fidl::internal {
template <typename Protocol, ::fidl::bsd::EndpointRole Role,
    typename Constraint>
struct NaturalCodingTraits<::fidl::bsd::Endpoint<Protocol, Role>, Constraint> {
	static constexpr size_t kInlineSize = sizeof(fidl_handle_t);
	static constexpr bool kIsMemcpyCompatible = false;
	using Endpoint = ::fidl::bsd::Endpoint<Protocol, Role>;
	static void Encode(NaturalEncoder *encoder, Endpoint *value,
	    size_t offset, size_t depth)
	{
		NaturalCodingTraits<::fidl::bsd::Descriptor,
		    Constraint>::Encode(encoder, &value->descriptor(), offset,
		    depth);
	}
	static void Decode(NaturalDecoder *decoder, Endpoint *value,
	    size_t offset, size_t depth)
	{
		NaturalCodingTraits<::fidl::bsd::Descriptor,
		    Constraint>::Decode(decoder, &value->descriptor(), offset,
		    depth);
	}
};
}
#endif
