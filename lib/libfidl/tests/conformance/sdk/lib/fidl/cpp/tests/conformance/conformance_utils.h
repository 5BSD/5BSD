/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * 5BSD replacement for upstream conformance_utils.h. The cases run through
 * the same natural codec entry points as fidl::bsd::Outgoing::Encode and
 * fidl::bsd::Incoming::Decode, using the native descriptor transport.
 * Zircon handle cases are compiled out by the generator (__Fuchsia__).
 */
#ifndef FIDL_BSD_CONFORMANCE_UTILS_H
#define FIDL_BSD_CONFORMANCE_UTILS_H
#include <fidl/bsd/runtime.h>
#include <zxtest/zxtest.h>

#include <cstring>
#include <vector>

namespace conformance_utils {

inline void
CheckVersion(fidl::internal::WireFormatVersion version)
{
	ASSERT_EQ(version, fidl::internal::WireFormatVersion::kV2);
}

template <typename FidlType>
void
EncodeSuccess(fidl::internal::WireFormatVersion version, FidlType &obj,
    const std::vector<uint8_t> &expected_bytes,
    const std::vector<zx_handle_disposition_t> expected_handles, bool)
{
	CheckVersion(version);
	auto encoded = fidl::internal::EncodeWithTransport<fidl::bsd::Transport>(
	    std::move(obj));
	auto &message = encoded.message();
	ASSERT_TRUE(message.ok()) << message.error().FormatDescription();
	auto bytes = message.CopyBytes();
	ASSERT_EQ(std::vector<uint8_t>(bytes.begin(), bytes.end()),
	    expected_bytes);
	ASSERT_EQ(message.handle_actual(), expected_handles.size());
}

template <typename FidlType>
fit::result<fidl::Error, FidlType>
Decode(fidl::internal::WireFormatVersion version, std::vector<uint8_t> &bytes)
{
	// Incoming::Decode copies payloads into 8-byte aligned storage.
	std::vector<uint64_t> storage((bytes.size() + 7) / 8);
	if (!bytes.empty())
		memcpy(storage.data(), bytes.data(), bytes.size());
	auto message = fidl::EncodedMessage::Create<fidl::bsd::Transport>(
	    { reinterpret_cast<uint8_t *>(storage.data()), bytes.size() },
	    nullptr, nullptr, 0);
	return fidl::StandaloneDecode<FidlType>(std::move(message),
	    fidl::internal::WireFormatMetadataForVersion(version));
}

template <typename FidlType, typename EqualityCheck>
void
DecodeSuccess(fidl::internal::WireFormatVersion version,
    std::vector<uint8_t> &bytes, const std::vector<zx_handle_info_t> handles,
    EqualityCheck equality_check)
{
	CheckVersion(version);
	ASSERT_TRUE(handles.empty());
	auto result = Decode<FidlType>(version, bytes);
	ASSERT_TRUE(result.is_ok()) << result.error_value().FormatDescription();
	equality_check(result.value());
}

template <typename FidlType>
void
EncodeFailure(fidl::internal::WireFormatVersion version, FidlType &obj)
{
	CheckVersion(version);
	auto encoded = fidl::internal::EncodeWithTransport<fidl::bsd::Transport>(
	    std::move(obj));
	ASSERT_FALSE(encoded.message().ok());
}

template <typename FidlType>
void
DecodeFailure(fidl::internal::WireFormatVersion version,
    std::vector<uint8_t> &bytes, const std::vector<zx_handle_info_t> handles)
{
	CheckVersion(version);
	ASSERT_TRUE(handles.empty());
	ASSERT_TRUE(Decode<FidlType>(version, bytes).is_error());
}

} // namespace conformance_utils
#endif
