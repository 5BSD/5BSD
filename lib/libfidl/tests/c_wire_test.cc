/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The C bindings' direct wire codec (<fidl/bsd/c_wire.h>, generated
 * CWEnc_/CWDec_ functions) against the upstream natural codec it replaces:
 *
 * - encoding: a C value encodes to the same bytes and descriptor count as
 *   the natural value converted from it, and fails exactly when that does;
 * - decoding: valid encodings and many mutations of them are accepted by
 *   both decoders or by neither, and an accepted message decodes to the
 *   same value (compared by encoding both results again).
 *
 * Plain program: prints a summary, exits 0 on success.
 */
#include <fcntl.h>
#include <fidl/bsd.runtime.test/c/bridge.h>
#include <fidl/bsd/c_wire.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace fidl::bsd;
using namespace fidl::bsd::generated;
namespace types = bsd_runtime_test;

static unsigned failures, checks;

#define CHECK(cond)                                                          \
	do {                                                                 \
		++checks;                                                    \
		if (!(cond)) {                                               \
			++failures;                                          \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__,   \
			    #cond);                                          \
		}                                                            \
	} while (0)

struct Encoded {
	int error = 0;
	std::vector<uint8_t> body;
	size_t handles = 0;
};

static Encoded
FromPacket(const Outgoing &packet)
{
	Encoded e;
	auto view = packet.view();
	const auto *bytes = static_cast<const uint8_t *>(view.data);
	e.body.assign(bytes + sizeof(fidl_message_header_t),
	    bytes + view.length);
	e.handles = view.nfds;
	return e;
}

template <typename C>
static Encoded
RawEncode(void (*enc)(cwire::Encoder &, const C *, size_t, size_t),
    size_t inline_size, const C &value)
{
	Outgoing packet;
	Encoded e;
	e.error = packet.RawStart(1, 0x1234, false);
	if (!e.error) {
		cwire::Encoder encoder(packet);
		size_t at = encoder.Alloc(inline_size);
		enc(encoder, &value, at, 0);
		e.error = encoder.error();
	}
	if (e.error)
		return e;
	return FromPacket(packet);
}

template <typename C>
static Encoded
NaturalEncode(const C &value)
{
	Encoded e;
	try {
		auto natural = FromC(&value);
		auto packet = Outgoing::Encode(std::move(natural), 1, 0x1234);
		if (packet.is_error()) {
			e.error = packet.error_value();
			return e;
		}
		return FromPacket(*packet.value());
	} catch (const std::system_error &error) {
		e.error = error.code().value();
	} catch (const std::bad_alloc &) {
		e.error = ENOMEM;
	}
	return e;
}

static std::vector<int>
Descriptors(size_t count)
{
	std::vector<int> fds;
	for (size_t i = 0; i < count; ++i)
		fds.push_back(open("/dev/null", O_RDWR | O_CLOEXEC));
	return fds;
}

// Natural decode, converted back to C, encoded with the direct encoder.
template <typename C, typename N, typename V>
static Encoded
NaturalRoundTrip(void (*enc)(cwire::Encoder &, const C *, size_t, size_t),
    size_t inline_size, const std::vector<uint8_t> &body, size_t nfds)
{
	Encoded out;
	std::vector<uint64_t> storage((body.size() + 7) / 8 + 1);
	memcpy(storage.data(), body.data(), body.size());
	auto fds = Descriptors(nfds);
	std::array<fidl_handle_t, kMaxDescriptors> slots {};
	std::array<Transport::HandleMetadata, kMaxDescriptors> metadata {};
	for (size_t i = 0; i < nfds; ++i)
		slots[i] = static_cast<uint32_t>(fds[i]) + 1;
	auto message = fidl::EncodedMessage::Create<Transport>(
	    { reinterpret_cast<uint8_t *>(storage.data()), body.size() },
	    slots.data(), metadata.data(), static_cast<uint32_t>(nfds));
	auto result = fidl::StandaloneDecode<N>(std::move(message),
	    fidl::internal::WireFormatMetadataForVersion(
		fidl::internal::WireFormatVersion::kV2));
	if (result.is_error()) {
		out.error = EPROTO;
		return out;
	}
	try {
		V view(result.value());
		return RawEncode(enc, inline_size, view.data);
	} catch (...) {
		out.error = EINVAL;
		return out;
	}
}

// Direct decode, encoded again with the direct encoder.
template <typename C>
static Encoded
DirectRoundTrip(void (*enc)(cwire::Encoder &, const C *, size_t, size_t),
    bool (*dec)(cwire::Decoder &, size_t, C *, size_t), size_t inline_size,
    const std::vector<uint8_t> &body, size_t nfds)
{
	Encoded out;
	std::vector<uint64_t> storage((body.size() + 7) / 8 + 1);
	memcpy(storage.data(), body.data(), body.size());
	auto fds = Descriptors(nfds);
	cwire::Arena arena;
	C value {};
	cwire::Decoder decoder(arena);
	decoder.Begin(reinterpret_cast<const uint8_t *>(storage.data()),
	    body.size(), fds.data(), nullptr, nullptr, nfds);
	size_t at;
	if (!decoder.Claim(inline_size, &at) || !dec(decoder, at, &value, 0) ||
	    !decoder.Finish()) {
		out.error = EPROTO;
		return out;
	}
	return RawEncode(enc, inline_size, value);
}

template <typename C, typename N, typename V> struct Kit {
	void (*enc)(cwire::Encoder &, const C *, size_t, size_t);
	bool (*dec)(cwire::Decoder &, size_t, C *, size_t);
	size_t inline_size;
	const char *name;
};

// One value: encoders agree; then decoders agree on it and its mutations.
template <typename C, typename N, typename V>
static void
Exercise(const Kit<C, N, V> &kit, const C &value, std::mt19937 &random,
    unsigned mutations)
{
	auto raw = RawEncode(kit.enc, kit.inline_size, value);
	auto natural = NaturalEncode(value);
	CHECK((raw.error == 0) == (natural.error == 0));
	if (raw.error || natural.error)
		return;
	CHECK(raw.body == natural.body);
	CHECK(raw.handles == natural.handles);
	if (raw.body != natural.body)
		fprintf(stderr, "  %s: encodings differ (%zu vs %zu bytes)\n",
		    kit.name, raw.body.size(), natural.body.size());
	unsigned accepted = 0;
	for (unsigned i = 0; i <= mutations; ++i) {
		auto body = natural.body;
		size_t nfds = natural.handles;
		if (i) {
			switch (random() % 6) {
			case 0:
			case 1:
			case 2:
				if (!body.empty())
					body[random() % body.size()] =
					    static_cast<uint8_t>(random());
				break;
			case 3:
				if (!body.empty())
					body[random() % body.size()] ^=
					    static_cast<uint8_t>(1u << (random() % 8));
				break;
			case 4:
				body.resize(random() % (body.size() + 9));
				break;
			case 5:
				nfds = random() % (natural.handles + 2);
				break;
			}
		}
		auto a = NaturalRoundTrip<C, N, V>(kit.enc, kit.inline_size, body,
		    nfds);
		auto b = DirectRoundTrip<C>(kit.enc, kit.dec, kit.inline_size,
		    body, nfds);
		CHECK((a.error == 0) == (b.error == 0));
		if ((a.error == 0) != (b.error == 0))
			fprintf(stderr, "  %s mutation %u: natural %d direct %d\n",
			    kit.name, i, a.error, b.error);
		if (!a.error && !b.error) {
			++accepted;
			CHECK(a.body == b.body);
			CHECK(a.handles == b.handles);
		}
	}
	printf("%s: %u/%u messages accepted by both codecs\n", kit.name,
	    accepted, mutations + 1);
}

#define KIT(cn, natural)                                                     \
	Kit<cn, natural, View_##cn>                                          \
	{                                                                    \
		CWEnc_##cn, CWDec_##cn,                                      \
		    fidl::internal::NaturalCodingTraits<natural,             \
			fidl::internal::NaturalCodingConstraintEmpty>::      \
			kInlineSize,                                         \
		    #cn                                                      \
	}

int
main(int argc, char **argv)
{
	unsigned mutations = argc > 1 ? strtoul(argv[1], nullptr, 10) : 2000;
	std::mt19937 random(12345);

	// Strings, unions, results.
	bsd_runtime_test_Response response { "hello", 5 };
	Exercise(KIT(bsd_runtime_test_Response, types::Response), response,
	    random, mutations);
	bsd_runtime_test_Response bad_utf8 { "\xc0\x80", 2 };
	Exercise(KIT(bsd_runtime_test_Response, types::Response), bad_utf8,
	    random, 0);
	// The empty string, as C callers write it: NULL with size 0.
	bsd_runtime_test_Response empty_text { nullptr, 0 };
	Exercise(KIT(bsd_runtime_test_Response, types::Response), empty_text,
	    random, mutations);
	bsd_runtime_test_Response too_long { nullptr, 0 };
	std::string long_text(257, 'x');
	too_long.text = long_text.c_str();
	too_long.text_size = long_text.size();
	Exercise(KIT(bsd_runtime_test_Response, types::Response), too_long,
	    random, 0);

	bsd_runtime_test_Collections_Check_Result check {};
	check.tag = bsd_runtime_test_Collections_Check_Result_err_tag;
	check.value.err = 17;
	Exercise(KIT(bsd_runtime_test_Collections_Check_Result,
		     types::CollectionsCheckResult),
	    check, random, mutations);
	check.tag = bsd_runtime_test_Collections_Check_Result_response_tag;
	check.value.response = { "ok", 2 };
	Exercise(KIT(bsd_runtime_test_Collections_Check_Result,
		     types::CollectionsCheckResult),
	    check, random, mutations);
	check.tag = 99;
	Exercise(KIT(bsd_runtime_test_Collections_Check_Result,
		     types::CollectionsCheckResult),
	    check, random, 0);

	bsd_runtime_test_Flexible_Check_Result flexible {};
	flexible.tag = bsd_runtime_test_Flexible_Check_Result_framework_err_tag;
	flexible.value.framework_err = -2;
	Exercise(KIT(bsd_runtime_test_Flexible_Check_Result,
		     types::FlexibleCheckResult),
	    flexible, random, mutations);

	// Tables and flexible unions.
	bsd_runtime_test_Configuration config {};
	Exercise(KIT(bsd_runtime_test_Configuration, types::Configuration),
	    config, random, mutations);
	config.has_selection = true;
	config.selection.tag = bsd_runtime_test_Selection_entry_tag;
	config.selection.value.entry = { "key", 3, "value", 5 };
	config.has_label = true;
	config.label = "label";
	config.label_size = 5;
	Exercise(KIT(bsd_runtime_test_Configuration, types::Configuration),
	    config, random, mutations);
	config.has_selection = true;
	config.selection.tag = bsd_runtime_test_Selection_number_tag;
	config.selection.value.number = 7;
	config.has_label = false;
	Exercise(KIT(bsd_runtime_test_Configuration, types::Configuration),
	    config, random, mutations);

	// The aggregate fixture: descriptors, vectors, arrays, bools,
	// optional string/vector, box, enum and bits.
	auto fds = Descriptors(2);
	bsd_runtime_test_DictionaryEntry entries[2] = {
		{ "a", 1, "1", 1 }, { "bb", 2, "22", 2 } };
	bool switches[3] = { true, false, true };
	uint32_t optional_numbers[2] = { 4, 5 };
	bsd_runtime_test_Linked tail { 2, nullptr }, head { 1, &tail };
	bsd_runtime_test_Collection collection {};
	collection.descriptors = fds.data();
	collection.descriptors_size = fds.size();
	collection.entries = entries;
	collection.entries_size = 2;
	collection.numbers[0] = 1;
	collection.numbers[1] = 2;
	collection.numbers[2] = 3;
	collection.switches = switches;
	collection.switches_size = 3;
	collection.label = "label";
	collection.label_size = 5;
	collection.label_present = true;
	collection.optional_numbers = optional_numbers;
	collection.optional_numbers_size = 2;
	collection.optional_numbers_present = true;
	collection.chain = &head;
	collection.mode = bsd_runtime_test_Mode_ON;
	collection.features = bsd_runtime_test_Features_FIRST |
	    bsd_runtime_test_Features_SECOND;
	Exercise(KIT(bsd_runtime_test_Collection, types::Collection),
	    collection, random, mutations);
	auto empty = collection;
	empty.descriptors_size = empty.entries_size = empty.switches_size = 0;
	empty.label_present = false;
	empty.label = nullptr;
	empty.label_size = 0;
	empty.optional_numbers_present = false;
	empty.optional_numbers = nullptr;
	empty.optional_numbers_size = 0;
	empty.chain = nullptr;
	Exercise(KIT(bsd_runtime_test_Collection, types::Collection), empty,
	    random, mutations);
	auto bad_enum = collection;
	bad_enum.mode = 7;
	Exercise(KIT(bsd_runtime_test_Collection, types::Collection),
	    bad_enum, random, 0);
	auto bad_bits = collection;
	bad_bits.features = 4;
	Exercise(KIT(bsd_runtime_test_Collection, types::Collection),
	    bad_bits, random, 0);

	// Recursion depth: chains around the 32-level limit.
	for (unsigned length : { 30u, 31u, 32u, 33u }) {
		std::vector<bsd_runtime_test_Linked> chain(length);
		for (unsigned i = 0; i < length; ++i)
			chain[i] = { i, i + 1 < length ? &chain[i + 1] : nullptr };
		auto deep = empty;
		deep.chain = &chain[0];
		Exercise(KIT(bsd_runtime_test_Collection, types::Collection),
		    deep, random, 50);
	}

	// Escaped names, many descriptors, large bodies, tables of handles.
	bsd_runtime_test_EscapedNames escaped { 1, "t", 1, 2, 3 };
	Exercise(KIT(bsd_runtime_test_EscapedNames, types::EscapedNames),
	    escaped, random, mutations);
	auto many_fds = Descriptors(5);
	bsd_runtime_test_ManyResources many { many_fds.data(),
		many_fds.size() };
	Exercise(KIT(bsd_runtime_test_ManyResources, types::ManyResources),
	    many, random, mutations);
	std::vector<uint8_t> large_bytes(3000, 0x5a);
	bsd_runtime_test_Large large { large_bytes.data(), large_bytes.size() };
	Exercise(KIT(bsd_runtime_test_Large, types::Large), large, random,
	    mutations / 4);
	bsd_runtime_test_Extensible extensible { true, fds[0] };
	Exercise(KIT(bsd_runtime_test_Extensible, types::Extensible),
	    extensible, random, mutations);
	bsd_runtime_test_OptionalResource optional { -1 };
	Exercise(KIT(bsd_runtime_test_OptionalResource,
		     types::OptionalResource),
	    optional, random, mutations);
	bsd_runtime_test_Flag flag { true };
	Exercise(KIT(bsd_runtime_test_Flag, types::Flag), flag, random,
	    mutations);

	printf("c_wire_test: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
