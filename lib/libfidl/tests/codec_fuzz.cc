/* SPDX-License-Identifier: BSD-2-Clause */
/* Coverage-guided native transport/codec fuzzing; never run clock gates. */
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <fidl/bsd.runtime.test/cpp/bsd.h>
#include <fidl/bsd/runtime.h>
#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace fidl::bsd;
namespace types = bsd_runtime_test;
static constexpr uint64_t ordinal = 0x123456789ULL;
static constexpr unsigned shapes = 12;
static std::array<uint64_t, shapes> attempts {}, accepted {};

static void
Require(bool condition)
{
	if (!condition)
		abort();
}

template <typename T>
static void
Decode(Incoming &message, unsigned shape)
{
	attempts[shape]++;
	auto value = message.Decode<T>();
	if (value.is_ok()) {
		accepted[shape]++;
		// Exercise encoding and ownership of decoded values too.
		// Unknown flexible union variants legitimately cannot be
		// encoded again.
		auto encoded = Outgoing::Encode(std::move(value.value()), 0,
		    ordinal);
		if (encoded.is_ok())
			Require(
			    encoded.value()->view().length <= kMaxMessageBytes);
	}
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > kMaxMessageBytes + 2)
		return 0;
	unsigned shape = data[0] % shapes;
	unsigned count = data[1] % (kMaxDescriptors + 1);
	std::vector<Descriptor> readers, writers;
	std::vector<int> attachments;
	for (unsigned i = 0; i < count; ++i) {
		int pipefd[2];
		Require(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0);
		readers.emplace_back(pipefd[0]);
		writers.emplace_back(pipefd[1]);
		attachments.push_back(pipefd[1]);
	}
	{
		int ends[2];
		Require(mac_capability_channel_create(ends) == 0);
		Descriptor sender(ends[0]);
		auto receiver = Connection::Create(ends[1],
		    CHANNEL_ROLE_PROVIDER);
		Require(receiver.is_ok());
		bool handled = false;
		auto decode = [shape, &handled](
				  std::unique_ptr<Incoming> message) {
			handled = true;
			switch (shape) {
			case 0:
				Decode<types::Request>(*message, shape);
				break;
			case 1:
				Decode<types::Flag>(*message, shape);
				break;
			case 2:
				Decode<types::Resource>(*message, shape);
				break;
			case 3:
				Decode<types::OptionalResource>(*message,
				    shape);
				break;
			case 4:
				Decode<types::ManyResources>(*message, shape);
				break;
			case 5:
				Decode<types::DecodeAllocation>(*message,
				    shape);
				break;
			case 6:
				Decode<types::Collection>(*message, shape);
				break;
			case 7:
				Decode<types::Configuration>(*message, shape);
				break;
			case 8:
				Decode<types::Selection>(*message, shape);
				break;
			case 9:
				Decode<types::ChannelResource>(*message, shape);
				break;
			case 10:
				Decode<types::SocketResource>(*message, shape);
				break;
			case 11:
				Decode<types::ReadOnly>(*message, shape);
				break;
			}
		};
		receiver.value()->SetEventHandler(decode);
		receiver.value()->SetRequestHandler(decode);
		mac_capability_sendmsg_args request {};
		request.payload = data + 2;
		request.payload_len = size - 2;
		request.fds = attachments.data();
		request.nfds = count;
		int result = ioctl(sender.get(), MAC_CAPABILITY_SENDMSG,
		    &request);
		Require(result == 0 || (size == 2 && errno == EINVAL));
		writers.clear();
		// Delivery is checked with a bounded wait, not one zero-timeout
		// poll, so a loaded host cannot skip decoding an accepted send.
		for (int i = 0; result == 0 && !handled && i < 3 &&
		     receiver.value()->Poll(100) == 0;
		     ++i)
			;
	}
	// EOF proves there is no retained sender/queue/decoder/encoded copy.
	for (auto &reader : readers) {
		char byte;
		Require(read(reader.get(), &byte, 1) == 0);
	}
	return 0;
}

template <typename T>
static void
Seed(const std::filesystem::path &directory, unsigned shape, T value)
{
	auto encoded = Outgoing::Encode(std::move(value), 0, ordinal);
	Require(encoded.is_ok());
	auto view = encoded.value()->view();
	std::ofstream out(directory / (std::to_string(shape) + ".seed"),
	    std::ios::binary);
	out.put(static_cast<char>(shape));
	out.put(static_cast<char>(view.nfds));
	out.write(static_cast<const char *>(view.data), view.length);
	Require(out.good());
}

static void
Report()
{
	for (unsigned shape = 0; shape < shapes; ++shape)
		fprintf(stderr,
		    "fidl-fuzz shape=%u decoded=%llu accepted=%llu\n", shape,
		    (unsigned long long)attempts[shape],
		    (unsigned long long)accepted[shape]);
}

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct rlimit limit { 256, 256 };
	Require(setrlimit(RLIMIT_NOFILE, &limit) == 0);
	if (*argc == 3 && std::string((*argv)[1]) == "--write-corpus") {
		std::filesystem::path directory((*argv)[2]);
		std::filesystem::create_directories(directory);
		int ends[2];
		Require(pipe(ends) == 0);
		Descriptor reader(ends[0]), writer(ends[1]);
		Seed(directory, 0, types::Request("native fuzz seed"));
		Seed(directory, 1, types::Flag(true));
		Seed(directory, 2,
		    types::Resource(Descriptor(dup(writer.get()))));
		Seed(directory, 3, types::OptionalResource(Descriptor()));
		std::vector<Descriptor> descriptors;
		descriptors.emplace_back(dup(writer.get()));
		Seed(directory, 4,
		    types::ManyResources(std::move(descriptors)));
		Seed(directory, 5,
		    types::DecodeAllocation("seed",
			Descriptor(dup(writer.get())), { 1, 2, 3 }));
		types::Collection collection;
		collection.entries().emplace_back("key", "value");
		collection.label() = "seed";
		Seed(directory, 6, std::move(collection));
		types::Configuration configuration;
		configuration.label("seed");
		configuration.selection(types::Selection::WithNumber(42));
		Seed(directory, 7, std::move(configuration));
		Seed(directory, 8, types::Selection::WithNumber(42));
		// Deliberately wrong native types exercise descriptor
		// rejection.
		for (unsigned shape : { 9u, 10u, 11u })
			Seed(directory, shape,
			    types::Resource(Descriptor(dup(writer.get()))));
		exit(0);
	}
	atexit(Report);
	return 0;
}

// Keep the instrumented target before the prebuilt no-main driver archive.
// Otherwise its uninstrumented vector instantiations can replace ASan-aware
// instantiations and produce false container-overflow reports after resize.
extern "C" int LLVMFuzzerRunDriver(int *, char ***,
    int (*)(const uint8_t *, size_t));
int
main(int argc, char **argv)
{
	return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
