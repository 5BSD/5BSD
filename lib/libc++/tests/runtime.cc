/* SPDX-License-Identifier: BSD-2-Clause */
/* Public-API integration checks for the native libc++ shared-library closure. */
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <locale>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static void
require(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

int
main()
{
	try {
		char text[64];
		auto converted = std::to_chars(text, text + sizeof(text), 1.25);
		require(converted.ec == std::errc{} &&
		    std::string(text, converted.ptr) == "1.25", "floating to_chars");
		double number = 0;
		auto parsed = std::from_chars(text, converted.ptr, number);
		require(parsed.ec == std::errc{} && parsed.ptr == converted.ptr &&
		    number == 1.25, "floating from_chars");
		const std::string invalid = "not-a-number", overflow = "1e9999";
		require(std::from_chars(invalid.data(), invalid.data() + invalid.size(), number).ec ==
		    std::errc::invalid_argument, "from_chars invalid input");
		require(std::from_chars(overflow.data(), overflow.data() + overflow.size(), number).ec ==
		    std::errc::result_out_of_range, "from_chars overflow");

		std::vector<std::string> values{"one", "two"};
		values.emplace_back("three");
		bool caught = false;
		try {
			(void)values.at(values.size());
		} catch (const std::out_of_range &) {
			caught = true;
		}
		require(caught && values.back() == "three", "vector and exception ABI");
		std::ostringstream stream;
		stream.imbue(std::locale::classic());
		stream << 1.25;
		require(stream.str() == "1.25", "classic locale formatting");

		std::promise<int> promise;
		auto future = promise.get_future();
		std::thread worker([&promise] { promise.set_value(42); });
		worker.join();
		require(future.get() == 42, "thread/promise/future");

		const char *tmp = std::getenv("TEST_TMPDIR");
		require(tmp != nullptr, "TEST_TMPDIR required");
		const auto directory = std::filesystem::path(tmp) / "libcxx-runtime";
		require(std::filesystem::create_directory(directory), "create directory");
		const auto file = directory / "data", renamed = directory / "renamed";
		{
			std::ofstream output(file);
			output << "native libc++\n";
			output.close();
			require(!output.fail(), "ofstream write");
		}
		std::filesystem::rename(file, renamed);
		require(!std::filesystem::exists(file) && std::filesystem::file_size(renamed) == 14,
		    "filesystem rename and size");
		std::ifstream input(renamed);
		std::string line;
		std::getline(input, line);
		require(line == "native libc++", "ifstream read");
		input.close();
		require(std::distance(std::filesystem::directory_iterator(directory),
		    std::filesystem::directory_iterator{}) == 1, "directory iteration");
		require(std::filesystem::remove_all(directory) == 2, "filesystem cleanup");
		std::cout << "PASS\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
