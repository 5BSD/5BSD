// SPDX-License-Identifier: BSD-2-Clause
#include <algorithm>
#include <charconv>
#include <stdexcept>
#include <string>
#include <vector>

int main()
{
    std::vector<std::string> values = {"gamma", "alpha", "beta"};
    std::sort(values.begin(), values.end());
    if (values.front() + ":" + values.back() != "alpha:gamma")
        return 1;
    bool caught = false;
    try {
        (void)values.at(values.size());
    } catch (const std::out_of_range &) {
        caught = true;
    }
    if (!caught)
        return 2;
    char text[32];
    auto result = std::to_chars(text, text + sizeof(text), 12.5);
    if (result.ec != std::errc() || std::string(text, result.ptr) != "12.5")
        return 3;
    return 0;
}
