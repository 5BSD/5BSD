/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise standard C/C++ headers through libctf's public link interface. */
#include <cerrno>
#include <cmath>
#include <cstring>
#include <string>
#include <cwchar>

int
main()
{
    char copy[8] = {};
    const std::string text("ctf");
    std::memcpy(copy, text.c_str(), text.size() + 1);
    errno = EINVAL;
    const std::wint_t character = L'c';
    return errno != EINVAL || std::strcmp(copy, "ctf") != 0 ||
        !std::isfinite(1.0) || character != L'c';
}
