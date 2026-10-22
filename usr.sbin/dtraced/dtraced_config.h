/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_CONFIG_H
#define DTRACED_CONFIG_H
#include <cerrno>
#include <cstdlib>
#include <cstring>
namespace dtraced {
constexpr unsigned long max_workers = 1024;
inline bool parse_workers(const char *text, unsigned long &count) {
    if (text == nullptr || *text < '0' || *text > '9') { errno = EINVAL; return false; }
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0) return false;
    if (*end != '\0' || value == 0 || value > max_workers) { errno = EINVAL; return false; }
    count = value; return true;
}
template<size_t N>
bool directory_paths(const char *input, char (&base)[N], char (&inbound)[N],
    char (&outbound)[N], char (&local)[N]) {
    if (input == nullptr || input[0] != '/') { errno = EINVAL; return false; }
    size_t length = strnlen(input, N);
    if (length == N) { errno = ENAMETOOLONG; return false; }
    while (length > 1 && input[length - 1] == '/') length--;
    size_t prefix = length == 1 ? 0 : length;
    if (prefix + sizeof("/outbound/") > N) { errno = ENAMETOOLONG; return false; }
    memcpy(base, input, length); base[length] = '\0';
    memcpy(inbound, input, prefix); memcpy(inbound + prefix, "/inbound/", sizeof("/inbound/"));
    memcpy(outbound, input, prefix); memcpy(outbound + prefix, "/outbound/", sizeof("/outbound/"));
    memcpy(local, input, prefix); memcpy(local + prefix, "/base/", sizeof("/base/"));
    return true;
}
}
#endif
