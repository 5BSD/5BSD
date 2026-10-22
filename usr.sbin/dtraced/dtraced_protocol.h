/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_PROTOCOL_H
#define DTRACED_PROTOCOL_H
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include "dtraced_io.h"
namespace dtraced {
/* Bound the native-ABI local control protocol before allocating. */
constexpr size_t max_request_bytes = 64 * 1024 * 1024;
constexpr size_t max_cleanup_entries = 4096;
constexpr size_t max_cleanup_name = 4096;
inline bool
parse_guest_elf_envelope(const unsigned char *p, size_t size,
    uint16_t vmid, uint64_t epoch, const char *name, size_t &elf_offset)
{
    hypertrace_vm_envelope envelope{};
    if (p == nullptr || name == nullptr || vmid == 0 ||
        vmid >= HYPERTRACE_MAX_VMS || epoch == 0 ||
        size < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
        errno = EPROTO;
        return false;
    }
    hypertrace_envelope_decode(&envelope, p);
    size_t name_length = ::strnlen(name, HYPERTRACE_VM_ATTEST_NAME_LEN);
    if (envelope.magic != HYPERTRACE_ENVELOPE_MAGIC ||
        envelope.version != HYPERTRACE_ENVELOPE_VERSION ||
        envelope.vmid != vmid || envelope.epoch != epoch ||
        name_length == HYPERTRACE_VM_ATTEST_NAME_LEN ||
        envelope.name_length != name_length || name_length == 0 ||
        name_length > size - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE - 4 ||
        std::memcmp(p + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
        name, name_length) != 0) {
        errno = EPROTO;
        return false;
    }
    size_t offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + name_length;
    if (std::memcmp(p + offset, "\177ELF", 4) != 0) {
        errno = EPROTO;
        return false;
    }
    elf_offset = offset;
    return true;
}
inline bool
parse_cleanup(const unsigned char *p, size_t size, uint64_t count,
    std::vector<std::string> &out)
{
    if ((p == nullptr && size != 0) || count > max_cleanup_entries ||
        count > size / 9)
        return false;
    std::vector<std::string> entries;
    entries.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        if (size < 8) return false;
        uint64_t wire_len = dtraced_wire_get_u64(p);
        p += 8; size -= 8;
        if (wire_len == 0 || wire_len > max_cleanup_name ||
            wire_len > size)
            return false;
        size_t len = (size_t)wire_len;
        if (p[len - 1] != 0 ||
            std::memchr(p, 0, len - 1) != nullptr)
            return false;
        entries.emplace_back(reinterpret_cast<const char *>(p), len - 1);
        p += len; size -= len;
    }
    if (size != 0) return false;
    out.swap(entries);
    return true;
}
}
#endif
