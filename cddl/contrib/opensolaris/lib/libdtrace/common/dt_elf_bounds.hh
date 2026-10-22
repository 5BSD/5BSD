/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DT_ELF_BOUNDS_HH
#define DT_ELF_BOUNDS_HH
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace dtrace {
template<class Record, class Data>
static inline Record *elfBoundedRecord(Data *data)
{
    if (data == nullptr || data->d_buf == nullptr || data->d_size < sizeof(Record) ||
        reinterpret_cast<uintptr_t>(data->d_buf) % alignof(Record) != 0)
        return nullptr;
    return static_cast<Record *>(data->d_buf);
}
static inline bool
elfArrayFits(size_t bytes, size_t header, uint64_t count, size_t width)
{
    return width != 0 && header <= bytes && count <= (bytes - header) / width;
}
static inline bool
elfStringFits(const char *table, size_t bytes, size_t offset)
{
    return table != nullptr && offset < bytes &&
        std::memchr(table + offset, 0, bytes - offset) != nullptr;
}
class ElfDepthGuard {
    size_t &depth;
public:
    explicit ElfDepthGuard(size_t &value) : depth(value) { ++depth; }
    ~ElfDepthGuard() { --depth; }
};
}
#endif
