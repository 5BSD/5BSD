/* SPDX-License-Identifier: BSD-2-Clause */
#include <cstdlib>
#include <new>
extern "C" void *dt_alloc(void *, size_t);
void *operator new(size_t size) {
    void *p = dt_alloc(nullptr, size == 0 ? 1 : size);
    if (p == nullptr) throw std::bad_alloc();
    return p;
}
void *operator new[](size_t size) { return ::operator new(size); }
void operator delete(void *p) noexcept { free(p); }
void operator delete[](void *p) noexcept { free(p); }
void operator delete(void *p, size_t) noexcept { free(p); }
void operator delete[](void *p, size_t) noexcept { free(p); }
