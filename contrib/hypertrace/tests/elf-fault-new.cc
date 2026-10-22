/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * C++ part of elf-fault-shim.so: operator new from libdtrace fails with
 * std::bad_alloc when the "new" fault is armed (see elf-fault-shim.c).
 */
#include <cstdlib>
#include <new>

extern "C" int fault_should_fail_new(const void *);

void *
operator new(std::size_t size)
{
	if (fault_should_fail_new(__builtin_return_address(0)))
		throw std::bad_alloc();
	void *p = std::malloc(size == 0 ? 1 : size);
	if (p == nullptr)
		throw std::bad_alloc();
	return (p);
}

void *
operator new[](std::size_t size)
{
	return (::operator new(size));
}

void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
