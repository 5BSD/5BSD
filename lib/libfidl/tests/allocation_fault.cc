/* SPDX-License-Identifier: BSD-2-Clause */
#include <cstddef>
#include <new>

#include "allocation_fault.h"
namespace {
thread_local bool fail_metadata = false;
thread_local int fail_new_after = -1;
thread_local bool triggered = false;
thread_local unsigned long allocations = 0;
}
namespace fidl::bsd::testing {
void
FailMetadataAllocation()
{
	fail_metadata = true;
	triggered = false;
}
void
FailNewAfter(int count)
{
	fail_new_after = count;
	triggered = false;
}
bool
DisableAllocationFault()
{
	fail_metadata = false;
	fail_new_after = -1;
	return triggered;
}
unsigned long
AllocationCount()
{
	return allocations;
}
}
extern "C" void *__real_malloc(std::size_t);
extern "C" void *__real__Znwm(std::size_t);
extern "C" void *__real__Znam(std::size_t);
extern "C" void *
__wrap_malloc(std::size_t count)
{
	++allocations;
	if (fail_metadata) {
		fail_metadata = false;
		triggered = true;
		return nullptr;
	}
	return __real_malloc(count);
}
static void
CheckNew()
{
	++allocations;
	if (fail_new_after < 0)
		return;
	if (fail_new_after-- == 0) {
		triggered = true;
		throw std::bad_alloc();
	}
}
extern "C" void *
__wrap__Znwm(std::size_t count)
{
	CheckNew();
	return __real__Znwm(count);
}
extern "C" void *
__wrap__Znam(std::size_t count)
{
	CheckNew();
	return __real__Znam(count);
}
