/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_ALLOCATION_FAULT_H
#define FIDL_ALLOCATION_FAULT_H
namespace fidl::bsd::testing {
// The wrappers exist only in the standalone test executable, never the library.
void FailMetadataAllocation();
void FailNewAfter(int successful_allocations);
bool DisableAllocationFault();
// Heap allocations (malloc and operator new) made by this thread so far.
unsigned long AllocationCount();
}
#endif
