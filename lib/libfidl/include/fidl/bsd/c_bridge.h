/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_C_BRIDGE_H
#define FIDL_BSD_C_BRIDGE_H
#include <sys/capsicum.h>

#include <fcntl.h>
#include <fidl/bsd/runtime.h>
#include <fidl/bsd/runtime_c.h>
#include <system_error>

// Private C++ implementation behind the opaque C ABI.
struct fidl_bsd_connection {
	std::unique_ptr<fidl::bsd::Connection> value;
};
struct fidl_bsd_request {
	unsigned references = 1;
	std::unique_ptr<fidl::bsd::Incoming> value;
};
namespace fidl::bsd {
// Limit conversion work before allocating natural objects. The wire byte
// limit bounds any useful payload; allow aggregate bookkeeping as well.
struct CEncodeBudget {
	size_t remaining = 2 * kMaxMessageBytes;
	size_t descriptors = kMaxDescriptors;
	void DescriptorSlot(int fd)
	{
		if (fd < 0)
			return;
		if (!descriptors)
			throw std::system_error(EMSGSIZE,
			    std::generic_category());
		--descriptors;
	}
	void Consume(size_t count)
	{
		if (count > remaining)
			throw std::system_error(EMSGSIZE,
			    std::generic_category());
		remaining -= count;
	}
	void Enter(size_t depth)
	{
		if (depth > 64)
			throw std::system_error(EINVAL,
			    std::generic_category());
		Consume(1);
	}
};
// C views borrow native strings and descriptors. Allocated C aggregate
// arrays live through the callback. Track each original descriptor slot,
// so changing a C vector pointer or length cannot defeat ownership cleanup.
class CViewArena {
	struct Allocation {
		void *pointer;
		void (*destroy)(void *);
	};
	struct Borrowed {
		int *slot;
		Descriptor *owner;
	};
	std::vector<Allocation> allocations_;
	std::array<Borrowed, kMaxDescriptors> descriptors_ {};
	size_t count_ = 0;

    public:
	CViewArena() = default;
	CViewArena(const CViewArena &) = delete;
	CViewArena &operator=(const CViewArena &) = delete;
	~CViewArena()
	{
		for (size_t i = 0; i < count_; ++i)
			if (*descriptors_[i].slot == -1)
				descriptors_[i].owner->release();
		for (auto &allocation : allocations_)
			allocation.destroy(allocation.pointer);
	}
	template <typename T> T *Allocate(size_t count)
	{
		if (!count)
			return nullptr;
		auto storage = std::make_unique<T[]>(count);
		allocations_.push_back({ storage.get(),
		    [](void *p) { delete[] static_cast<T *>(p); } });
		return storage.release();
	}
	void Borrow(Descriptor &owner, int *slot)
	{
		if (count_ == descriptors_.size())
			throw std::system_error(EMSGSIZE,
			    std::generic_category());
		*slot = owner.get();
		if (owner)
			descriptors_[count_++] = { slot, &owner };
	}
};
// C callers lend descriptors, so the bindings send a private duplicate.
// One system call: C connections deliver with close-on-exec and
// close-on-fork locked (Connection::LockSentDescriptorInheritance), so
// the duplicate needs no locks of its own.
inline Descriptor
DuplicateForC(int fd)
{
	if (fd < 0)
		return Descriptor();
	Descriptor result(fcntl(fd, F_DUPFD_CLOFORK, 0));
	if (!result)
		throw std::system_error(errno, std::generic_category());
	return result;
}
template <typename F>
int
CBoundary(F action) noexcept
{
	try {
		return action();
	} catch (const std::bad_alloc &) {
		return ENOMEM;
	} catch (const std::system_error &error) {
		return error.code().value();
	} catch (...) {
		return EINVAL;
	}
}
struct RequestRelease {
	void operator()(fidl_bsd_request *request) const
	{
		fidl_bsd_request_release(request);
	}
};
using CRequest = std::unique_ptr<fidl_bsd_request, RequestRelease>;
}
namespace fidl::bsd::generated {
inline Empty
FromC(const fidl_bsd_empty *input, CEncodeBudget &budget, size_t depth)
{
	if (!input)
		throw std::system_error(EINVAL, std::generic_category());
	budget.Enter(depth);
	return {};
}
inline Empty
FromC(const fidl_bsd_empty *input)
{
	CEncodeBudget budget;
	return FromC(input, budget, 0);
}
inline void
ToC(Empty &, fidl_bsd_empty &, CViewArena &, size_t)
{
}
struct View_fidl_bsd_empty {
	fidl_bsd_empty data {};
	explicit View_fidl_bsd_empty(Empty &) { }
};
}
#endif
