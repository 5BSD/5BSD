# Compressed memory: prior art and a design for 5BSD

Status: **design, nothing built.** This is here to be argued with.

Today 5BSD has no compressed memory of any kind. `sys/vm` contains no
compression and `swap_pager.c` writes pages out uncompressed. On an appliance
with a small swap device, or none, the only response to memory pressure is the
out-of-memory killer — see `memory-pressure-policy-design.md`, which is the
other half of this problem.

## What the others do

### Linux zswap — a compressed cache in front of swap

Verified against the kernel documentation.

A page being swapped out is compressed and kept in a RAM pool instead of going
to the device. The pool is managed by `zsmalloc`. When it fills, pages are
evicted **to the real swap device** on an LRU basis.

- Requires a swap device. It is a cache in front of one, not a replacement.
- `max_pool_percent` bounds the pool as a share of memory.
- `accept_threshold_percent` is hysteresis: without it a full pool rejects
  pages, they go to disk, and the pool thrashes at its boundary.
- Same-value-filled pages (all zeroes, all `0xff`) are stored as a pattern
  with compressed length zero. A large fraction of real pages are like this.
- Stated trade: CPU cycles for swap I/O. Longer SSD life, less I/O pressure.
- Wart: disabling it at runtime does not flush what it holds.

### Linux zram — a compressed RAM block device

Verified against the kernel documentation.

`/dev/zram0` is a block device whose contents live compressed in RAM. Used as
swap, it needs no backing store at all, which is why Android and ChromeOS use
it. Also `zsmalloc`; compressors are lzo, lz4, zstd and others.

- Supports up to four algorithms — one primary, three secondary — so a page
  can be **recompressed** more aggressively later.
- Pages that will not compress are flagged "huge" and, with writeback
  configured, pushed to a real backing device rather than wasting RAM.
- Idle pages can also be written back.
- `mem_limit` caps consumption.

### Darwin — compression as a page state, not an I/O path

Read from the XNU source (`osfmk/vm/vm_compressor_xnu.h`,
`vm_compressor_algorithms_internal.h`).

Pages are compressed **in place in RAM** and packed into **segments**. A
`c_segment` holds many compressed pages in one buffer and tracks
`c_bytes_used` / `c_bytes_unused` / `c_slots_used` / `c_nextoffset` — offsets
counted in 32-bit words, not bytes. Its `c_store` is a **union**: either a
buffer pointer when the segment is in memory, or a swap handle when it is on
disk. That one union is the whole idea — the same object is the RAM cache and
the swap representation, and moving between them is a state change, not a
format change.

A compressed page is addressed by a 32-bit `c_slot_mapping` held in the pager:
segment number plus a slot index within it. The indirection means the
compressor can **relocate and compact segments without touching pager
metadata**. Each `c_slot` records offset and size, with two reserved sizes
carrying meaning: `4` means a short repeated value, `PAGE_SIZE` means the page
would not compress.

Segments move through an explicit state machine, each state a queue:

| State | Meaning |
|---|---|
| `C_IS_EMPTY` / `C_IS_FILLING` | being filled with newly compressed pages |
| `C_ON_AGE_Q` | aged, eligible for swapout |
| `C_ON_SWAPOUT_Q` / `C_ON_SWAPIO_Q` | being written |
| `C_ON_SWAPPEDOUT_Q` | fully on disk |
| `C_ON_SWAPPEDOUTSPARSE_Q` | on disk but with slots since freed |
| `C_ON_SWAPPEDIN_Q` | brought back |
| `C_ON_MAJORCOMPACT_Q` | after compaction |

Fragmentation is handled by **compaction**, with two tiers: minor when unused
bytes reach a quarter of the buffer, major when unused plus free reaches an
eighth *and* there are enough free slots. This is the answer to the packing
problem — rather than a clever allocator, Darwin packs simply and compacts
later, which it can afford precisely because of the indirection above.

Thresholds for when to compress, when to swap and when to throttle are
computed from available memory with hysteresis (multipliers of 9 and 11 around
the trigger), and platform floors differ sharply: 20,000 reserve pages on iOS
against 128 on macOS.

Two algorithms are selectable — **WKdm** (`CMODE_WK`, a dictionary scheme
tuned for what pages actually contain: pointers, zeroes, repeated words) and
**LZ4** (`CMODE_LZ4`) — plus a **hybrid** mode (`CMODE_HYB`) that chooses per
page. Size fields are architecture-specific: ARM64 packs a 33-bit pointer and
a 14-bit size, x86_64 36 and 12.

The idea worth taking is not the algorithm. It is this:

> A compressed page is still **resident**. Compression is a state a page is
> in, not a destination it is sent to.

That is why iOS works with no swap device. Decompressing is a memcpy, not a
disk read, so the cost of being wrong is microseconds rather than milliseconds.
zram reaches a similar place by pretending to be a disk; Darwin does it without
the pretence, at the cost of touching the VM properly.

## What this means for us

Three things about our situation decide the design.

**Appliances may have no swap device.** That rules out a zswap-style cache as
the first step: zswap without a device to evict to has nowhere to go when the
pool fills.

**We already have the compressors.** LZ4 is in the tree at
`sys/cddl/contrib/opensolaris/common/lz4/lz4.c` and zstd at
`sys/contrib/zstd`. Nothing needs writing or importing. WKdm is interesting
but is an optimisation, not a prerequisite.

**The packing problem has two known answers, and Darwin's is the cheaper
one.** Linux solves it with an allocator — zsmalloc — that packs
variable-length objects across pages. Darwin does not: it appends into a
segment buffer, lets holes accumulate as slots are freed, and **compacts**
later, at a quarter unused for minor and an eighth for major. It can do that
because the pager holds an indirection (`c_slot_mapping`), so segments can be
moved without anyone else noticing.

Compaction is much easier to get right than an allocator, and the indirection
that makes it possible is something we need anyway. Writing a zsmalloc
equivalent should be the fallback, not the plan.

## Options, cheapest first

**A. zram-shaped: a compressed RAM block device used as swap.**
Reuses `swap_pager` unchanged; the device is just another swap target. Least
invasive, and it works with no physical swap. The cost is that every page goes
through the block layer to reach a memcpy — real overhead for no I/O.

**B. zswap-shaped: compress inside the swap pager.**
Hook `swap_pager_putpages`/`getpages`, keep a compressed pool, fall through to
a device when the pool is full — or refuse when there is no device. Avoids the
block layer. Confined to `swap_pager.c` plus an allocator.

**C. Darwin-shaped: a compressed page state in the VM.**
Pages move active → inactive → compressed → (optionally) swapped. Best result:
the page daemon can treat compression as a reclaim target like any other, and
accounting is honest because compressed pages are still counted as resident.
Most invasive by a wide margin.

**Recommendation: B, built so C remains reachable.** B is buildable without
redesigning the VM and works with no swap device if the pool is allowed to be
terminal. The thing to take from Darwin regardless of which shape we pick is
the **indirection**: address a compressed page by (segment, slot) through a
table, never by pointer. That one decision is what makes compaction possible,
makes segments relocatable, and makes the later move from B to C a change of
who decides rather than a change of format.

The trap to avoid is B built as "compress on the way to the device," which
bakes in the assumption that there is a device and makes C unreachable.

## Questions to settle before writing code

1. **Append-and-compact, or allocate?** Darwin's answer says append into a
   segment and compact when holes reach a quarter. That needs an indirection
   table so segments can move. Decide this first: it shapes everything else.
2. **Terminal pool or cache?** With no swap device, a full pool has nowhere to
   evict. Does it refuse (and the OOM killer runs), or do we require a device?
3. **Same-value pages.** Cheap and worth doing on day one — a zero page costs
   a tag, not a buffer. Likely the single best return per line.
4. **Incompressible pages.** Store uncompressed, or pass through to a device?
   zram's "huge page" flag is the precedent.
5. **Accounting.** A compressed page is resident. If it is not visible to the
   page daemon and to per-unit accounting, we have moved the problem rather
   than solved it, and the OOM killer will make worse decisions.
6. **Where the CPU goes.** Compression in the page daemon's own thread is a
   new way to make the page daemon slow. Probably its own taskqueue.

## Sources

- [zswap — Linux kernel documentation](https://docs.kernel.org/admin-guide/mm/zswap.html)
- [zram — Linux kernel documentation](https://docs.kernel.org/admin-guide/blockdev/zram.html)
