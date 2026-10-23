/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAPIMAGE_ELF_H_
#define _SYS_CAPIMAGE_ELF_H_
#include <sys/capimage.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif
/* No allocation, errno,
 * native ELF alignment or byte order assumptions. Callback: 0 on full read.
 * Probe: 0 no recognized signature, 1 structural signature, -1 damaged/read
 * failure. Ordinary malformed ELF without a recognized locator remains 0. */
typedef int (*capimage_elf_read_t)(void *, uint64_t, void *, size_t);
static inline uint64_t
capimage_elf_uint(const uint8_t *p, unsigned n, int little)
{
	uint64_t v = 0;
	for (unsigned i = 0; i < n; i++)
		v = (v << 8) | p[little ? n - 1 - i : i];
	return (v);
}
static inline void
capimage_elf_put(uint8_t *p, uint64_t v, unsigned n, int little)
{
	for (unsigned i = 0; i < n; i++, v >>= 8)
		p[little ? i : n - 1 - i] = (uint8_t)v;
}
static inline int
capimage_elf_range(uint64_t o, uint64_t n, uint64_t limit)
{
	return (o <= limit && n <= limit - o);
}
static inline int
capimage_elf_probe_impl(capimage_elf_read_t rd, void *ctx, uint64_t size,
    struct capimage_elf_info *out)
{
	uint8_t eh[64], footer[32], sh[64], str[64], nh[20], h[112], orig[88];
	uint8_t old[64], expected[64];
	uint64_t so, strings, strings_size, noteoff = 0, notesize = 0, limit;
	unsigned es, ss, sn, si, is64, le, version = 0, found = 0, noteindex = 0;
	int marked = 0;
	memset(out, 0, sizeof(*out));
	if (size < 32) return (0);
	if (rd(ctx, size - 32, footer, 32) != 0) return (-1);
	marked = memcmp(footer, "5BSDEND", 8) == 0;
	if (size < 52) return (marked ? -1 : 0);
	memset(eh, 0, sizeof(eh));
	if (rd(ctx, 0, eh, 52) != 0) return (-1);
	if (memcmp(eh, "\177ELF", 4) != 0 || (eh[4] != 1 && eh[4] != 2) ||
	    (eh[5] != 1 && eh[5] != 2) || eh[6] != 1)
		return (marked ? -1 : 0);
	is64 = eh[4] == 2; le = eh[5] == 1; es = is64 ? 64 : 52;
	ss = is64 ? 64 : 40;
	if (size < es || (is64 && rd(ctx, 52, eh + 52, 12) != 0)) return (-1);
#define CI_U(p,n) capimage_elf_uint((p),(n),le)
	so = CI_U(eh + (is64 ? 40 : 32), is64 ? 8 : 4);
	sn = CI_U(eh + (is64 ? 60 : 48), 2);
	si = CI_U(eh + (is64 ? 62 : 50), 2);
	/* Bounded discovery. Bad ordinary section metadata is left to ELF loader.
	 * A matching named section is recognized before checking its attributes. */
	if (sn != 0 && sn <= 8192 && si != 0 && si < sn &&
	    CI_U(eh + (is64 ? 58 : 46), 2) == ss &&
	    capimage_elf_range(so, (uint64_t)sn * ss, size)) {
		if (rd(ctx, so + (uint64_t)si * ss, str, ss) != 0) return (-1);
		strings = CI_U(str + (is64 ? 24 : 16), is64 ? 8 : 4);
		strings_size = CI_U(str + (is64 ? 32 : 20), is64 ? 8 : 4);
		if (CI_U(str + 4, 4) == 3 && capimage_elf_range(strings, strings_size, size)) {
			for (unsigned i = 1; i < sn; i++) {
				char name[sizeof(CAPIMAGE_ELF_SECTION)];
				if (rd(ctx, so + (uint64_t)i * ss, sh, ss) != 0) return (-1);
				uint64_t no = CI_U(sh, 4);
				int named = 0, typed = 0;
				if (capimage_elf_range(no, sizeof(name), strings_size)) {
					if (rd(ctx, strings + no, name, sizeof(name)) != 0) return (-1);
					named = memcmp(name, CAPIMAGE_ELF_SECTION, sizeof(name)) == 0;
				}
				uint64_t npos = CI_U(sh + (is64 ? 24 : 16), is64 ? 8 : 4);
				uint64_t nlen = CI_U(sh + (is64 ? 32 : 20), is64 ? 8 : 4);
				if (CI_U(sh + 4, 4) == 7 && nlen >= 20 && capimage_elf_range(npos, 20, size)) {
					if (rd(ctx, npos, nh, 20) != 0) return (-1);
					typed = CI_U(nh, 4) == 5 && CI_U(nh + 8, 4) == CAPIMAGE_ELF_NOTE_TYPE && memcmp(nh + 12, "5BSD", 5) == 0;
				}
				if (!named && !typed) continue;
				if (!named || !typed) return (-1);
				noteindex = i;
				if (++found != 1 || CI_U(sh + 4, 4) != 7 ||
				    CI_U(sh + 8, is64 ? 8 : 4) != 0 ||
				    CI_U(sh + (is64 ? 16 : 12), is64 ? 8 : 4) != 0 ||
				    CI_U(sh + (is64 ? 48 : 32), is64 ? 8 : 4) != 4 ||
				    CI_U(sh + (is64 ? 40 : 24), 4) != 0 ||
				    CI_U(sh + (is64 ? 44 : 28), 4) != 0 ||
				    CI_U(sh + (is64 ? 56 : 36), is64 ? 8 : 4) != 0)
					return (-1);
				noteoff = CI_U(sh + (is64 ? 24 : 16), is64 ? 8 : 4);
				notesize = CI_U(sh + (is64 ? 32 : 20), is64 ? 8 : 4);
			}
		}
	}
	if (!marked && !found) return (0);
	/* Discover advertised signatures even above the verification size limit.
	 * Sparse appends must not downgrade signed objects to unsigned. */
	if (!marked || size > CAPIMAGE_FILE_MAX) return (-1);
	version = capimage_elf_uint(footer + 8, 4, 1);
	if (capimage_elf_uint(footer + 12, 4, 1) != 0 ||
	    version != CAPIMAGE_VERSION) return (-1);
	out->version = version; out->header_size = es;
	out->descriptor_offset = capimage_elf_uint(footer + 16, 8, 1);
	out->descriptor_size = capimage_elf_uint(footer + 24, 8, 1);
	if (out->descriptor_offset < es || out->descriptor_size < 113 ||
	    out->descriptor_size > 112 + CAPIMAGE_POLICY_MAX + 88 ||
	    !capimage_elf_range(out->descriptor_offset, out->descriptor_size, size - 32) ||
	    rd(ctx, out->descriptor_offset, h, sizeof(h)) != 0 ||
	    memcmp(h, "5BSDSIG", 8) != 0 || capimage_elf_uint(h + 8, 4, 1) != version)
		return (-1);
	uint64_t policy = capimage_elf_uint(h + 12, 4, 1);
	if (policy == 0 || policy > CAPIMAGE_POLICY_MAX ||
	    out->descriptor_size != 112 + policy + 88) return (-1);
	{
		if (found != 1 || noteindex != sn - 1 || noteoff % 4 != 0 ||
		    noteoff + 20 != out->descriptor_offset ||
		    notesize != 20 + ((out->descriptor_size + 3) & ~UINT64_C(3)) ||
		    !capimage_elf_range(noteoff, notesize, size - 32) ||
		    rd(ctx, noteoff, nh, sizeof(nh)) != 0 || CI_U(nh, 4) != 5 ||
		    CI_U(nh + 4, 4) != out->descriptor_size ||
		    CI_U(nh + 8, 4) != CAPIMAGE_ELF_NOTE_TYPE ||
		    memcmp(nh + 12, "5BSD\0\0\0", 8) != 0 ||
		    rd(ctx, out->descriptor_offset + 112 + policy, orig, sizeof(orig)) != 0 ||
		    memcmp(orig, "5BSDORIG", 8) != 0 ||
		    capimage_elf_uint(orig + 8, 4, 1) != CAPIMAGE_VERSION ||
		    capimage_elf_uint(orig + 12, 4, 1) != es) return (-1);
		out->original_size = capimage_elf_uint(orig + 16, 8, 1);
		memcpy(out->original_header, orig + 24, 64);
		if (out->original_size < es || out->original_size > noteoff ||
		    noteoff != ((out->original_size + 3) & ~UINT64_C(3))) return (-1);
		memcpy(expected, out->original_header, 64);
		/* Only section table locator fields may differ. */
		memcpy(expected + (is64 ? 40 : 32), eh + (is64 ? 40 : 32), is64 ? 8 : 4);
		memcpy(expected + (is64 ? 58 : 46), eh + (is64 ? 58 : 46), 6);
		if (memcmp(expected, eh, 64) != 0) return (-1);
		uint64_t os = CI_U(out->original_header + (is64 ? 40 : 32), is64 ? 8 : 4);
		unsigned on = CI_U(out->original_header + (is64 ? 60 : 48), 2);
		unsigned oi = CI_U(out->original_header + (is64 ? 62 : 50), 2);
		if (sn > 8192 || so < noteoff + notesize ||
		    so + (uint64_t)sn * ss != size - 32) return (-1);
		if (CI_U(str + 8, is64 ? 8 : 4) != 0 ||
		    CI_U(str + (is64 ? 16 : 12), is64 ? 8 : 4) != 0 ||
		    strings != noteoff + notesize || strings_size > CAPIMAGE_POLICY_MAX + sizeof(CAPIMAGE_ELF_SECTION) ||
		    so != ((strings + strings_size + 7) & ~UINT64_C(7))) return (-1);
		if (out->original_size >= 32) {
			if (rd(ctx, out->original_size - 32, old, 32) != 0) return (-1);
			if (memcmp(old, "5BSDEND", 8) == 0) return (-1);
		}
		if (on == 0) {
			if (os != 0 || oi != 0 || sn != 3 || si != 1 ||
			    strings_size != sizeof("\0.shstrtab") + sizeof(CAPIMAGE_ELF_SECTION)) return (-1);
			if (rd(ctx, so, old, ss) != 0) return (-1);
			for (unsigned i = 0; i < ss; i++) if (old[i] != 0) return (-1);
			if (rd(ctx, strings, old, sizeof("\0.shstrtab")) != 0 ||
			    memcmp(old, "\0.shstrtab", sizeof("\0.shstrtab")) != 0) return (-1);
		} else {
			if (on >= 8192 || sn != on + 1 || oi == 0 || oi >= on || si != oi ||
			    CI_U(out->original_header + (is64 ? 58 : 46), 2) != ss ||
			    !capimage_elf_range(os, (uint64_t)on * ss, out->original_size)) return (-1);
			/* Existing section entries are preserved, except shstrtab storage. */
			for (unsigned i = 0; i < on; i++) {
				if (rd(ctx, os + (uint64_t)i * ss, old, ss) != 0 ||
				    rd(ctx, so + (uint64_t)i * ss, expected, ss) != 0) return (-1);
				if (i == oi) {
					uint64_t oldoff = CI_U(old + (is64 ? 24 : 16), is64 ? 8 : 4);
					uint64_t oldsize = CI_U(old + (is64 ? 32 : 20), is64 ? 8 : 4);
					if (CI_U(old + 8, is64 ? 8 : 4) != 0 || oldsize == 0 ||
					    oldsize > CAPIMAGE_POLICY_MAX || strings_size != oldsize + sizeof(CAPIMAGE_ELF_SECTION) ||
					    !capimage_elf_range(oldoff, oldsize, out->original_size)) return (-1);
					uint8_t a[64], b[64];
					for (uint64_t at = 0; at < oldsize;) {
						size_t take = oldsize - at < sizeof(a) ? (size_t)(oldsize - at) : sizeof(a);
						if (rd(ctx, oldoff + at, a, take) != 0 || rd(ctx, strings + at, b, take) != 0 ||
						    memcmp(a, b, take) != 0) return (-1);
						at += take;
					}
					memcpy(old + (is64 ? 24 : 16), expected + (is64 ? 24 : 16), is64 ? 16 : 8);
				}
				if (memcmp(old, expected, ss) != 0) return (-1);
			}
		}
		if (strings < noteoff + notesize || strings + strings_size > so)
			return (-1);
	}
	limit = out->original_size;
	/* All original program-backed bytes remain inside the restored image. */
	uint64_t po = CI_U(eh + (is64 ? 32 : 28), is64 ? 8 : 4);
	unsigned pn = CI_U(eh + (is64 ? 56 : 44), 2), ps = is64 ? 56 : 32;
	if ((CI_U(eh + 16, 2) != 2 && CI_U(eh + 16, 2) != 3) ||
	    CI_U(eh + (is64 ? 52 : 40), 2) != es || pn == 0 || pn > 4096 ||
	    CI_U(eh + (is64 ? 54 : 42), 2) != ps ||
	    !capimage_elf_range(po, (uint64_t)pn * ps, limit)) return (-1);
	for (unsigned i = 0; i < pn; i++) {
		if (rd(ctx, po + (uint64_t)i * ps, sh, ps) != 0 ||
		    !capimage_elf_range(CI_U(sh + (is64 ? 8 : 4), is64 ? 8 : 4),
		    CI_U(sh + (is64 ? 32 : 16), is64 ? 8 : 4), limit)) return (-1);
		if (CI_U(sh, 4) == 4) {
			uint64_t off = CI_U(sh + (is64 ? 8 : 4), is64 ? 8 : 4);
			uint64_t end = off + CI_U(sh + (is64 ? 32 : 16), is64 ? 8 : 4);
			unsigned count = 0;
			while (off < end) {
				if (++count > 8192 || !capimage_elf_range(off, 12, end) || rd(ctx, off, nh, 12) != 0) return (-1);
				uint64_t name = CI_U(nh, 4), desc = CI_U(nh + 4, 4), type = CI_U(nh + 8, 4);
				off += 12;
				if (!capimage_elf_range(off, (name + 3) & ~UINT64_C(3), end)) return (-1);
				if (name == 5 && (type == CAPIMAGE_NOTE_TYPE || type == CAPIMAGE_ELF_NOTE_TYPE)) {
					if (rd(ctx, off, old, 5) != 0) return (-1);
					if (memcmp(old, "5BSD", 5) == 0) return (-1);
				}
				off += (name + 3) & ~UINT64_C(3);
				if (!capimage_elf_range(off, (desc + 3) & ~UINT64_C(3), end)) return (-1);
				off += (desc + 3) & ~UINT64_C(3);
			}
		}
	}
#undef CI_U
	return (1);
}
/* Two small read windows amortize section/name and old/new table traversal.
 * Storage is fixed (1 KiB), no allocations and no retained file descriptors.
 * The callback and caller's vnode/snapshot lifetime still own consistency. */
struct capimage_elf_window {
	capimage_elf_read_t reader;
	void *context;
	uint64_t size, offset[2];
	size_t length[2];
	unsigned next;
	uint8_t bytes[2][512];
};
static inline int
capimage_elf_window_read(void *arg, uint64_t offset, void *data, size_t size)
{
	struct capimage_elf_window *w = arg;
	uint8_t *p = data;
	if (!capimage_elf_range(offset, size, w->size)) return (-1);
	while (size != 0) {
		unsigned slot;
		for (slot = 0; slot < 2; slot++)
			if (offset >= w->offset[slot] && offset - w->offset[slot] < w->length[slot]) break;
		if (slot == 2) {
			slot = w->next; w->next ^= 1;
			w->offset[slot] = offset & ~UINT64_C(511);
			uint64_t remain = w->size - w->offset[slot];
			w->length[slot] = remain < 512 ? (size_t)remain : 512;
			if (w->reader(w->context, w->offset[slot], w->bytes[slot], w->length[slot]) != 0) return (-1);
		}
		w->next = slot ^ 1;
		size_t at = (size_t)(offset - w->offset[slot]);
		size_t take = w->length[slot] - at;
		if (take > size) take = size;
		memcpy(p, w->bytes[slot] + at, take);
		p += take; offset += take; size -= take;
	}
	return (0);
}
static inline int
capimage_elf_probe(capimage_elf_read_t rd, void *ctx, uint64_t size,
    struct capimage_elf_info *out)
{
	struct capimage_elf_window w;
	memset(&w, 0, sizeof(w));
	w.reader = rd; w.context = ctx; w.size = size;
	return (capimage_elf_probe_impl(capimage_elf_window_read, &w, size, out));
}
#endif
