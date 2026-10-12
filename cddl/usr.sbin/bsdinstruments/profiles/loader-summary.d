/* Loader library frequency and timing aggregates (profiling rtld required).
 * SPDX-License-Identifier: BSD-2-Clause */
/* Run globally in an isolated profiling VM; do not use -p/-c or ktrace.
 * All utrace payloads are untrusted diagnostics. No authority decisions. */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option strsize=256
struct ec_profile {
    char magic[8];
    uint32_t flags;
    uint32_t reason;
    uint64_t bytes;
    uint64_t lookup_ns;
    uint64_t cache_ns;
    uint64_t map_ns;
    uint64_t device;
    uint64_t inode;
    char path[256];
    char requested[128];
    char consumer[256];
};
syscall::utrace:entry
/arg1 == 704 && stringof(copyin(arg0, 8)) == "ECLOAD2" &&
 (*(uint32_t *)copyin(arg0 + 8, 4) & 1) == 0 /* @bsdinstruments-predicate-and */ /
{
    this->event = (struct ec_profile *)copyin(arg0, 704);
    @loads[stringof(this->event->path), this->event->device, this->event->inode, execname,
        this->event->reason, this->event->flags] = count();
    @file_bytes[stringof(this->event->path)] = max(this->event->bytes);
    @lookup_ns[stringof(this->event->path)] = sum(this->event->lookup_ns);
    @cache_check_ns[stringof(this->event->path)] = sum(this->event->cache_ns);
    @map_ns[stringof(this->event->path)] = sum(this->event->map_ns);
}
