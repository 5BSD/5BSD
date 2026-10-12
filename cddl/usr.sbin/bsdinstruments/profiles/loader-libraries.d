/* Loader library loads, cache decisions and timings (profiling rtld required).
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
dtrace:::BEGIN
{
    printf("ELFPROFILE_BEGIN\t2\n");
}
syscall::utrace:entry
/arg1 == 704 && stringof(copyin(arg0, 8)) == "ECLOAD2" /* @bsdinstruments-predicate-and */ /
{
    this->event = (struct ec_profile *)copyin(arg0, 704);
    printf("ELFLOAD2\t%llu\t%u\t%u\t%S\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%S\t%S\t%S\n",
        (unsigned long long)timestamp, pid, tid, execname,
        this->event->flags, this->event->reason, (unsigned long long)this->event->bytes,
        (unsigned long long)this->event->lookup_ns, (unsigned long long)this->event->cache_ns,
        (unsigned long long)this->event->map_ns,
        (unsigned long long)this->event->device, (unsigned long long)this->event->inode,
        stringof(this->event->path), stringof(this->event->requested),
        stringof(this->event->consumer));
}
dtrace:::ERROR
{
    printf("ELFPROFILE_ERROR\t%u\t%u\n", arg1, arg4);
}
dtrace:::END
{
    printf("ELFPROFILE_END\t2\n");
}
