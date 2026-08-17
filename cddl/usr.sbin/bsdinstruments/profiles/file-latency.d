/*
 * File operation latency — quantize slow open/read/write/stat/fsync.
 *
 * Measures per-syscall latency for common file operations and
 * aggregates as histograms by syscall name. Identifies which
 * file operations are slow and how slow they are.
 */

syscall::open:entry,
syscall::openat:entry,
syscall::read:entry,
syscall::write:entry,
syscall::pread:entry,
syscall::pwrite:entry,
syscall::stat:entry,
syscall::fstat:entry,
syscall::lstat:entry,
syscall::fstatat:entry,
syscall::fsync:entry,
syscall::fdatasync:entry,
syscall::close:entry
/* @bsdinstruments-predicate */
{
    self->file_ts = timestamp;
}

syscall::open:return,
syscall::openat:return,
syscall::read:return,
syscall::write:return,
syscall::pread:return,
syscall::pwrite:return,
syscall::stat:return,
syscall::fstat:return,
syscall::lstat:return,
syscall::fstatat:return,
syscall::fsync:return,
syscall::fdatasync:return,
syscall::close:return
/self->file_ts/
{
    this->elapsed_us = (timestamp - self->file_ts) / 1000;
    @latency[execname, probefunc] = quantize(this->elapsed_us);
    @slow[execname, probefunc] = max(this->elapsed_us);
    self->file_ts = 0;
}

dtrace:::END
{
    printf("\n--- File operation latency (us) by process/syscall ---\n");
    printa(@latency);
    printf("\n--- Max latency (us) by process/syscall ---\n");
    printa("%-20s %-14s %@d\n", @slow);
}
