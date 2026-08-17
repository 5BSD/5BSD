/*
 * VFS operation latency — lookup/create/remove/rename timing.
 *
 * Traces the kernel VFS layer (VOP functions) rather than
 * syscalls, giving a filesystem-level view of latency.
 */

fbt::VOP_LOOKUP:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "lookup";
}

fbt::VOP_CREATE:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "create";
}

fbt::VOP_REMOVE:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "remove";
}

fbt::VOP_RENAME:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "rename";
}

fbt::VOP_READ:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "read";
}

fbt::VOP_WRITE:entry
/* @bsdinstruments-predicate */
{
    self->vop_ts = timestamp;
    self->vop_name = "write";
}

fbt::VOP_LOOKUP:return,
fbt::VOP_CREATE:return,
fbt::VOP_REMOVE:return,
fbt::VOP_RENAME:return,
fbt::VOP_READ:return,
fbt::VOP_WRITE:return
/self->vop_ts/
{
    this->elapsed_us = (timestamp - self->vop_ts) / 1000;
    @latency[execname, self->vop_name] = quantize(this->elapsed_us);
    self->vop_ts = 0;
    self->vop_name = 0;
}

dtrace:::END
{
    printf("\n--- VFS operation latency (us) by process/operation ---\n");
    printa(@latency);
}
