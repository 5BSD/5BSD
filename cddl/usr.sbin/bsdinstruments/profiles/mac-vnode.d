/*
 * MAC Framework vnode checks — file access control decisions.
 *
 * Traces Mandatory Access Control checks on file operations:
 * open, exec, read, write, unlink, rename, lookup, mmap.
 * Non-zero returns indicate a MAC policy denied the operation.
 * Requires a MAC policy module loaded (e.g., mac_bsdextended).
 */

fbt::mac_vnode_check_open:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "open";
}

fbt::mac_vnode_check_exec:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "exec";
}

fbt::mac_vnode_check_read:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "read";
}

fbt::mac_vnode_check_write:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "write";
}

fbt::mac_vnode_check_unlink:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "unlink";
}

fbt::mac_vnode_check_rename_from:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "rename";
}

fbt::mac_vnode_check_lookup:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "lookup";
}

fbt::mac_vnode_check_mmap:entry
/* @bsdinstruments-predicate */
{
    self->mac_ts = timestamp;
    self->mac_op = "mmap";
}

fbt::mac_vnode_check_open:return,
fbt::mac_vnode_check_exec:return,
fbt::mac_vnode_check_read:return,
fbt::mac_vnode_check_write:return,
fbt::mac_vnode_check_unlink:return,
fbt::mac_vnode_check_rename_from:return,
fbt::mac_vnode_check_lookup:return,
fbt::mac_vnode_check_mmap:return
/self->mac_ts && arg1 != 0/
{
    printf("%s[%d]: MAC DENIED vnode %s err=%d\n",
        execname, pid, self->mac_op, arg1);
    @denied[execname, self->mac_op] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    self->mac_ts = 0;
    self->mac_op = 0;
}

fbt::mac_vnode_check_open:return,
fbt::mac_vnode_check_exec:return,
fbt::mac_vnode_check_read:return,
fbt::mac_vnode_check_write:return,
fbt::mac_vnode_check_unlink:return,
fbt::mac_vnode_check_rename_from:return,
fbt::mac_vnode_check_lookup:return,
fbt::mac_vnode_check_mmap:return
/self->mac_ts && arg1 == 0/
{
    @allowed[execname, self->mac_op] = count();
    self->mac_ts = 0;
    self->mac_op = 0;
}

dtrace:::END
{
    printf("\n--- MAC vnode denials ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-10s %@8d\n", @denied);
    printf("\n--- MAC vnode allowed ---\n");
    printa("%-20s %-10s %@8d\n", @allowed);
}
