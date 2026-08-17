/*
 * bhyve VMM audit — VM lifecycle and I/O activity.
 *
 * Traces bhyve virtual machine monitor operations via kernel
 * FBT probes. Shows VM entry/exit, vmexit reasons, and I/O
 * handling. Requires bhyve/vmm.ko loaded.
 * FreeBSD-specific.
 */

fbt:vmm:vm_run:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vm_run\n", execname, pid);
    @vm_runs[execname] = count();
}

fbt:vmm:vm_exit_process:entry
/* @bsdinstruments-predicate */
{
    @vm_exits[execname] = count();
}

fbt:vmm:vm_handle_inst_emul:entry
/* @bsdinstruments-predicate */
{
    @vm_emul[execname, "inst_emul"] = count();
}

fbt:vmm:vm_handle_hlt:entry
/* @bsdinstruments-predicate */
{
    @vm_emul[execname, "hlt"] = count();
}

fbt:vmm:vm_handle_paging:entry
/* @bsdinstruments-predicate */
{
    @vm_emul[execname, "paging"] = count();
}

fbt:vmm:vlapic_fire_timer:entry
/* @bsdinstruments-predicate */
{
    @vm_emul[execname, "lapic_timer"] = count();
}

syscall::ioctl:entry
/execname == "bhyve" /* @bsdinstruments-predicate-and *//
{
    @bhyve_ioctls[execname] = count();
}

dtrace:::END
{
    printf("\n--- VM run count ---\n");
    printa("%-30s %@d\n", @vm_runs);
    printf("\n--- VM exit count ---\n");
    printa("%-30s %@d\n", @vm_exits);
    printf("\n--- VM exit reasons ---\n");
    printa("%-20s %-14s %@d\n", @vm_emul);
    printf("\n--- bhyve ioctl count ---\n");
    printa("%-30s %@d\n", @bhyve_ioctls);
}
