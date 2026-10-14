# PF callback lifetime evidence

The preserved DDB trace at `/usr/obj/5BSD-pf-parity/vms/dut-ddb20.log`
reports a write after free in a 4096-byte `M_DEVBUF` allocation at offset
64. The panic happened when a later `pfsync_clone_create()` caused the
allocator to inspect the old allocation. It does not contain the writer's
stack or instruction. Offset 64 is `sc_ltask.t_vnet` in the old
`pfsync_softc`; `task_add()` writes `t_vnet` before queueing a task. A stale
link hook is therefore a plausible writer, not a proved one.

`pfsync_up()` registers `sc_ltask` for link events and `sc_dtask` for detach
events on its sync interface. Both task objects and their callback argument
live in `pfsync_softc`. The link callback accesses the softc directly; the
detach callback calls `pfsync_down()`. PF also registers an address task in
`pfi_attach_ifnet()`; that task is owned by its `pfi_kif` and freed in
`pfi_detach_ifnet()`.

The FreeBSD event handlers in `pf_freebsd.c` send link/address events to
`obsd_ifhooks_run()` and send a departure event there before
`pfi_detach_ifnet()`. On ordinary detach the interface is already
`IFF_DYING`, so `pfsync_down()` cannot rely on `if_get()` to find and remove
the old registration. On a VNET move `IFF_DYING` need not be set. The hook
registry must close additions and remove/drain every kind of task while its
owners remain alive. The departure callback may then stop pfsync; after it
returns PF can release its address task. Separately, `pfsync_down()` must
close timer/task scheduling, wait for each callout and queued task, and only
then allow `pfsync_clone_destroy()` to free the softc.

The VM lifecycle test covers detach, VNET move, down/up, and destroy. It
checks that the repaired path survives those operations; it cannot identify
the original writer without a captured write stack.
