# Service daemon status

The authoritative pre-v1 architecture and implementation roadmap is
[`service-architecture-plan.md`](service-architecture-plan.md).

The previous version of this file described a systemd-like dependency graph,
targets, and per-script rc ingestion.  That proposal is superseded.  The
current design has no hard or soft dependency language: IPC, sockets, timers,
path events, explicit administrative requests, and a bounded boot event create
demand directly.

Current implementation and qualification evidence are maintained in:

- [`capability-components-validation.md`](capability-components-validation.md)
- [`capability-daemon-test-suite.md`](capability-daemon-test-suite.md)
- [`capability-components-roadmap.md`](capability-components-roadmap.md)
- [`book/src/system/serviced.md`](book/src/system/serviced.md)
- [`book/src/system/rc-integration.md`](book/src/system/rc-integration.md)

Until the demand-driven phases land, serviced continues to run `/etc/rc` as
one transitional boot job and the current native bundle implementation may
still contain internal startup-edge code.  That code is migration work, not a
compatibility contract.
