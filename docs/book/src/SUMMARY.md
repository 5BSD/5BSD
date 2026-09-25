# Summary

[Introduction](introduction.md)

# Part I: Orientation

- [What 5BSD Is](orientation/what-5bsd-is.md)
- [From Power-On to Login](orientation/boot-to-login.md)
- [How to Read This Book](orientation/how-to-read.md)

# Part II: The Capability System

- [The MAC Capability Framework](capability/mac-capability.md)
- [Coalitions and Accounting](capability/coalitions-and-accounting.md)
- [Capability Mode and the Born-Sandboxed Launch](capability/capability-mode-and-launch.md)
- [Descriptor and Process Protections](capability/descriptor-protections.md)
- [The Authority Model](capability/authority-model.md)
- [Policy Points](capability/policy-points.md)
- [System Gates](capability/system-gates.md)
- [Attribute-Based Access Control (mac_abac)](capability/mac-abac.md)
- [Endpoint Security (OES)](capability/oes.md)
- [Verified Execution](capability/veriexec.md)

# Part III: The Plane

- [Capsule, PID 1](plane/capsule.md)
- [Switchboard](plane/switchboard.md)
- [Bundles and Manifests](plane/bundles-and-manifests.md)
- [Discovery and the Lookup Channel](plane/discovery-and-lookup.md)
- [Containers and Storage](plane/containers-and-storage.md)
- [Anointments and Principal Policy](plane/anointments.md)
- [The Management Model](plane/management-model.md)
- [Logging, Audit and Trace](plane/logging-audit-trace.md)

# Part IV: System Capabilities Reference

- [How to Read a Provider Chapter](providers/overview.md)
- [system.Filesystem (BSDFilesystem)](providers/filesystem.md)
- [system.Log (BSDLog)](providers/log.md)
- [system.Audit (BSDAudit)](providers/audit.md)
- [system.Auth (BSDAuth)](providers/auth.md)
- [system.Crypto (BSDCrypto)](providers/crypto.md)
- [system.Network (BSDNetwork)](providers/network.md)
- [system.Device (BSDDevice)](providers/device.md)
- [system.Notify (BSDNotify)](providers/notify.md)
- [system.Sysctl (BSDSysctl)](providers/sysctl.md)
- [system.Time (BSDTime)](providers/time.md)
- [system.Power (BSDPower)](providers/power.md)
- [system.SystemExtension (BSDExtension)](providers/extension.md)
- [system.Namespace (BSDNamespace)](providers/namespace.md)
- [system.Trace (BSDTrace)](providers/trace.md)
- [system.VM (BSDVM)](providers/vm.md)
- [system.Bluetooth (BSDBluetooth)](providers/bluetooth.md)

# Part V: Backward Compatibility

- [The BSD Side](compat/bsd-side.md)
- [rc and service(8)](compat/rc-and-service.md)
- [Sessions: login, su, ssh and cron](compat/sessions.md)
- [Jails](compat/jails.md)
- [Packages and Ports](compat/packages.md)
- [Virtual Machines](compat/virtual-machines.md)
- [Linux Emulation](compat/linux/overview.md)
    - [System Calls](compat/linux/syscalls.md)
    - [io_uring and squeue](compat/linux/io-uring.md)
    - [procfs, sysfs and the Filesystem View](compat/linux/procfs-sysfs.md)
    - [Sandboxing and Debugging](compat/linux/sandboxing.md)
    - [Running Real Applications](compat/linux/running-apps.md)

# Part VI: Writing Software for 5BSD

- [Choosing What to Write](develop/choosing.md)
- [A Capability Provider](develop/provider.md)
- [A Consumer Application](develop/consumer-app.md)
- [A Per-User Agent](develop/per-user-agent.md)
- [Migrating an rc Daemon](develop/migrating-an-rc-daemon.md)
- [A Linux Application](develop/linux-application.md)
- [A Device Driver Bundle](develop/device-driver-bundle.md)
- [A Kernel Extension](develop/kernel-extension.md)
- [Testing](develop/testing.md)
- [Packaging and Shipping](develop/packaging.md)

# Part VII: Operations

- [Building](operations/building.md)
- [Installing](operations/installing.md)
- [Upgrading](operations/upgrading.md)
- [Boot Knobs](operations/boot-knobs.md)
- [Observability](operations/observability.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Tool Reference](operations/tools.md)

# Appendices

- [Glossary of Names](appendix/glossary.md)
- [Manual Page Index](appendix/man-index.md)
- [System Calls and Sysctls](appendix/syscalls-and-sysctls.md)
- [Design Document Index](appendix/design-docs.md)
