# Summary

[Introduction](introduction.md)

# Platform

- [Architecture Overview](architecture.md)
- [The Linuxulator](linuxulator.md)

# Security

- [MAC Capability Framework](security/mac-capability.md)
- [The Authority Model](security/authority-model.md)
- [The Authentication Boundary](security/session-mint.md)
- [Attribute-Based Access Control (mac_abac)](security/mac-abac.md)
- [Capability Transfer](security/capability-transfer.md)
- [Capability Bundles](security/capability-bundles.md)
- [Process Protections](security/process-protections.md)
- [Descriptor Types](security/descriptors.md)
- [Endpoint Security (OES)](security/endpoint-security.md)
- [auditbrokerd (BSM Audit Broker)](security/auditbrokerd.md)
- [Cryptographic Services](security/crypto.md)

# Developer Guide

- [The Hybrid Model: BSD plus a Capability SDK](development/hybrid-model.md)
- [Writing a Service Provider](development/writing-components.md)
- [Using Process Protections](development/using-protections.md)

# Virtualization (WASPNest)

- [WASPNest Overview](virtualization/overview.md)
- [VirtIO Device Models](virtualization/virtio.md)
- [vsock](virtualization/vsock.md)
- [Live Migration and Nested VMX](virtualization/migration-nested.md)
- [Qualification and Testing](virtualization/qualification.md)

# Bluetooth

- [Bluetooth Stack Overview](bluetooth/overview.md)
- [blued](bluetooth/blued.md)
- [BLE Mesh](bluetooth/mesh.md)

# Storage

- [TrustedZFS](storage/trustedzfs.md)
- [tzfsd Storage Broker](storage/tzfsd.md)

# System Services

- [Capability Filesystem Hierarchy](system/capability-hier.md)
- [Capsule (PID 1)](system/capsule.md)
- [serviced](system/serviced.md)
- [BSDNotify](system/bsdnotify.md)
- [localnetwork (Network Broker)](system/localnetwork.md)
- [rc Integration](system/rc-integration.md)
- [Service Manifests](system/manifests.md)

# Observability

- [ObservableBSD](observability/observablebsd.md)
- [DTrace and Hardware Tracing](observability/dtrace.md)
- [traced (DTrace Capability Broker)](observability/traced.md)

# Operations

- [Building 5BSD](operations/building.md)
- [Packaging (pkgbase)](operations/packaging.md)
- [Release Engineering](operations/releases.md)
- [Tool Reference](operations/tools.md)
