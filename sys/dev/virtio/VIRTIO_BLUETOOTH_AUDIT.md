# VirtIO Bluetooth Local Audit

Date: 2026-07-13

Scope: local VirtIO device identification, PCI transport readiness, and the
existing Bluetooth virtual-controller infrastructure.

## Findings

| Area | Local state | Result |
| --- | --- | --- |
| Device ID | `VIRTIO_ID_BT` was missing while the table already included the adjacent GPIO ID. | Added ID 40 and a `Bluetooth` entry so modern PCI probe descriptions can identify the device type. |
| PCI transport | `sys/dev/virtio/pci/virtio_pci_modern.c` already probes modern and transitional devices, validates required vendor capabilities, maps common/notify/ISR/device config areas, negotiates `VIRTIO_F_VERSION_1`, and supports reset/reinit/virtqueue lifecycle. | No local transport rewrite was justified without a failing capability case or normative conformance test. |
| Bluetooth virtual HCI | The tree has netgraph virtual HCI support through `ng_hci_virt`, `vhcitool`, and `tests/sys/netgraph/vhci_test.sh`. | This is useful emulator coverage for the Bluetooth stack, but it is not a virtio-bluetooth device implementation. |
| VirtIO Bluetooth driver | No `sys/dev/virtio/bluetooth` driver or module exists. | Remaining work is a new kernel driver tied to the virtio Bluetooth device chapter: feature negotiation, virtqueue layout, packet path, reset/error recovery, and emulator-backed tests. |

## Blockers

- No local virtio specification file is checked in under `/usr/src`; the only
  confirmed local source is the existing kernel VirtIO framework.
- A correct virtio-bluetooth driver needs the normative device-specific queue
  and feature definitions plus a test/emulator target.  The current `ng_hci_virt`
  stack cannot prove virtio transport behavior by itself.

## Verified

```sh
env MAKEOBJDIRPREFIX=/tmp/obj make -C sys/modules/virtio/virtio -j2
```
