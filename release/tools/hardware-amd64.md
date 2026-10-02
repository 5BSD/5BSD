# Initial amd64 installer hardware profile

The first ISO and USB image use the committed 5BSD source baseline plus the
installer/release changes, and a pinned ports revision. The base kernel, its
modules and external module packages must be built from that same source and
configuration. Raw firmware remains separately packaged data; it is selected
and tested with the driver release, not compiled against a kernel ABI.

## Included components

| Area | Included in the image | Source |
| --- | --- | --- |
| Graphics | Intel `i915kms`, AMD `amdgpu`, legacy `radeonkms` when supported by the selected DRM release; complete matching Intel/AMD/Radeon firmware collection | `graphics/drm-kmod`, `graphics/gpu-firmware-kmod` |
| Intel Wi-Fi | Base `iwm`/`iwn` support and firmware; the iwlwifi firmware families provided by the pinned ports tree | Base packages and `net/wifi-firmware-kmod` |
| Realtek Wi-Fi | Base `rtwn`, `rtw88`, `rtw89` modules where enabled; corresponding firmware | Base packages and Wi-Fi metaport |
| Qualcomm/Atheros Wi-Fi | Base `ath` support; ath10k/ath11k/ath12k firmware carried for the devices whose drivers are present in the selected kernel | Base packages and Wi-Fi metaport |
| MediaTek/Ralink Wi-Fi | Base supported Ralink devices; mt76-family and USB MT7601U firmware | Base packages and Wi-Fi metaport |
| Bluetooth | Base Bluetooth stack and firmware loaders, Intel `iwmbt-firmware` and Realtek `rtlbt-firmware`, including supported OEM USB IDs | Base packages; `comms/iwmbt-firmware`, `comms/rtlbt-firmware` |
| Wired networking | Drivers and bundled firmware supplied by the base release, including its Intel, Realtek, Broadcom, Chelsio and Mellanox support | Kernel and base firmware packages |
| Storage and peripherals | Base NVMe, AHCI/SATA, supported SAS/HBA, USB storage, keyboard/mouse, audio and other base drivers | Kernel and base packages |
| Virtual machines | Base VirtIO networking/block devices and other included virtual hardware drivers | Kernel and base packages |

The build profile is `hardware-ports.amd64`. It uses the full Wi-Fi metaport,
not its reduced `release` flavor. The exact expanded package list, versions,
checksums and package kinds are emitted in `hardware.json`. Device-ID-based
selection installs needed packages from that offline collection onto the target.
Bluetooth selection follows the base firmware loaders' supported IDs; generic
Realtek USB devices must expose Bluetooth interface 0 to be selected. It must
not identify every Realtek USB peripheral as Bluetooth.

## Inclusion versus support

Including firmware does not create a driver or make a newer chipset work.
Some firmware collections contain blobs for hardware unsupported by the
selected kernel. The published hardware-support list must report actual
qualification separately from the package inventory. In particular, do not
advertise every Intel Arc generation, every AMD GPU, or every Wi-Fi 6/7 device
merely because its firmware appears in a package.

The first qualification targets include AMD Hawk Point graphics (PCI
`1002:1900`), Intel Alder Lake graphics, at least one supported Intel Wi-Fi
adapter, and a supported USB Wi-Fi adapter. Hawk Point firmware selection
shares the Phoenix1 IP-block packages; a successful package build is not
a substitute for booting and checking DRM attachment on that hardware.
Expand the tested list with AMD graphics, Realtek Wi-Fi and Intel/Realtek
Bluetooth hardware as available. A VM boot/install test covers installation
logic and virtual drivers, not physical radio or graphics initialization.

NVIDIA proprietary drivers, additional vendor drivers such as Broadcom Wi-Fi,
and CPU microcode update policy are separate release profiles pending their
own integration and qualification. ARM board boot firmware belongs to that
board's image profile, not this amd64 ISO. Keep vendor firmware license files
with the packages and use ports' redistribution rules when publishing media.

## Release gates

- Build the complete profile against the frozen source/ports revisions.
- Check fwget device mappings against the produced package closure.
- Verify live installer networking and an offline target installation.
- Verify graphics and radios after booting the installed system.
- Test a coordinated kernel/module upgrade; ensure raw firmware can remain
  installed independently when the kernel changes.
- Publish the qualified-device list, package inventory, image checksums and
  signed repositories with the ISO and USB image.
