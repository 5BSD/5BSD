# Raspberry Pi 4 and Zero 2 W Wi-Fi: LinuxKPI implementation plan

Date: 2026-09-13. Source review only; no driver build or hardware test performed.
Local baseline: `94f8977baab591037d1727c505bcd3a0f83be6c2`.
Scope: onboard Wi-Fi on Raspberry Pi 4 Model B and Raspberry Pi Zero 2 W,
initially station mode. Implementation remains pending. Shared fixes below
apply to both boards; the Zero 2 W and delivery sections add board-specific work.

## Findings

The target is the BCM43455/CYW43455 family, driven by Linux **brcmfmac over
SDIO**, with brcmutil and firmware. This is a FullMAC device: firmware handles
the wireless MAC/association work, and the driver exposes cfg80211 operations
and an Ethernet net_device. It does not use the mac80211 driver interface.
The existing LinuxKPI mac80211 bridge therefore does not complete this port.

We already have the imported driver, module scaffolding, device-tree sources,
native SDHCI, and an MMCCAM SDIO bus. The major work is a Linux SDIO adapter,
a functional FullMAC cfg80211/net80211 bridge, and net_device packet/lifecycle
integration. Some host power/interrupt work is outside LinuxKPI.

FreeBSD does have brcmfmac source and development support. Its
[2026 Q2 wireless report](https://lists.freebsd.org/archives/freebsd-announce/2026-July/000296.html)
still describes firmware loading with cfg80211 and netdev integration missing.
The [Q1 report](https://lists.freebsd.org/archives/freebsd-announce/2026-April/000240.html)
specifies PCIe for that firmware-loading milestone and describes an unpublished
LinuxKPI SDIO implementation, with interrupt and speed work outstanding.
Neither milestone establishes working onboard Pi 4 SDIO Wi-Fi. These are dated
upstream reports, not a verification of every September development branch.
The separate [native brcmfmac project](https://github.com/narqo/freebsd-brcmfmac)
lists BCM43455 as a target but labels itself experimental; its README's tested
platform is a PCIe MacBook. Do not treat that as Pi 4 validation.

## Linux driver and board wiring

Local driver: `sys/contrib/dev/broadcom/brcm80211/`.
The module selects LinuxKPI version 70000; the latest local driver import is
`117d9331fed` (2026-04-19). Preserve that version as the initial port baseline;
Linux master is a reference, not an interchangeable set of API definitions.

| Component | Role and required scope |
|---|---|
| `brcmfmac/bcmsdh.c`, `sdio.c` | SDIO function attachment, chip/backplane access, firmware transfer, interrupt service and data transport |
| `brcmfmac/bcdc.c`, `fwsignal.c` | SDIO control/data protocol and firmware flow control |
| `brcmfmac/cfg80211.c`, `core.c`, `fweh.c`, `fwil.c` | Wireless operations, network interface, asynchronous events and firmware commands |
| `brcmfmac/firmware.c`, `of.c` | Firmware/NVRAM selection and board properties |
| `brcmutil`, firmware-vendor subdrivers | Shared helpers and vendor-specific firmware handling already represented in the module scaffolding |

The local arm64 Pi 4 DTS includes the ARM source. Relevant files are
`sys/contrib/device-tree/src/arm/broadcom/bcm2711-rpi-4-b.dts` and
`bcm283x-rpi-wifi-bt.dtsi` in the same directory:

- `&sdhci` supplies Wi-Fi over four SDIO data lines on GPIO34–39, with
  `non-removable`, enabled status, and `mmc-pwrseq`.
- Its `wifi@1` child has `reg = <1>` and `compatible = "brcm,bcm4329-fmac"`.
  This is a family binding, not evidence that the chip is a BCM4329.
- `wifi-pwrseq` uses `mmc-pwrseq-simple`; the Pi 4 sets
  `reset-gpios = <&expgpio 1 GPIO_ACTIVE_LOW>`. That firmware GPIO is WL_ON.
- `&emmc2` is the SD-card controller; do not confuse it with the Wi-Fi host.
- Bluetooth is a separate UART child with its own enable GPIO. Making
  brcmfmac work does not implement Bluetooth transport or firmware loading.

There is a significant downstream distinction: the
[Raspberry Pi rpi-6.18.y DTS](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/broadcom/bcm2711-rpi-4-b.dts)
later deletes `wifi-pwrseq` and enables `&mmcnr`, after additional vendor includes.
Inspect the actual bootloader-provided, overlay-modified DTB before selecting
host glue or changing nodes. The imported mainline description alone does not
prove what our image boots. Compare against
[Linux mainline Pi 4 DTS](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm/boot/dts/broadcom/bcm2711-rpi-4-b.dts).

## Required additions and fixes

### 1. Linux MMC/SDIO compatibility over the native bus

Confirmed: `sys/compat/linuxkpi/common/include/linux/mmc/` is absent.
Add the required `sdio.h`, `sdio_ids.h`, `sdio_func.h`, `card.h`, `host.h`,
`core.h` and supporting definitions based on the imported driver's actual uses.
Implement a kernel adapter, for example `common/src/linux_sdio.c`, over
`sys/dev/sdio/` and `sys/cam/mmc/`.

Required semantics include:

- `sdio_driver` registration, ID matching, probe/remove, driver data, and device
  parentage; Linux `mmc_card`, `mmc_host`, and `sdio_func` object lifetimes.
- Shared card ownership for functions 1 and 2. `brcmf_ops_sdio_probe()` accepts
  function 1, starts the device on function 2, and retrieves function 1 through
  `card->sdio_func[0]`. Native SDIO also represents function 0: translate indices
  explicitly and make all sibling objects available before invoking probe.
- Host claim/release with Linux-compatible serialization and callback context.
  Individual CAM request locking is not a substitute for an atomic sequence of
  backplane-window selection and subsequent transfers.
- Function enable/disable, block sizing, function-0 and ordinary register I/O,
  CMD52/CMD53, fixed-address FIFO versus incrementing-address memory transfers,
  byte/block modes, alignment, transfer limits, timeouts and error translation.
- `sdio_readl/writel`, `sdio_readsb`, `sdio_memcpy_fromio/toio`, and the other
  accessors used by the driver and its headers.
- Scatter/gather request support used by `bcmsdh.c`: `mmc_wait_for_req`,
  `mmc_set_data_timeout`, and host limits. A conservative copy/linear-transfer
  implementation may be a first step only if it preserves framing and limits.
- `sdio_claim_irq/release_irq`: native card-interrupt enable, pending-function
  dispatch, rearming and synchronized teardown. The current `sdio_if.m` only
  exposes direct/extended reads and writes, so bus work is also needed.
- Reset (`mmc_hw_reset`), host PM capability/flags and retuning APIs. For a first
  implementation, accurately report unsupported PM capabilities; do not claim
  wake-on-wireless or power retention through empty success stubs.

Reuse `sdiob.c`: it already enumerates functions before attachment and performs
CAM-backed direct/extended transfers. `usr.bin/sdiotool/linux_sdio_compat.c` is
userspace diagnostic precedent, not the missing kernel adapter. Native
`sdiob_detach()` currently returns `EOPNOTSUPP`; reliable lifecycle work must
include the native bus as well as LinuxKPI.

### 2. A FullMAC cfg80211 bridge to net80211

This is a substantial functional addition, not just missing declarations.
In `common/include/net/cfg80211.h`, `cfg80211_scan_done`,
`cfg80211_connect_done`, `cfg80211_disconnected`, and `wiphy_unregister` are
TODO stubs. `linuxkpi_80211_wiphy_register()` in `common/src/linux_80211.c`
annotates bands and returns success without a complete FullMAC attachment.

Add a separate FullMAC integration path that can reuse shared cfg80211 helpers
without requiring a mac80211 `ieee80211_hw`/`ieee80211_ops` driver:

- Create/destroy wiphy, wireless_dev, interface and net80211 VAP associations.
- Translate native scan requests into cfg80211 driver operations; import BSS
  results, channel/security IEs and signal units; deliver scan completion/abort.
- Translate connect/disconnect, authentication settings, keys and default-key
  selection. Deliver connection results, link loss and relevant firmware events
  to native state handling and the existing supplicant interface.
- Define ownership of association, roaming and packet encryption: firmware
  performs these operations, and net80211 must not run a competing software MAC
  state machine or encrypt the already-offloaded traffic again.
- Implement regulatory/channel restrictions, station information and supported
  capability reporting. Leave AP, P2P, scheduled scans and WoWLAN unadvertised
  until their paths work.
- Audit structure fields and numeric flags: the header has explicit brcmfmac
  placeholders, including `WIPHY_PARAM_*` values based on `__LINE__`.
- Document locking and callback lifetimes across taskqueues, cfg80211 events,
  net80211 state transitions and firmware command waits.

### 3. Functional net_device data and lifecycle support

`common/include/linux/netdevice.h` has TODO receive and unregister functions,
including `netif_rx()`. Existing NAPI and sk_buff infrastructure is useful but
does not provide the FullMAC interface by itself.

Implement interface registration/removal, ndo open/stop/start_xmit dispatch,
Ethernet mbuf/sk_buff conversion, ownership on success/error, RX delivery,
carrier notifications, queue stop/wake and backpressure, multicast filters,
MAC address and statistics. Ensure EAPOL reaches the supplicant and key setup
completes before ordinary protected traffic. Drain work, IRQ callbacks, TX and
firmware events before freeing objects.

### 4. OF properties and native board power integration

`common/include/linux/of.h` contains only a kobject include; `linux/clk.h` is
absent. The imported `brcmfmac/of.c` requires real property/node APIs, optional
clock handling, MAC-address lookup and optional interrupt parsing.

Implement the used subset over native OFW/FDT: root compatible for board type,
property string/bool/u32 readers, compatible matching, node references and
`of_get_mac_address`. Attach `wifi@1` to the correct SDIO function's Linux
device. Support optional country maps, drive strength and LPO clock semantics.
Missing optional properties must behave like absence, not attach failure.
Only implement/use an out-of-band host-wake IRQ if the actual board DT describes
one; the imported shared node has none, so in-band SDIO IRQ support matters.

Reuse native `mmc_pwrseq.c` and firmware GPIO support. A concrete host issue:
`bcm2835_sdhci.c` calls `mmc_fdt_parse()`, but `bcm_sdhci_update_ios()` toggles
regulators directly and does not call `mmc_fdt_set_power()` or the power-sequence
interface. Wire the correct sequencing into the actual selected host, with
proper ordering and error handling. Validate cold boot without depending on
firmware having left WL_ON asserted. Also check four-bit/high-speed negotiation,
DMA/cache handling and interrupt routing on the MMCCAM path.

### 5. Firmware and build integration

`common/src/linux_firmware.c` already implements synchronous/asynchronous
requests through FreeBSD firmware(9). Reuse it; package/register names that
match brcmfmac's requests and preserve fallback/error and callback lifetimes.

The local SDIO firmware table selects the `brcmfmac43455-sdio` family. Provide
the chip firmware `.bin`, Pi 4 board NVRAM (normally
`brcm/brcmfmac43455-sdio.raspberrypi,4-model-b.txt`), and matching `.clm_blob`
when supplied/required by the firmware set. Preserve board-specific selection,
calibration and regulatory data; a binary by itself is not a complete package.
The exact requested fallbacks should be logged during bring-up. Firmware(9)
registration is required; copying files into a Linux-style directory alone
does not establish availability to this loader.

`sys/modules/brcm80211/brcmfmac/Makefile` already builds `if_brcmfmac` with
PCI enabled, SDIO/USB/OF disabled. Its SDIO branch requires `MMCCAM` and selects
`sdio.c`, `bcmsdh.c`, BCDC and firmware flow control. Enable SDIO and OF for the
Pi target after their dependencies exist; include brcmutil/vendor components,
generated SDIO interfaces and LinuxKPI dependencies. Add the module to the
appropriate build/image selection: the top-level module list does not currently
select brcm80211. `sys/arm64/conf/GENERIC-MMCCAM` is an existing test baseline;
switching MMC stacks also requires validating boot storage and root mounting.

## Ordered implementation tasks and acceptance criteria

1. **Capture board baseline.** Record board revision, effective DTB, selected
   Wi-Fi controller, GPIO/clock state and SDIO identity. Review available
   upstream SDIO work before recreating it. Keep the initial Linux import fixed.
2. **Power and native SDIO.** Cold-boot enumeration of functions 1/2; repeatable
   CMD52/CMD53 reads/writes; correct four-bit operation; working interrupt
   delivery/rearming. Confirm SD-card boot still works with MMCCAM.
3. **Linux SDIO and firmware.** Compile the SDIO/BCDC/OF module configuration;
   probe both functions; select the Pi NVRAM; download firmware; read firmware
   version and complete repeated control transactions. Exercise missing-firmware
   and transfer-timeout cleanup. This milestone does not yet mean usable Wi-Fi.
4. **FullMAC station interface.** Native interface creation; repeated scan and
   cancellation; WPA2 association through the normal supplicant; key install;
   DHCP, IPv4/IPv6 and bidirectional traffic on supported channels: 2.4 GHz on
   Zero 2 W and 2.4/5 GHz on Pi 4.
5. **Reliability.** Reconnect after AP loss, queue pressure, sustained traffic,
   cold/warm reboot, firmware recovery and unload/reload where supported.
   Verify no callback uses freed state. Run a smoke test on an existing
   mac80211 LinuxKPI driver after changing shared wireless/netdev helpers.
6. **Later capabilities.** Tune bus speed/aggregation and power saving; implement
   and test AP/P2P/WoWLAN separately before advertising them.

The principal architectural dependency is the FullMAC bridge. SDIO attachment
and successful firmware loading can be developed first, but neither bypasses
the missing cfg80211/netdev behavior.


## Zero 2 W: board, radio revisions and firmware

The Zero 2 W also uses **brcmfmac over SDIO with BCDC**. The LinuxKPI SDIO,
FullMAC cfg80211, net_device, OF and firmware work above is shared. It does not
require a separate wireless driver. Its SYN43436 radio variants expose
BCM43430 chip/revision identities; the exact payload depends on the revision.

The [Zero 2 W specification](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/)
includes 512 MB RAM and 2.4 GHz 802.11b/g/n. Use the BCM2837/arm64 platform for
initial bring-up. This target is distinct from the original Zero W, and must
not advertise Pi 4's 5 GHz support.

| Property | Pi 4 Model B | Zero 2 W |
|---|---|---|
| Driver / transport | brcmfmac / SDIO / BCDC | Same shared implementation |
| Radio | BCM43455/CYW43455 family | SYN43436 variants, BCM43430 identities |
| Root DT compatible | `raspberrypi,4-model-b` | `raspberrypi,model-zero-2-w` |
| Wi-Fi host in imported DTS | `&sdhci`, GPIO34–39 | `&sdhci`, `emmc_gpio34` pin group |
| WL_ON reset | Firmware expander pin 1, active low | SoC GPIO41, active low |
| Additional Wi-Fi pinmux | Check board clock setup | `gpclk2_gpio43` / WIFI_CLK |
| Boot SD host in imported DTS | `&emmc2` | `&sdhost`, GPIO48–53 |
| Bluetooth enable | Firmware expander pin 0 | SoC GPIO42 |

### Device tree, clock and storage fixes

The Zero 2 W source already exists at
`sys/contrib/device-tree/src/arm/broadcom/bcm2837-rpi-zero-2-w.dts`, with an
arm64 include wrapper. It includes the same `bcm283x-rpi-wifi-bt.dtsi` as Pi 4,
inheriting the non-removable four-bit host, `wifi@1` and simple power sequence.
The [Raspberry Pi Linux DTS](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/broadcom/bcm2837-rpi-zero-2-w.dts)
also selects GPIO41 reset and the additional GPIO43 clock pinmux. Several
internal GPIO line-name comments say NC; use the actual pinctrl references for
host configuration rather than treating those comments as absent SDIO wiring.

Required board work:

- Apply the shared SDHCI power-sequence fix using the direct GPIO41 provider.
  Resolve provider attachment before reset/enumeration, preserve polarity and
  delays, and test a cold boot without depending on a prior OS's power state.
- Validate GPIO43 clock source, rate and enable state. Pinmux does not generate
  a clock. Native `bcm2835_clkman_set_frequency()` currently only accepts
  `BCM_PWM_CLKSRC`, so its presence does not establish GPCLK2 support. If boot
  firmware does not supply a stable clock contract, add native GPCLK2 control
  and a proper DT clock provider/consumer path. Do not infer a frequency from
  the GPIO label or assume brcmfmac's optional LPO API configures this pin.
- Preserve SD-card `sdhost` while using SDHCI for Wi-Fi. Native
  `bcm2835_sdhost.c` uses the SDHCI framework and has MMCCAM conditionals;
  validate its CAM path and root-disk naming when switching kernels.
- Validate bounded queues and allocations with 512 MB RAM during firmware
  download, scanning, memory pressure and sustained traffic.

### S/P variants and exact firmware requests

[Raspberry Pi PCN38](https://pip-assets.raspberrypi.com/categories/1163-pcn/documents/RP-009258-PC-2-PCN38,%20Raspberry%20Pi%20Zero%202W%20Change%20to%20use%20the%2043436P%20wireless%20device.pdf)
documents a change from SYN43436S to SYN43436P starting 2025-11-01, with both
variants available during transition. Its identification method distinguishes
BCM43430/1 from BCM43430/2 in firmware logs. Record runtime identity: the board
product name is insufficient for selecting the wireless payload.

Our imported `brcmfmac/sdio.c` already maps BCM43430 revision 1 to
`brcmfmac43430-sdio`, and revision 2 (and later revisions under its mask) to
`brcmfmac43430b0-sdio`. Absence of a literal 43436 chip-table entry does not
establish a missing chip implementation.

Raspberry Pi supplies board-specific aliases to select the payloads. These
symlink targets were read from the firmware repository's `bookworm` branch,
Git tree `c91cd2804cf7463aab913e7247c176049f16bbd6`, on 2026-09-13:

| Driver request below `brcm/` | Payload |
|---|---|
| `brcmfmac43430-sdio.raspberrypi,model-zero-2-w.bin` | `brcmfmac43436s-sdio.bin` |
| `brcmfmac43430-sdio.raspberrypi,model-zero-2-w.txt` | `brcmfmac43436s-sdio.txt` |
| `brcmfmac43430b0-sdio.raspberrypi,model-zero-2-w.bin` | `brcmfmac43436-sdio.bin` |
| `brcmfmac43430b0-sdio.raspberrypi,model-zero-2-w.txt` | `brcmfmac43436-sdio.txt` |
| `brcmfmac43430b0-sdio.raspberrypi,model-zero-2-w.clm_blob` | `brcmfmac43436-sdio.clm_blob` |

Source: [Raspberry Pi firmware aliases](https://github.com/RPi-Distro/firmware-nonfree/tree/bookworm/debian/config/brcm80211/brcm).
The current default `trixie` branch places the corresponding files under
[`debian/added-firmware/brcm`](https://github.com/RPi-Distro/firmware-nonfree/tree/trixie/debian/added-firmware/brcm);
do not use the old repository-root `brcm/` path as a current packaging manifest.
Pin the selected package revision and record payload hashes and licenses when
packaging the firmware. The alias table is packaging evidence, not hardware
validation of every radio revision.

Register these exact board aliases with firmware(9), including the module
autoload mapping. Linux filesystem symlinks do not create firmware(9)
registrations. Preserve board-first fallback and never globally substitute
Zero 2 W firmware for generic BCM43430 firmware. Verify the optional CLM
requests actually made by this driver version and their adequacy for the
selected payload. Do not assume every variant needs a newly named 43436P file.

FreeBSD's incomplete cfg80211/netdev and SDIO integration described above also
blocks this board. The presence of its DTS and imported chip support does not
establish a working onboard interface. The separate native BCM43455 project
cited above is not evidence of Zero 2 W support.

## Concrete implementation and delivery checklist

All tasks are open. New filenames below are suggested implementation targets.
Dependencies identify functional ordering; compilation scaffolding can be
prepared before the dependent hardware milestones are complete.

| ID | Change and primary files | Dependencies | Completion evidence |
|---|---|---|---|
| W1 | Record effective DTBs, overlays, radio IDs and firmware revisions on both boards | None | Reproducible boot manifests and serial logs, including Zero 2 W S/P identities |
| W2 | Fix reset/power in `bcm2835_sdhci.c`, `mmc_fdt_helpers.c`, `mmc_pwrseq.c`; resolve provider ordering and GPIO43 clock if needed | W1 | Cold-boot enumeration and working SD-card root |
| W3 | Complete native IRQ dispatch/rearming and lifecycle in `sys/dev/sdio/`, `sys/dev/sdhci/`, `sys/cam/mmc/` | W2 | Repeated IRQ-driven transfers without deadlock, interrupt storms or late callbacks |
| W4 | Add `linux/mmc/*` and `common/src/linux_sdio.c`: driver matching, sibling objects, host locking, CMD52/53 and MMC request translation | W3 | Both functions attach; backplane/control transfers succeed |
| W5 | Implement used OF/clock APIs, function-to-DT mapping and resource lifetime in LinuxKPI | W1 | Correct board type, MAC and optional-property handling |
| W6 | Package both boards' firmware, NVRAM, CLM and firmware(9) aliases | W1, W5 | Correct payload selected for each revision; firmware version query and missing-file cleanup work |
| W7 | Implement FullMAC cfg80211/net80211 bridge, e.g. `common/src/linux_cfg80211.c`, and complete relevant header structures/flags | W4–W6 for hardware validation | Native VAP, scan, connection and key events without mac80211 driver ops |
| W8 | Complete `linux_netdev.c`, `linux/netdevice.h` and skb/mbuf integration | W7 for end-to-end validation | EAPOL, key exchange and bidirectional traffic with queue control |
| W9 | Enable SDIO/BCDC/OF in `sys/modules/brcm80211/`; register added LinuxKPI sources/dependencies in module lists and `sys/conf/files*`; add a Pi MMCCAM config | W4–W8 for final build | arm64 kernel/modules compile and link; required modules enter the image |
| W10 | Extend Pi 4 image integration and add a Zero 2 W image profile in `release/tools/` | W9 | Both images boot SD and contain firmware and normal wireless configuration tools |
| W11 | Run the hardware acceptance matrix and document setup/support limits | W10 | Recorded test results, image/package hashes and logs for every supported variant |

Inspect available FreeBSD SDIO development patches before implementing W3/W4.
The dated upstream report establishes prior work, not a public patch location
or permission to assume it is finished. Reuse compatible pieces after review.
Firmware download can be achieved through W2–W6 plus the partial W9 build;
working packet flow still requires W7/W8.

### Image integration fixes

`release/tools/rpi4-zfs.conf` currently copies only Pi 4 boot assets and a Pi 4
DTB, uses `dtoverlay=mmc`, and disables Bluetooth with `dtoverlay=disable-bt`.
It neither packages these Wi-Fi payloads nor explicitly configures a wireless
VAP. Its default DHCP setting alone is not a complete wireless setup.

- Pi 4: inspect post-overlay host ownership under `dtoverlay=mmc` and ensure
  simultaneous SD-card/Wi-Fi access. Supply the MMCCAM kernel, `if_brcmfmac`,
  shared dependencies and the firmware modules in the image manifest.
- Zero 2 W: create a distinct profile with its board DTB, boot firmware,
  compatible U-Boot build and loader configuration. Do not copy the Pi 4
  `start4.elf`, `fixup4.dat` or GIC armstub selection. Verify the selected boot
  chain on the board.
- The imported DTS is not an installed DTB: `sys/modules/dtb/rpi/Makefile`
  currently builds SPI overlays only. Explicitly package the validated DTB
  from the selected source/firmware package and record its provenance.
- Start the 512 MB Zero 2 W with a modest UFS root as an implementation choice;
  validate any ZFS profile separately. The Pi 4 ZFS artifact is not evidence
  that the same image/profile will boot Zero 2 W.
- Once the actual native parent name is known, document normal
  `wlans_<parent>`, `ifconfig_wlan0="WPA DHCP"`, country/regulatory selection
  and a user-supplied supplicant configuration. Include the required tools
  without embedding credentials in build artifacts.
- Bluetooth remains a separate task if requested: UART HCI attachment,
  revision-specific patchram firmware, baud/flow control, BT_ON and coexistence.
  The current Pi 4 profile explicitly disables it; enabling Wi-Fi cannot fix it.

### Hardware acceptance matrix

Run on Pi 4, Zero 2 W BCM43430/1 and Zero 2 W BCM43430/2. Mark unavailable or
untested variants explicitly; do not extrapolate full board coverage from one.

- Cold/warm boot, GPIO reset and reliable SD-card root mounting.
- Exact firmware/NVRAM selection and valid MAC without wrong-board fallback.
- Scan/cancel, WPA2 association, wrong-password failure, reconnect after AP
  loss, DHCP, IPv4/IPv6, multicast/broadcast and sustained bidirectional data.
- 2.4 GHz on all targets, 5 GHz on Pi 4 only; enforce actual regulatory and
  firmware capabilities instead of hardcoding advertised bands/rates.
- Allocation pressure on Zero 2 W, queue pressure, SDIO timeout/recovery,
  interrupt rearming and removal/reload where supported.
- Smoke-test an existing mac80211 LinuxKPI driver after shared helper changes.

Save serial logs, effective DTB, source/config revision, module/firmware hashes
and outcomes with each image. Build success and firmware download are
intermediate milestones. Native wireless configuration and stable packet flow
are the criteria for delivering these drivers.
