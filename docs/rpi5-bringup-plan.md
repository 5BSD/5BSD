# Raspberry Pi 5 bring-up plan for 5BSD

Status: DRAFT — research complete, implementation not started
Date: 2026-08-12
Scope: everything needed to boot and run 5BSD on the Raspberry Pi 5
(BCM2712 C1/D0, 2/4/8/16 GB), from serial-console single-user to a
self-hosting multi-user system with storage, USB, and onboard Ethernet.

---

## 1. Executive summary

The Pi 5 is not "another Raspberry Pi." Broadcom built BCM2712 out of
their set-top-box (STB) IP portfolio, and Raspberry Pi moved nearly all
board I/O off-SoC into **RP1**, a custom southbridge attached over a
PCIe 2.0 x4 endpoint. Almost none of our existing bcm2835/2711 driver
stack applies. The tree today has **zero BCM2712/RP1 driver code**; the
only Pi 5 artifacts present are the device-tree sources from the Linux
6.16 import (`sys/contrib/device-tree/src/arm64/broadcom/bcm2712*`,
`rp1*`). Upstream FreeBSD is in the same position — no committed kernel
work — so nothing is waiting to be merged; we write this ourselves.

The good news:

- **OpenBSD 7.8 (Oct 2025) shipped a complete native port** (kettenis@,
  mglocker@). Their driver set is small, well-factored, and maps almost
  1:1 onto drivers we already have or can port. It is our primary
  reference alongside Linux.
- The big-ticket peripherals are **licensed standard IP**, not Broadcom
  custom: Ethernet is Cadence GEM (we have `if_cgem`), USB is Synopsys
  DWC3 → xHCI (we have both cores), SD is SDHCI with brcmstb quirks (we
  have the SDHCI framework), UARTs are PL011 (we have `uart_dev_pl011`),
  the GIC is a plain GIC-400/GICv2 (driver present).
- FreeBSD 15 already boots multi-user on Pi 5 via the community EDK2
  UEFI firmware in ACPI mode (USB, NVMe, SD, HDMI work; no onboard
  Ethernet). That gives us a **day-one validation platform** while we do
  the native FDT port.

The genuinely new work is concentrated in three places: the **BCM2712
PCIe root complex** (brcmstb variant), the **MIP MSI-X→GIC-SPI
translator** (BCM2712 has no ITS), and the **RP1 bus driver** that maps
the southbridge BAR, demuxes its 61 MSI-X vectors, and enumerates its
peripherals as an FDT sub-bus. Once those three exist, most of the rest
is glue onto existing drivers.

Recommended shape: **five phases**, each ending in a bootable milestone.
Estimated total: roughly 10–14 engineer-weeks to Phase 3 (multi-user
with Ethernet/USB/SD via native FDT boot), with Phase 4 polish ongoing.

---

## 2. Hardware overview (what we're targeting)

### 2.1 BCM2712 SoC

| Block | Detail | 5BSD status |
|---|---|---|
| CPU | 4x Cortex-A76 r4p1 @ 2.4 GHz, DynamIQ DSU, 512K private L2/core, 2 MB L3, crypto extensions (unlike BCM2711) | Works as-is; no A76 r4p1 errata in Linux's list |
| Interrupts | **GIC-400 (GICv2)**, no ITS. STB L2 cascade intcs (`brcm,bcm7271-l2-intc`, `brcm,bcm2711-l2-intc`) for UART/BSC/AON | GICv2 driver present (`sys/arm/arm/gic.c`); L2 intc driver: **new** |
| MSI | Two **MIP** widgets (`brcm,bcm2712-mip`): MSI writes → GIC SPIs. mip0 = 64 vectors (SPI 128–191, serves pcie2/RP1), mip1 = 8 vectors | **New driver** (small; Linux `irq-bcm2712-mip.c`, OpenBSD `bcm2712_mip.c`) |
| Timer | ARM generic timer, CNTFRQ = 54 MHz set by firmware stub | Works as-is |
| SMP | PSCI 1.0 via SMC (TF-A-derived stub embedded in EEPROM bootloader); kernel entered at **EL2** | Works as-is (`sys/dev/psci`) |
| SD/eMMC | `brcm,bcm2712-sdhci` / `brcm,sdhci-brcmstb` @ 0x10_00FFF000 (SD slot, SDR104, CQE) + second instance @ 0x10_01100000 for SDIO WiFi | SDHCI core present; **brcmstb glue new** |
| PCIe | 3x `brcm,bcm2712-pcie` (brcmstb DWC): pcie1 = external FPC connector (Gen2, Gen3 via dtparam), pcie2 = x4 to RP1, pcie0 unused | **New driver** (relative: Pi 4 `bcm2838_pci.c` in tree; OpenBSD extended their Pi 4 driver in place) |
| GPIO | STB GPIO (`brcm,brcm7445-gpio`): `gio` (WL_ON/BT_ON/power button) + `gio_aon` (SD card-detect, ACT LED) | **New driver** (small) |
| Pinctrl | `brcm,bcm2712c0-pinctrl` (mainline) / `brcm,bcm2712-pinctrl` (downstream) | **New driver** |
| Console UART | **uart10**: on-SoC PL011 @ 0x10_7D001000, GIC SPI 121, **fixed 9.216 MHz uartclk**, 3-pin JST-SH debug connector; `stdout-path = serial10` | `uart_dev_pl011` present — must verify it takes the clock from FDT, not an assumed constant |
| Mailbox/firmware | Same VideoCore mailbox as always (`brcm,bcm2835-mbox` @ 0x10_7C013880) + property channel; firmware clocks are load-bearing (HVSt/HDMI/V3D) | `bcm2835_mbox.c`/`bcm2835_firmware.c` present — need address/offset audit on 2712 |
| Misc | RESCAL PCIe/SATA reset-cal (`brcm,bcm7216-pcie-sata-rescal`), STB reset, RNG200, `brcm,bcm2711-thermal`, watchdog `brcm,bcm2712-pm`, RTC in DA9091 PMIC via firmware mailbox only | Mostly small new glue; RNG200/thermal have near relatives in Linux only |

Steppings: original boards are **C1**; the 2 GB/16 GB/Pi 500 use **D0**,
which needs different DTBs (`bcm2712-d-rpi-5-b.dtb`) and, with vendor
firmware, `bcm2712d0.dtbo` + `overlay_map.dtb` present or even the UART
doesn't come up (bit OpenBSD during bring-up). Plan on having one board
of each stepping in the test pool.

Page size: Raspberry Pi OS defaults to 16K pages for ~5% perf; **4K
pages are fully supported by the hardware** — no pmap work needed.

### 2.2 RP1 southbridge

- PCIe 2.0 x4 **endpoint** (PCI ID `1de4:0001`) on BCM2712 pcie2.
  BAR1 = ~4 MB peripheral window, BAR2 = 64 KB SRAM.
- **Firmware**: none loaded by the OS. The VideoCore bootloader uploads
  RP1 firmware over I2C and trains the link before the kernel runs; by
  kernel entry RP1 is alive.
- **All RP1 interrupts are MSI-X**: 61 vectors, one per peripheral,
  landing in mip0. Level-triggered sources need an **IACK write** to the
  RP1 PCIE APB block (base 0x108000 in BAR1) after each interrupt to
  re-arm — miss this and level IRQs fire exactly once.
- Register-access nicety: every 4 KB register block has +0x1000 XOR,
  +0x2000 set, +0x3000 clear aliases — use them to avoid read-modify-
  write round trips over PCIe.
- DMA note: BCM2712's inbound PCIe windows are **non-identity** — DRAM
  appears at PCIe address 0x10_0000_0000. The PCIe RC driver must
  program inbound windows accordingly and the `dma-ranges` translation
  must flow through `busdma` correctly (OpenBSD hit a double-translation
  bug here; see their `bcm2711_pcie.c` r1.14).

RP1 peripheral inventory and what serves it:

| Peripheral | IP | 5BSD driver plan |
|---|---|---|
| Ethernet (1GbE) | **Cadence GEM_GXL** + BCM54213PE PHY (RGMII, delays must be configured) | Adapt `sys/dev/cadence/if_cgem.c` (OpenBSD reused their cad(4) the same way); brgphy for the PHY |
| USB 3.0 x2 | **Synopsys DWC3** (host-only, xHCI 1.2) | RP1 glue onto existing `sys/dev/usb/controller/dwc3/` + xhci |
| GPIO/pinctrl | RP1-custom, 3 banks (bank0 = 40-pin header) | **New driver** (Linux `pinctrl-rp1.c`, OpenBSD `rpigpio.c`) |
| UARTs x6 | ARM PL011 | Existing `uart_dev_pl011` once RP1 bus enumerates them |
| SPI x9 | Synopsys DW APB SSI | New small driver or port (check for reusable DW SSI code in tree) |
| I2C x7 | Synopsys DesignWare I2C | Same — DW I2C glue |
| PWM x2 | RP1-custom (**the fan** is pwm1 ch3) | New small driver (OpenBSD `rpipwm.c`) |
| Clocks | RP1-custom clock controller | New clkdev driver (OpenBSD `rpiclock.c`) |
| SDIO x2 | DWC MSHC — **not** the SD slot (that's on-SoC) | Defer |
| I2S, MIPI CSI/DSI, VEC/DPI, ADC, PIO, DMA | various | Defer (Phase 4+/out of scope) |

### 2.3 Boot flow

Boot ROM (VPU) → SPI-EEPROM bootloader (has start.elf equivalent
embedded; **no start4.elf-style files on Pi 5**) → loads payload named
by `kernel=` in config.txt from FAT (or NVMe/USB/TFTP per EEPROM
`BOOT_ORDER`) → payload entered at EL2 with firmware-patched DTB.

Three viable OS boot paths:

1. **Firmware → U-Boot → EFI loader → kernel** (OpenBSD's path, and our
   existing Pi 3/4 image layout). Mainline U-Boot has booted Pi 5 since
   v2024.04 (`rpi_arm64_defconfig`); **BCM2712 PCIe landed in U-Boot
   v2026.07**, so U-Boot can now reach NVMe and RP1 xHCI/USB storage.
   Still no RP1 Ethernet in U-Boot (no netboot). DTB comes from the
   vendor firmware, passed through U-Boot's EFI DTB table.
2. **Firmware → EDK2 UEFI (worproject/NumberOneGit rpi5-uefi) → loader
   → kernel in ACPI mode.** Works with stock FreeBSD 15 today: PCIe/
   NVMe, USB, SD (slow), HDMI. No onboard Ethernet, C1-only for the
   archived original (the NumberOneGit fork handles D0). Great harness,
   wrong long-term base: firmware is community-maintained/archived and
   ACPI hides exactly the devices we need to drive (RP1 children).
3. **Firmware → kernel directly** (Linux's path). Fewest moving parts
   long-term, but requires our loader/kernel to be a valid firmware
   payload and `os_check=0` in config.txt. Defer; U-Boot path first.

Decision: **primary path = (1)**, matching `release/arm64/RPI.conf`
conventions (vendor `rpi-firmware` + `u-boot-rpi-arm64` on the FAT
partition). Keep (2) as the bring-up/validation harness from day one.

---

## 3. Current state of play

- **This tree**: solid Pi 3/4 support (`sys/arm/broadcom/bcm2835/`,
  `if_genet`, `bcm2838_pci.c`/`bcm2838_xhci.c`), Linux 6.16 DT import
  including all Pi 5 DTS, `sys/arm64/conf/std.broadcom` with
  `SOC_BRCM_BCM2837/BCM2838`, release machinery in
  `release/arm64/RPI.conf` (Pi 3/4 only, kernel `VBSD`). Fork divergence
  in arm64 is virtualization/CCA/MAC-focused — no conflict with this
  work; the Broadcom code tracks upstream FreeBSD.
- **FreeBSD upstream**: no Pi 5 kernel code, no open reviews. Community
  runs 15.x via EDK2/ACPI. Out-of-tree: **jsm222/rpi5-stuff** (FreeBSD
  dev jsm@) has proof-of-concept brcmstb GPIO + sdhci-brcmstb +
  vcbus patches for a headless native-FDT boot — worth mining, not
  mergeable as-is.
- **OpenBSD 7.8**: complete native port. New drivers:
  `sys/arch/arm64/dev/{rpone.c, bcm2712_mip.c, rpigpio.c, rpiclock.c,
  rpipwm.c, rpirtc.c}` and `sys/dev/fdt/{bcmstbgpio.c, bcmstbintc.c,
  bcmstbpinctrl.c, bcmstbrescal.c, bcmstbreset.c}`; extended
  `bcm2711_pcie.c` for BCM2712 and reused cad(4)/sdhc(4)/xhci(4)/
  bwfm(4). Known gaps at release: no NVMe *boot* (pre-dated U-Boot
  PCIe), D0 WiFi broken.
- **NetBSD**: UEFI-only, no onboard Ethernet, SD broken until -current.
  Their experience is the cautionary tale for stopping at path (2).
- **Linux**: everything supported; mainline merge points that matter to
  us: pcie-brcmstb BCM2712 + MIP irqchip v6.15, RP1 core/pinctrl/clk
  v6.17, brcmstb pinctrl v6.18. Downstream `rpi-6.12.y` remains the
  most complete single reference (RP1 PWM, RTC, thermal DT are still
  downstream-only). Our 6.16 DT import predates the mainline RP1
  static-DT rework (v6.17+) — see §5 Phase 3 note on DTBs.

---

## 4. Strategy

1. **Native FDT port, OpenBSD-shaped.** UEFI/ACPI is a harness, not the
   product: it can never expose RP1 Ethernet, GPIO, PWM, or the fan, and
   the firmware is community-archived. Everything real lives behind the
   PCIe RC + MIP + RP1 triad, so build those.
2. **Reuse aggressively, in this order**: existing 5BSD driver → port of
   OpenBSD's driver (closest architecture: same rman/newbus-ish FDT
   attach world, small, audited) → rewrite from Linux source + RP1
   datasheet (authoritative for register detail).
3. **Vendor DTBs at runtime.** Ship `rpi-firmware` DTBs and let the
   VideoCore bootloader patch and hand them over (memory size, MAC
   addresses, overlays, D0 selection all come free). Our in-tree DT
   import is for compile-time `compatible` validation, not for shipping.
4. **Milestone per phase**, serial-console first, each phase ends in
   something that boots and is CI-able.

---

## 5. Work plan

### Phase 0 — rig + baseline (≈1 week, mostly lab work)

- Acquire boards: 1x Pi 5 C1 stepping (4/8 GB), 1x D0 (2 or 16 GB),
  debug-UART cables (3-pin JST-SH), M.2 HAT, PoE or smart PDU for power
  cycling. Netboot/rpiboot recovery workflow documented.
- Stand up the **EDK2/ACPI baseline**: stock 5BSD arm64 memstick +
  NumberOneGit rpi5-uefi on SD. Expected result (matches FreeBSD 15
  reports): multi-user over HDMI/USB or serial, NVMe root, USB Ethernet
  dongle for network. This validates our generic arm64 kernel on the
  A76/GIC-400 before we write a line of code, and gives developers a
  self-hosting build box.
- Serial/console harness like the existing `~/vm` bhyve rig: console
  server on the debug UART, power-cycle scripting, image-flash script.
- CI: add an arm64 `VBSD` cross-build + Pi 5 image-build smoke target.

Exit: 5BSD multi-user on Pi 5 hardware via UEFI/ACPI, documented.

### Phase 1 — native FDT boot to single-user on SD (≈2–3 weeks)

The kernel comes up via firmware → U-Boot (≥ v2026.07) → loader.efi with
the firmware DTB; serial console; root on SD.

1. **Config plumbing**: add `SOC_BRCM_BCM2712` to
   `sys/arm64/conf/std.broadcom`, wire new files in
   `sys/conf/files.arm64` (follow the BCM2838 pattern, ~lines 624–652).
2. **Console**: verify `uart_dev_pl011` honors the FDT clock property
   (uart10 runs at a fixed 9.216 MHz — a hardcoded 24/48 MHz assumption
   means garbage output). `stdout-path = serial10:115200n8`.
3. **STB L2 interrupt controller** (`brcm,bcm7271-l2-intc` +
   `brcm,bcm2711-l2-intc`): new INTRNG driver; needed for on-SoC UART/
   I2C/AON interrupts. Small (OpenBSD `bcmstbintc.c` is ~200 lines).
4. **STB GPIO** (`brcm,brcm7445-gpio`) for `gio`/`gio_aon`: SD
   card-detect, ACT LED, power button. Reference: OpenBSD
   `bcmstbgpio.c`, jsm's `brcmstb-gpio.c`, Linux `gpio-brcmstb.c`.
5. **STB pinctrl** (`brcm,bcm2712*-pinctrl`): enough to satisfy DT
   `pinctrl-0` references on the devices we touch.
6. **sdhci-brcmstb glue**: new `sys/dev/sdhci/sdhci_brcmstb.c` (or fdt
   compat additions): honor DT `sdhci-caps`/`sdhci-caps-mask` (the
   bootloader supplies capability values — OpenBSD needed this),
   `vmmc-supply`/vqmmc GPIO regulator for 1.8 V switching, card-detect
   via gio_aon. jsm's `sdhci-brcmstb.c` is a working FreeBSD-API
   starting point. Start at HS/50 MHz; SDR104 tuning later.
7. **Audit the legacy bcm2835 stack on 2712**: mailbox/firmware property
   channel (bcm2835_mbox @ new address — vcbus mapping differs; jsm
   patched `bcm2835_vcbus.c`), watchdog/reboot (`brcm,bcm2712-pm`),
   RNG200. Gate what misbehaves behind the SOC option.
8. GENERIC/VBSD boots with GICv2 + generic timer + PSCI out of the box —
   confirm SMP on all 4 cores, EL2 entry handled (it is for Pi 4).

Exit: single-user shell on serial, root on SD, 4 CPUs, clean dmesg.

### Phase 2 — PCIe root complex + MSI (≈2–3 weeks, the hard part)

1. **`pcie-brcmstb` host driver for BCM2712**. Options: extend
   `sys/arm/broadcom/bcm2835/bcm2838_pci.c` (what OpenBSD did to their
   Pi 4 driver) or write `sys/dev/pci/pcie_brcmstb.c` fresh from Linux
   `pcie-brcmstb.c` + OpenBSD r1.15–r1.18. Must handle: RESCAL + STB
   reset sequencing (two more tiny drivers: OpenBSD `bcmstbrescal.c`,
   `bcmstbreset.c`), Gen2/Gen3 link speed from DT, and critically the
   **non-identity inbound `dma-ranges`** (DRAM @ PCIe 0x10_0000_0000) —
   both window programming and busdma translation. OpenBSD's r1.14
   double-translation fix is the known landmine.
2. **MIP MSI driver** (`brcm,bcm2712-mip`): INTRNG MSI/MSI-X provider
   mapping doorbell writes → GIC SPIs (64 + 8 vectors). References:
   Linux `irq-bcm2712-mip.c`, OpenBSD `bcm2712_mip.c`. Wire as
   `msi-parent` for pcie1/pcie2.
3. Validate on **pcie1 (external connector)**: NVMe on the M.2 HAT with
   MSI-X interrupts working. This proves RC + MIP before RP1 exists.

Exit: NVMe HAT works under native FDT boot; `pciconf -lv` sane;
MSI-X interrupts flowing through MIP.

### Phase 3 — RP1 southbridge + the peripherals people actually want (≈3–4 weeks)

1. **RP1 bus driver** (`sys/arm64/broadcom/rp1/rp1.c`, modeled on
   OpenBSD `rpone.c` + Linux `drivers/misc/rp1/rp1_pci.c`): attach to
   PCI `1de4:0001`, map BAR1, allocate 61 MSI-X vectors, expose an
   interrupt controller + simple-bus that enumerates the RP1 DT
   sub-nodes and parents them to the PCI device. Implement the
   **level-IRQ IACK re-arm quirk** in the interrupt path from day one.
   *DTB note*: firmware DTBs (downstream lineage) carry the RP1 subtree
   under pcie2 already; mainline only restructured this in v6.17+. Match
   `compatible` strings against the **vendor** DTB we actually boot
   with, and treat our in-tree 6.16 import as secondary.
2. **RP1 clocks** (`rpiclock.c` equivalent) — children need clkdev.
3. **RP1 GPIO/pinctrl** (`pinctrl-rp1.c` / `rpigpio.c`): 40-pin header,
   and required for Ethernet PHY/LED and UART pinmux.
4. **Ethernet**: adapt **`if_cgem`** (Cadence GEM) for the RP1 GEM_GXL
   instance: `raspberrypi,rp1-gem`/`cdns,macb` compat, fixed 125 MHz
   tx_clk from RP1 clock driver, **RGMII delay configuration for the
   BCM54213PE PHY** (OpenBSD's fix: "configure delays for RGMII PHYs
   correctly"), MDIO + brgphy. This is the single most-demanded feature
   — FreeBSD's #1 Pi 5 complaint is "no NIC".
5. **USB**: RP1 dwc3 glue (`sys/dev/usb/controller/dwc3/rp1_dwc3.c`)
   onto the existing dwc3/xhci core; host-only, 4 MSI-X vectors per
   controller.
6. **RP1 PL011 UARTs** (40-pin header uart0): should attach via
   existing pl011 once bus/clocks exist.
7. **PWM + fan** (`rpipwm.c` equivalent, pwm1 ch3) — trivial once
   clocks/gpio are in, and the fan-at-full-blast noise is what every
   NetBSD reviewer complained about.

Exit: **multi-user, native FDT, onboard GbE, USB3, SD, NVMe, fan
under control.** This is the "supported" announcement bar.

### Phase 4 — platform completeness (ongoing)

- **RTC** via firmware mailbox (DA9091 PMIC; OpenBSD `rpirtc.c`).
- **Thermal** (`brcm,bcm2711-avs-monitor`) → sysctl + fan curve.
- **CPU frequency/DVFS** via firmware clocks (audit
  `bcm2835_cpufreq.c` applicability on 2712).
- **DW I2C + DW APB SSI SPI** on RP1 for the 40-pin header (new small
  controller drivers; check tree for reusable DesignWare code first).
- **Release machinery**: `release/arm64/RPI5.conf` (or extend
  `RPI.conf`): MBR+FAT with `rpi-firmware` ≥ 1.20250430 (ships
  bcm2712 DTBs + `bcm2712d0.dtbo` + `overlay_map.dtb` for D0 boards),
  U-Boot ≥ v2026.07 built for rpi_arm64, `config.txt` with
  `os_check=0`, `kernel=u-boot.bin`, both C1 and D0 DTBs. May need our
  own `u-boot-rpi5`-capable port bump if `u-boot-rpi-arm64` in ports
  lags v2026.07.
- **Docs/man page**: a `pi5(4)`-style platform page; wiki runbook.
- **Stretch / explicitly out of scope for now**: WiFi/BT (BCM43455
  SDIO — no brcmfmac-class driver in tree; upstream lists it
  help-wanted; big independent project), display/KMS (VideoCore VII
  vc4-class stack; UEFI GOP/EFIFB remains the interim console),
  VCHIQ/camera/MIPI, RP1 PIO/ADC/I2S, 16K pages (perf experiment only).

---

## 6. Gotcha checklist (hard-won by others; don't rediscover)

1. PCIe inbound `dma-ranges` are non-identity (DRAM @ 0x10_0000_0000 on
   the bus) — busdma double-translation bit OpenBSD.
2. RP1 level interrupts need the per-source IACK write to
   `RP1_PCIE_APBS` after every MSI or they fire once and go dead.
3. uart10 clock is 9.216 MHz — don't assume a standard PL011 clock.
4. SDHCI capabilities must be read from DT `sdhci-caps`/`sdhci-caps-mask`
   (bootloader-provided), and `vmmc-supply` handling is required later
   for SDIO WiFi power.
5. D0-stepping boards: different DTB (`bcm2712-d-*`), and the firmware
   needs `bcm2712d0.dtbo` + `overlay_map.dtb` on the FAT partition or
   even UART is dead. C1 vs D0 must both be in the test matrix.
6. GEM needs RGMII delay config for the BCM54213PE or the link is dead/
   flaky at gigabit.
7. `config.txt` must exist and be non-empty on Pi 5; set `os_check=0`
   for non-Linux payloads.
8. Kernel enters at EL2; PSCI for secondaries; CNTFRQ pre-set to 54 MHz
   — all standard, but the old bcm2836 local-intc/spin-table paths must
   not engage on 2712.
9. RP1 register blocks have XOR/set/clear aliases at +0x1000/2000/3000 —
   use them; RMW over the PCIe link is slow and racy.
10. Don't ship the in-tree DTBs for Pi 5; boot the firmware-patched
    vendor DTB (memory size, MACs, overlays come from the bootloader).

## 7. Reference code map

| Component | Write/modify in 5BSD | OpenBSD reference | Linux reference |
|---|---|---|---|
| SOC option/config | `sys/arm64/conf/std.broadcom`, `sys/conf/files.arm64` | — | — |
| STB L2 intc | new `sys/arm64/broadcom/bcmstb_l2_intc.c` | `sys/dev/fdt/bcmstbintc.c` | `drivers/irqchip/irq-brcmstb-l2.c` |
| STB GPIO | new | `sys/dev/fdt/bcmstbgpio.c` | `drivers/gpio/gpio-brcmstb.c` |
| STB pinctrl | new | `sys/dev/fdt/bcmstbpinctrl.c` | `drivers/pinctrl/pinctrl-brcmstb-bcm2712.c` |
| SDHCI brcmstb | new glue under `sys/dev/sdhci/` | `sys/dev/fdt/sdhc_fdt.c` r1.22/r1.23 | `drivers/mmc/host/sdhci-brcmstb.c` |
| PCIe RC | extend `bcm2838_pci.c` or new | `sys/dev/fdt/bcm2711_pcie.c` r1.14–r1.18 | `drivers/pci/controller/pcie-brcmstb.c` |
| RESCAL/reset | new tiny drivers | `bcmstbrescal.c`, `bcmstbreset.c` | `reset-brcmstb*.c` |
| MIP MSI | new `sys/arm64/broadcom/bcm2712_mip.c` | `sys/arch/arm64/dev/bcm2712_mip.c` | `drivers/irqchip/irq-bcm2712-mip.c` |
| RP1 bus | new `sys/arm64/broadcom/rp1/` | `sys/arch/arm64/dev/rpone.c` + rpone(4) | `drivers/misc/rp1/rp1_pci.c` (v6.17) / `drivers/mfd/rp1.c` (downstream) |
| RP1 clocks | new | `rpiclock.c` | `drivers/clk/clk-rp1.c` |
| RP1 gpio/pinctrl | new | `rpigpio.c` | `drivers/pinctrl/pinctrl-rp1.c` |
| Ethernet | adapt `sys/dev/cadence/if_cgem.c` | `sys/dev/fdt/if_cad.c` | `drivers/net/ethernet/cadence/macb_main.c` |
| USB glue | new dwc3 glue | (their xhci attaches via rpone fdt bus) | `drivers/usb/dwc3/` |
| PWM/fan | new | `rpipwm.c` | `drivers/pwm/pwm-rp1.c` (downstream) |
| RTC | new | `rpirtc.c` | `drivers/rtc/rtc-rpi.c` (downstream) |
| FreeBSD-API PoC | mine jsm222/rpi5-stuff (gpio/sdhci/vcbus) | — | — |

Primary documents: RP1 peripherals datasheet
(datasheets.raspberrypi.com/rp1/rp1-peripherals.pdf — the only public
datasheet; there is **no** BCM2712 datasheet), Linux `rpi-6.12.y` DTS
(`bcm2712.dtsi`, `rp1.dtsi`), OpenBSD 7.8 announcement
(undeadly.org sid=20250903064251) and plus78.html changelog, FreeBSD
wiki arm/Raspberry Pi 5, U-Boot v2026.07 BCM2712 PCIe series.

## 8. Risks

- **PCIe RC subtleties** (link training, RESCAL ordering, inbound
  windows) are where the schedule slips; budget the extra week in
  Phase 2 and validate on pcie1/NVMe before touching RP1.
- **U-Boot dependency**: NVMe/USB boot needs U-Boot ≥ v2026.07; ports
  tree may need a bump we own.
- **D0 firmware churn**: vendor firmware/EEPROM updates have broken D0
  overlays before; pin known-good `rpi-firmware` versions in the image.
- **WiFi expectations**: onboard WLAN will not work in any near-term
  phase; say so loudly in release notes to preempt the #2 complaint.
- **Fork drift**: all of this is upstreamable to FreeBSD; writing it
  against upstream-compatible APIs keeps the door open and invites
  outside testing (jsm@ and the freebsd-arm crowd are active).
