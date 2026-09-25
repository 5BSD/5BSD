# Raspberry Pi Wi-Fi hardware testing

These profiles target the Pi 4 Model B and Pi Zero 2 W onboard SDIO radios.
They use the imported Linux brcmfmac driver through LinuxKPI, with a native CAM
SDIO bus and a net80211 station interface. Successful builds and host tests do
not establish that either board boots or associates successfully.

## Build and package

Build on a FreeBSD/5BSD host, using a separate object directory. The kernel must
be `GENERIC-RPI`: a stock kernel using the legacy MMC bus cannot supply this SDIO
transport. Keep the kernel and modules from the same build.

```sh
export MAKEOBJDIRPREFIX=/tmp/rpi-build
make -C /usr/src -j4 buildworld TARGET=arm64 TARGET_ARCH=aarch64
make -C /usr/src -j4 buildkernel TARGET=arm64 TARGET_ARCH=aarch64 \
    KERNCONF=GENERIC-RPI \
    MODULES_OVERRIDE='brcm80211 linuxkpi linuxkpi_wlan linuxkpi_sdio lindebugfs wlan wlan_ccmp wlan_amrr zfs'
```

The explicit module list includes the driver, its LinuxKPI and net80211
providers, WPA2 CCMP, rate control, and Pi 4 ZFS support. Omit
`MODULES_OVERRIDE` to build every module selected by the kernel configuration.
The kernel includes INVARIANTS and WITNESS for the initial tests.

Package this world and kernel with the repository's pkgbase release workflow,
passing the same `TARGET`, `TARGET_ARCH`, `KERNCONF`, object prefix and
`MODULES_OVERRIDE`. The image profiles require pkgbase and reject absent Wi-Fi
modules. Do not combine an existing stock kernel package with these modules.

## Boot assets and radio firmware

Unpack the FreeBSD `rpi-firmware` boot package and a suitable U-Boot package:
`u-boot-rpi4` for Pi 4, or `u-boot-rpi-arm64` for Zero 2 W. Set the following to
actual unpacked directories; Wi-Fi firmware is a separate download:

```sh
export RPI_FIRMWARE_DIR=/path/to/usr/local/share/rpi-firmware
export RPI_UBOOT_DIR=/path/to/usr/local/share/u-boot/u-boot-rpi-arm64
python3 /usr/src/release/tools/fetch-rpi-wifi-firmware.py /tmp/rpi-radio-firmware
export RPI_WIFI_FIRMWARE_DIR=/tmp/rpi-radio-firmware
```

The downloader pins RPi-Distro/firmware-nonfree revision
`c91cd2804cf7463aab913e7247c176049f16bbd6` and checks SHA256 against
`rpi-wifi-firmware.tsv`. Upstream symlinks are resolved to regular files with the
board names brcmfmac requests. The image includes the copyright/license file and
manifest. Image creation uses this cache offline and rejects incorrect hashes.
Pi 4 gets the BCM43455 firmware, NVRAM and CLM data. Zero 2 W gets both the 43436s
and 43436 variants, including the latter's CLM data; upstream supplies no CLM
file for the former.

Select the board profile through `VM_IMAGE_CONFIG` when running the release
`vm-image` target, with `WITH_VMIMAGES=yes`, `VMFORMATS=raw`, `WITHOUT_QEMU=yes`,
`NO_ROOT=yes`, and the same target/build parameters used for pkgbase:

| Board | VM_IMAGE_CONFIG | VMFSLIST | Layout |
| --- | --- | --- | --- |
| Pi 4 Model B | `/usr/src/release/tools/rpi4-zfs.conf` | `zfs` | GPT, FAT boot partition, ZFS root |
| Zero 2 W | `/usr/src/release/tools/rpi-zero2-ufs.conf` | `ufs` | MBR, FAT boot partition, BSD slice containing UFS |

Use a fresh release staging directory for each board. Set `VMSIZE` to a root
filesystem size that fits the SD card with room for the 128 MiB FAT partition
and partition tables. The Zero 2 W profile uses UFS for its 512 MiB memory limit.
Its root mounts through `/dev/ufs/rootfs`; the FAT partition mounts through its
filesystem label. The Pi 4 profile uses GPT labels for its FAT partition.

The profiles compile a board-specific `5bsd-wifi.dtbo`, load it after
`disable-bt`, and retain the native SD-card and Wi-Fi controller routes.
**Do not add `dtoverlay=mmc`: it disables the `mmcnr` controller used by Wi-Fi.**
The Zero 2 W overlay retains GPCLK2 on GPIO43; its clock rate still depends on
boot firmware and needs physical verification. Both overlays add the radio's
active-low reset power sequence and explicitly select PL011 on GPIO14/15.
Bluetooth is disabled for these UART tests.

The profiles place radio files under `/boot/firmware/brcm` and add
`if_brcmfmac` to `kld_list` in `/etc/rc.conf`. They remove its early
`loader.conf` entry so firmware requests occur after mounting root. Interface
creation is asynchronous; initial Wi-Fi setup below is deliberately manual.

## Verify before writing an SD card

```sh
python3 /usr/src/tools/test/mmc/run_tests.py
python3 /usr/src/tools/test/mmc/rpi_image_test.py \
    --boot-assets "$RPI_FIRMWARE_DIR" \
    --wifi-firmware "$RPI_WIFI_FIRMWARE_DIR"
```

The second command applies both overlays to the actual boot DTBs and checks
SD-card/Wi-Fi status, reset providers, the Zero 2 W clock pin, and effective
pin routing after the native pinctrl traversal, including the console. Host tests also
inspect an actual `mkimg` MBR/BSD layout, firmware hash rejection, and late module
loading. These checks do not execute Pi boot firmware or U-Boot.

Check the built module ABI using all providers, including `wlan.ko`, against the
matching kernel:

```sh
python3 /usr/src/tools/test/mmc/module_symbols_test.py \
    --kernel /path/to/bundle/boot/kernel/kernel \
    --artifacts /path/to/bundle/boot/kernel/*.ko
```

Record hashes of the disk image, kernel, modules, DTB, overlays, U-Boot and Pi
boot firmware. Retain `config.txt`, the radio manifest and build logs with them.
The kernel/module and FAT bundles alone are not complete SD-card images: a
matching installed userland and root filesystem are also required.

## Serial console and first boot

Use a USB-to-TTL UART adapter with **3.3 V logic**, at **115200 baud, 8N1**, with
hardware flow control disabled. With board power off, connect adapter GND to
physical pin 6, adapter RX to pin 8 (Pi TX/GPIO14), and adapter TX to pin 10
(Pi RX/GPIO15). Leave the adapter's power pin disconnected and power the Pi
normally. Zero 2 W requires a fitted header or suitable connections to those pads.

The generated `config.txt` enables UART and disables Bluetooth. Capture the
entire serial session from power-on, including firmware/U-Boot, EFI loader and
kernel messages. Start with a test SD card and a local console login configured
through the normal image provisioning process.

At a root console, collect:

```sh
uname -a
kldstat
camcontrol devlist
dmesg
sysctl net.wlan.devices
ifconfig -a
ofwdump -a
```

Expect CAM SD-card discovery, SDIO function discovery, firmware loading and a
wireless parent in `net.wlan.devices`. If it is absent, preserve the log before
retrying. Check `/boot/firmware/brcm`, `kldstat`, and the running kernel identity.
A missing firmware file, failure to obtain reset GPIOs, or SDIO timeout should
be investigated before association testing.

## Station tests

After attachment finishes, use the actual parent listed by
`sysctl net.wlan.devices` (replace `PARENT` below):

```sh
ifconfig wlan0 create wlandev PARENT
ifconfig wlan0 up
ifconfig wlan0 scan
```

Configure the correct local regulatory domain/country using normal net80211
configuration. Initially use a nearby 2.4 GHz WPA2-Personal AP with CCMP/AES;
this works as a common test target for both boards. Create a mode-0600
`/etc/wpa_supplicant.conf` with the AP's SSID and credentials. Then run:

```sh
wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf
ifconfig wlan0
dhclient wlan0
```

Check association, DHCP and ping to the local gateway. Exercise TCP transfers in
both directions and sustained traffic while saving console logs. Stop the test
supplicant and DHCP client, destroy/recreate `wlan0`, and repeat association.
Repeat after a warm reboot and a complete power cycle. Test both Zero 2 W radio
variants if available and record which firmware names were requested.

Current scope is one station with open or WPA2 CCMP operation. AP/monitor mode,
HT/VHT performance, roaming and other authentication modes are not acceptance
criteria for this first hardware pass. SDIO interrupts currently use polling.
A firmware scan completion lacking its scan header is ignored to prevent stale
completion from ending a newer scan; such firmware may complete only through
the scan timeout and needs a captured log for follow-up.

Treat panics, WITNESS reports, repeated SDIO errors, failed teardown, or stalled
traffic as failures. Preserve the exact bundle, full boot log, scan/association
output and reproduction steps before changing firmware or kernel builds.

## DTrace

The GENERIC-RPI kernel enables `KDTRACE_HOOKS` and `KDTRACE_FRAME`. The Wi-Fi
boundary code supplies 26 SDT probes; imported brcmfmac needs no DTrace changes.
Load `sdt.ko` for these probes, and optionally `fbt.ko` for function entry/return
tracing. Both require matching `dtrace.ko` and `opensolaris.ko`, which the module
loader loads as dependencies. The DTrace test bundle includes all four. The
root filesystem must also provide `/usr/sbin/dtrace` and its userland libraries.

For an already attached device:

```sh
kldload sdt
# Run from the source tree, or use the installed /usr/share/dtrace/rpi-wifi.
dtrace -s /usr/share/dtrace/rpi-wifi
```

The script prints firmware/scan/connection events and aggregates SDIO command
latency, polling results and TX counts. Press Ctrl-C to print the aggregations.
Run scans, association and traffic from another terminal while it is active.
`dtrace -l -P linuxkpi_fullmac` lists the FullMAC probes after its module loads;
use `dtrace -lv -P linuxkpi_fullmac` to inspect their argument types.

To capture initial driver attachment, remove only `if_brcmfmac` from the
`kld_list` setting before booting the test image. Start the script in one
terminal, wait for its "Tracing Pi Wi-Fi" message, then `kldload if_brcmfmac`
in another. The script permits providers that appear when modules load.
Tracing started after boot cannot recover native host attachment or early
power/reset events that have already happened. Keep the serial boot log too.

Probe names below follow `provider:::name`. Pointers are opaque correlation
identifiers and are valid only within the event's owning object's lifetime;
firmware filename strings must be consumed during the probe, as the script
does. No payload bytes, SSIDs or keys are passed to the probes.

| Provider | Probe | Arguments, starting at arg0 |
| --- | --- | --- |
| `bcm_sdhci` | `power-start` | Native device, requested MMC power mode |
| `bcm_sdhci` | `power-done` | Native device, requested mode, native errno |
| `sdio` | `command-start` | Bus identity, opcode (52/53), function, address, write flag, byte count |
| `sdio` | `command-done` | Bus identity, opcode, translated native errno |
| `linuxkpi_sdio` | `host-wait`, `host-claimed`, `host-release` | Linux SDIO function identity |
| `linuxkpi_sdio` | `attach-start` | Native child device, function number |
| `linuxkpi_sdio` | `attach-done`, `detach-done` | Native child device, native errno |
| `linuxkpi_sdio` | `detach-start` | Native child device |
| `linuxkpi_sdio` | `irq-poll` | Native bus, native errno, pending bits (zero on read failure) |
| `linuxkpi_sdio` | `irq-dispatch` | Linux SDIO function identity |
| `linuxkpi_fw` | `request-start` | Linux device identity, requested filename |
| `linuxkpi_fw` | `request-done` | Linux device identity, requested filename, Linux errno, bytes loaded |
| `linuxkpi_fw` | `callback-start` | Linux device identity, requested filename, firmware present flag |
| `linuxkpi_fw` | `callback-done` | Linux device identity, requested filename |
| `linuxkpi_fullmac` | `scan-start` | FullMAC identity, request identity, channel count, SSID count |
| `linuxkpi_fullmac` | `scan-error` | FullMAC identity, request identity, Linux errno |
| `linuxkpi_fullmac` | `scan-abort`, `scan-stale` | FullMAC identity, request identity |
| `linuxkpi_fullmac` | `scan-done` | FullMAC identity, request identity, aborted (0/1; -1 if unknown), native scan notification flag |
| `linuxkpi_fullmac` | `connect-done` | Linux netdevice identity, cfg80211 connection status |
| `linuxkpi_fullmac` | `disconnected` | Linux netdevice identity, 802.11 reason, locally generated flag |
| `linuxkpi_fullmac` | `tx-enqueue`, `tx-dispatch` | FullMAC identity, frame length, native errno |

Native errors are positive; Linux errors are negative. `connect-done` reports
the driver's status, which is not a native errno or proof that the native state
machine accepted the event. `tx-dispatch` success means the bridge is handing
the frame to the Linux driver, not radio transmission or acknowledgement.
CMD52/53 probes describe actual submitted commands, including individual chunks
of a larger transfer; invalid requests rejected before CAM submission emit no
command pair. Normal host-claim calls are serialized by the SDIO bus.

Power rollback can nest a power-off pair inside a power-up pair. Firmware load
pairs begin after argument validation and cover filename fallback resolution;
asynchronous submission failures before the worker runs emit no request pair.
A scan-start ends with scan-error or scan-done. Native cancellation emits
scan-abort, with scan-done later when the driver returns ownership. A stale
completion emits scan-stale and cannot complete the active request. Completion
may occur on a different thread, so correlate scans by both FullMAC and request
identity, not by thread. Enabling tracing mid-operation can miss a start probe.

Host fixtures check probe arguments, balanced error paths, canceled scans and
immediate firmware/request freeing under AddressSanitizer. These checks and
script compilation do not establish that DTrace works on either physical Pi;
probe discovery, event delivery and overhead still need hardware testing.
