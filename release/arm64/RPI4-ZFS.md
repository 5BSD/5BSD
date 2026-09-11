# Experimental Raspberry Pi 4 ZFS/pkgbase image

Use the existing mk-vmimage.sh pipeline with the profile
release/tools/rpi4-zfs.conf, TARGET=arm64, TARGET_ARCH=aarch64, VMFS=zfs,
and a target-architecture pkgbase repository. The profile creates a GPT image
with a 128 MiB firmware/FAT32 partition and a ZFS root.

Provide RPI_FIRMWARE_DIR from the unpacked FreeBSD rpi-firmware package and
RPI_UBOOT_DIR from u-boot-rpi-arm64. Keep those packages and checksums with the
build record. No firmware packages need to be installed on the build host.
The FAT partition contains Pi 4 firmware, DTB/overlays, U-Boot, and the target
EFI loader. The root uses the existing VM ZFS dataset layout and pkgbase database.

Use a numeric byte count for mk-vmimage.sh -s, for example 6442450944.
The final disk is larger by the firmware partition and partition-table overhead.
This is one whole-device image, not an ISO. Do not write it over a populated
device without explicitly selecting and approving that target.

Example (paths and repository configuration must already exist):

    env TARGET=arm64 TARGET_ARCH=aarch64 \
      PKG_ABI=FreeBSD:16:aarch64 PKG_CMD=/usr/local/sbin/pkg-static \
      PKGBASE_REPO_DIR=/path/to/repo-config \
      MAKEOBJDIRPREFIX=/path/to/arm64-objects \
      MAKEFS=/usr/sbin/makefs MKIMG=/usr/bin/mkimg \
      RPI_FIRMWARE_DIR=/path/to/rpi-firmware \
      RPI_UBOOT_DIR=/path/to/u-boot-rpi-arm64 \
      sh /usr/src/release/scripts/mk-vmimage.sh \
      -C /usr/src/release/tools/vmimage.subr \
      -c /usr/src/release/tools/rpi4-zfs.conf \
      -d /path/to/new-root -F zfs -f raw \
      -i /path/to/root.zfs -o /path/to/5BSD-rpi4-zfs.img \
      -s 6442450944 -S /usr/src

Qualification is intentionally split:

* ARM64 QEMU virt with an EFI firmware can test the EFI loader, ZFS root and
  userspace, but bypasses Pi firmware and U-Boot.
* A real Pi 4 must test SD/USB boot, storage, Ethernet, USB and console.
  USB boot may require an EEPROM update on older Pi 4 boards.
* Confirm the base/kernel package generation and test all core services before
  calling an image current or qualified. An old ARM64 repository produces an
  old system even when this image-building profile is new.
* No secure-boot, signed-seal or root-resistant immutability claim is made.

Pi boot documentation:
https://www.raspberrypi.com/documentation/computers/raspberry-pi.html
