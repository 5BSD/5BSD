#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real Pi image hooks with offline fixtures and optional real DTBs.

--boot-assets /path/to/rpi-firmware also applies and checks both board overlays.
--wifi-firmware /path/to/fetched-firmware validates the pinned real radio files.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile
ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / 'release/tools'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--boot-assets', type=Path)
parser.add_argument('--wifi-firmware', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='rpi-image-test-') as directory:
    work = Path(directory)
    copied_tools = work / 'tools'
    shutil.copytree(TOOLS / 'rpi', copied_tools / 'rpi')
    shutil.copy2(TOOLS / 'rpi.subr', copied_tools)
    wifi = args.wifi_firmware or work / 'wifi'
    wifi.mkdir(exist_ok=True)
    rows = []
    for line in (TOOLS / 'rpi-wifi-firmware.tsv').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        board, name, digest, upstream = line.split()
        if not args.wifi_firmware:
            data = ('fixture ' + name).encode()
            (wifi / name).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
        rows.append((board, name, digest, upstream))
    (copied_tools / 'rpi-wifi-firmware.tsv').write_text('\n'.join('\t'.join(row) for row in rows)+'\n')
    boot = args.boot_assets or work / 'boot'
    if not args.boot_assets:
        (boot / 'overlays').mkdir(parents=True)
        for name in ['start4.elf', 'fixup4.dat', 'armstub8-gic.bin', 'bcm2711-rpi-4-b.dtb',
                     'bootcode.bin', 'start.elf', 'fixup.dat', 'bcm2710-rpi-zero-2-w.dtb',
                     'LICENCE.broadcom', 'overlays/disable-bt.dtbo']:
            (boot / name).write_bytes(b'boot fixture')
    uboot = work / 'uboot'; uboot.mkdir(); (uboot / 'u-boot.bin').write_bytes(b'uboot')
    loader = work / 'loader.efi'; loader.write_bytes(b'loader')
    # Capture FAT staging without privileged mounts or allocating a disk image.
    makefs = work / 'makefs'
    makefs.write_text('#!/bin/sh\nfor arg do last=$arg; done\ncp -R "$last" "$CAPTURE"\nrm -rf "$last"\n')
    makefs.chmod(0o755)
    if args.boot_assets:
        lib = ROOT / 'sys/contrib/libfdt'
        sources = ['fdt.c','fdt_ro.c','fdt_rw.c','fdt_sw.c','fdt_wip.c','fdt_empty_tree.c',
                   'fdt_strerror.c','fdt_overlay.c','fdt_addresses.c']
        subprocess.run(['cc', '-I', str(lib), str(Path(__file__).with_name('rpi_dtb_test.c')),
                        *[str(lib / s) for s in sources], '-o', str(work / 'dtcheck')], check=True)
    for board, profile, dtb in [('rpi4','rpi4-zfs.conf','bcm2711-rpi-4-b.dtb'),
                                ('rpi-zero2','rpi-zero2-ufs.conf','bcm2710-rpi-zero-2-w.dtb')]:
        dest = work / board
        (dest / 'boot/kernel').mkdir(parents=True); (dest / 'etc').mkdir()
        modules = ['if_brcmfmac','brcmutil','linuxkpi','linuxkpi_wlan','linuxkpi_sdio','lindebugfs','wlan','wlan_ccmp','wlan_amrr']
        for module in modules: (dest / ('boot/kernel/'+module+'.ko')).write_bytes(b'fixture')
        (dest / 'boot/loader.conf').write_text('console="comconsole"\nif_brcmfmac_load="YES"\n')
        (dest / 'etc/rc.conf').write_text('kld_list="existing_module"\n')
        env = dict(os.environ, RPI_TOOLS_DIR=str(copied_tools), DESTDIR=str(dest),
                   RPI_WIFI_FIRMWARE_DIR=str(wifi), RPI_FIRMWARE_DIR=str(boot),
                   RPI_UBOOT_DIR=str(uboot), MAKEFS=str(makefs), CAPTURE=str(work / (board+'-fat')),
                   PROFILE=str(TOOLS/profile), LOADER=str(loader), NOPKGBASE='')
        harness = '''
set -eu
. "$PROFILE"
metalog_add_data() { printf '%s\\n' "$1" >> "$DESTDIR/METALOG"; }
vm_extra_install_base
make_esp_file ignored 0 "$LOADER"
printf '%s %s' "$PARTSCHEME" "$ROOTLABEL" > "$DESTDIR/layout"
'''
        subprocess.run(['sh', '-c', harness], env=env, check=True)
        assert (dest / 'layout').read_text() == ('gpt gpt' if board == 'rpi4' else 'mbr ufs')
        conf = (dest / 'boot/loader.conf').read_text()
        assert 'if_brcmfmac_load=' not in conf and 'comconsole' not in conf
        assert ('zfs_load=' in conf) == (board == 'rpi4')
        rc = subprocess.check_output(['sysrc','-f',str(dest/'etc/rc.conf'),'-n','kld_list'],text=True)
        assert rc.split() == ['existing_module','if_brcmfmac']
        for owner, name, digest, _ in rows:
            target = dest / 'boot/firmware/brcm' / name
            if owner in (board, 'all'): assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
            else: assert not target.exists()
        fat = work / (board+'-fat')
        config = (fat / 'config.txt').read_text()
        assert 'dtoverlay=mmc' not in config and 'dtoverlay=5bsd-wifi' in config
        assert (fat/dtb).exists() and (fat/'EFI/BOOT/bootaa64.efi').exists()
        assert ('armstub=' in config) == (board=='rpi4')
        if args.boot_assets:
            subprocess.run([str(work/'dtcheck'), str(fat/dtb), str(fat/'overlays/disable-bt.dtbo'),
                            str(fat/'overlays/5bsd-wifi.dtbo')],check=True)
        # Missing module and corrupt/missing radio inputs must abort staging.
        bad = dest / 'boot/kernel/linuxkpi_sdio.ko'; bad.unlink()
        result = subprocess.run(['sh','-c','set -eu; . "$PROFILE"; vm_extra_install_base'],env=env,capture_output=True)
        assert result.returncode != 0 and b'missing linuxkpi_sdio.ko' in result.stderr
        bad.write_bytes(b'fixture')
        empty = work / (board+'-empty'); empty.mkdir()
        result = subprocess.run(['sh','-c','set -eu; . "$PROFILE"; rpi_install_wifi_firmware'],
                                env=dict(env,RPI_WIFI_FIRMWARE_DIR=str(empty)),capture_output=True)
        assert result.returncode != 0 and b'Missing or incorrect' in result.stderr
        # Existing but incorrect firmware must fail before any image writes.
        for owner, name, _, _ in rows:
            if owner in (board, 'all'): (empty/name).write_bytes(b'corrupt firmware')
        result = subprocess.run(['sh','-c','set -eu; . "$PROFILE"; rpi_install_wifi_firmware'],
                                env=dict(env,RPI_WIFI_FIRMWARE_DIR=str(empty)),capture_output=True)
        assert result.returncode != 0 and b'Missing or incorrect' in result.stderr
        if board == 'rpi-zero2':
            # Inspect bytes from the actual mkimg implementation, including the
            # nested BSD label and the payload location in its UFS partition.
            root = work/'root.ufs'; root.write_bytes(b'ROOTFS' + bytes(131072-6))
            esp = work/'esp.fat'; esp.write_bytes(b'FATBOOT' + bytes(1048576-7))
            disk = work/'zero2.img'
            subprocess.run(['sh','-c','set -eu; . "$PROFILE"; rpi_zero2_partition "$ESP" "$SLICE"'],
                env=dict(env,MKIMG='mkimg',VMFORMAT='raw',VMBASE=str(root),VMIMAGE=str(disk),
                         ESP=str(esp),SLICE=str(work/'root.slice')),check=True)
            data = disk.read_bytes()
            assert data[510:512] == b'\x55\xaa'
            assert data[446] == 0x80 and data[450] == 0x0c and data[466] == 0xa5
            fat_start = struct.unpack_from('<I',data,454)[0]*512
            slice_start = struct.unpack_from('<I',data,470)[0]*512
            assert fat_start == 1048576 and data[fat_start:fat_start+7] == b'FATBOOT'
            label = slice_start+512
            assert struct.unpack_from('<I',data,label)[0] == 0x82564557
            # struct disklabel: partitions begin at byte 148; offset follows size.
            ufs_offset = struct.unpack_from('<I',data,label+152)[0]*512
            assert ufs_offset == 65536
            assert data[slice_start+ufs_offset:slice_start+ufs_offset+6] == b'ROOTFS'
print('PASS: both image profiles, firmware hashes/aliases, late module load, boot routing and missing-input gates')
