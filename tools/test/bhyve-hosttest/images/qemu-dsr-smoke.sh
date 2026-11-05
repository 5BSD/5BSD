#!/bin/sh
# Unprivileged QEMU/TCG smoke of the devices-sr guest side (authoring aid;
# bhyve needs root and vmm). Boots the kit image with the QEMU counterparts
# of the bhyve devices the phase exercises and runs the same dsr-guest.sh
# commands, judged with the phase's parsers (lib/common.sh). QEMU has no
# checkpoint/restore here: this proves the guest drivers attach under the
# capability plane and the exercise scripts work, not bhyve's save/restore.
# Then (SMOKE_UEFI=yes, default) boots the same image through EDK2 firmware.
#   usage: images/qemu-dsr-smoke.sh [IMAGE] [WORKDIR]
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
IMG=${1:-/usr/obj/5BSD-otel-validation/hosttest-images/current/guest.img}
W=${2:-/usr/obj/5BSD-otel-validation/hosttest-results/qemu-dsr-smoke}
Q=${QEMU:-/usr/local/bin/qemu-system-x86_64}
EFI=${EFI_CODE:-/usr/local/share/qemu/edk2-x86_64-code.fd}
EFIVARS=${EFI_VARS:-/usr/local/share/qemu/edk2-i386-vars.fd}
[ -x "$Q" ] || { echo "no QEMU at $Q" >&2; exit 2; }
case "$W" in /usr/obj/*) ;; *) echo "WORKDIR must be under /usr/obj" >&2; exit 2 ;; esac
HT_KIT=$KIT; export HT_KIT
. "$KIT/lib/common.sh" > /dev/null 2>&1; trap - EXIT INT TERM HUP
SRT=$KIT/guest-bin/srtool
G=/root/hosttest/dsr-guest.sh R=/root/hosttest/sr-guest.sh
rm -rf "$W"; mkdir -p "$W/share" "$W/cd"
cp "$IMG" "$W/disk.img"
for f in nvme ahci mq; do truncate -s 64m "$W/$f.img"; done
truncate -s 64m "$W/pmem.img"
"$SRT" pattern 4 77 > "$W/cd/pattern.bin"
makefs -t cd9660 -o rockridge,label=HTDSR "$W/cd.iso" "$W/cd" > /dev/null 2>&1
CDSHA=$(sha256 -q "$W/cd.iso")
"$SRT" pattern 4 78 > "$W/share/h1"; : > "$W/share/g1"   # g1 is overwritten, c1 created by the guest
port() { p=$1; while sockstat -4 -l | grep -q "127.0.0.1:$p[[:space:]]"; do p=$((p + 1)); done; echo $p; }
P1=$(port 4790); C2=$(port $((P1 + 1))); HP=$(port 5590); FW=$(port $((HP + 1)))

qpid= conpid=
stopq() { kill $qpid 2>/dev/null; [ -z "$conpid" ] || { pkill -P $conpid; kill $conpid; } 2>/dev/null; conpid=; wait $qpid 2>/dev/null; i=0; while sockstat -4 -l | grep -q "127.0.0.1:$P1[[:space:]]" && [ $i -lt 40 ]; do sleep 0.5; i=$((i + 1)); done; }
trap 'stopq; rm -f "$W"/*.img "$W/cd.iso"' EXIT
# boot_q TAG QEMU-ARGS...: start QEMU, attach the console, wait for READY.
boot_q()
{
	tag=$1; shift
	"$Q" -accel tcg,thread=multi -machine q35 -cpu max -smp 2 -display none -vga none \
	    -serial "tcp:127.0.0.1:$P1,server=on,wait=on" "$@" > "$W/qemu-$tag.log" 2>&1 &
	qpid=$!
	i=0; while ! sockstat -4 -l | grep -q "127.0.0.1:$P1[[:space:]]" && [ $i -lt 120 ]; do sleep 0.5; i=$((i + 1)); done
	: > "$W/console-$tag"; : > "$W/input-$tag"
	CONSOLE_LOG=$W/console-$tag CONSOLE_INPUT=$W/input-$tag; export CONSOLE_LOG CONSOLE_INPUT
	(tail -f "$W/input-$tag" | nc 127.0.0.1 "$P1" >> "$W/console-$tag" 2>&1) &
	conpid=$!
	t0=$(date +%s)
	until tr -d '\r' < "$W/console-$tag" | grep -q HOSTTEST-GUEST-READY; do
		kill -0 $qpid 2>/dev/null || { echo "qemu exited"; tail -5 "$W/qemu-$tag.log"; return 1; }
		tr -d '\r' < "$W/console-$tag" | grep -q -E '^panic:|Fatal trap' && { echo "[$tag] guest panic"; return 1; }
		[ $(( $(date +%s) - t0 )) -lt ${TIMEOUT:-900} ] || { echo "no ready marker"; tail -20 "$W/console-$tag"; return 1; }
		sleep 2
	done
	echo "[$tag] ready after $(( $(date +%s) - t0 )) s"
	sleep 5
}
g() { sh "$KIT/lib/acmd-console.sh" "$1" "${2:-60}"; }
gq() { g "$2" "${3:-60}" > "$W/$1" 2>&1; }
v() { sr_val "$W/$1" "$2" "$3"; }
rc=0
ok() { echo "dsr ok   $*"; }
nok() { echo "dsr FAIL $*"; rc=1; }
mon() { printf '%s\n' "$1" | timeout 5 nc -N -U "$W/mon.sock" > /dev/null 2>&1; }

boot_q dev -m 2048,slots=4,maxmem=4G \
    -drive file="$W/disk.img",format=raw,if=none,id=root -device virtio-blk-pci,drive=root,addr=0x3,bootindex=0 \
    -drive file="$W/mq.img",format=raw,if=none,id=mq -device virtio-blk-pci,drive=mq,num-queues=4,addr=0x9 \
    -drive file="$W/nvme.img",format=raw,if=none,id=nv -device nvme,drive=nv,serial=HTNVME01 \
    -device ahci,id=ahci0 -drive file="$W/ahci.img",format=raw,if=none,id=ad -device ide-hd,drive=ad,bus=ahci0.0 \
    -drive file="$W/cd.iso",format=raw,if=none,id=cd,media=cdrom,readonly=on -device ide-cd,drive=cd,bus=ahci0.1 \
    -netdev "user,id=n0,net=10.0.2.0/24,hostfwd=tcp:127.0.0.1:$FW-:5601" -device e1000,netdev=n0 \
    -device virtio-serial-pci \
    -chardev socket,id=vc1,path="$W/vcon1.sock",server=on,wait=off -device virtserialport,chardev=vc1,name=htcon1 \
    -chardev socket,id=vc2,path="$W/vcon2.sock",server=on,wait=off -device virtserialport,chardev=vc2,name=htcon2 \
    -serial "tcp:127.0.0.1:$C2,server=on,wait=off" \
    -device qemu-xhci -device usb-tablet \
    -audiodev none,id=snd0 -device intel-hda -device hda-duplex,audiodev=snd0 -device virtio-sound-pci,audiodev=snd0 \
    -device virtio-keyboard-pci \
    -virtfs local,path="$W/share",mount_tag=htshare,security_model=none,id=fs0 \
    -device virtio-balloon-pci \
    -device i6300esb -action watchdog=none \
    -object cryptodev-backend-builtin,id=cd0 -device virtio-crypto-pci,cryptodev=cd0 \
    -device pvpanic \
    -object memory-backend-file,id=pm0,share=on,mem-path="$W/pmem.img",size=64M -device virtio-pmem-pci,memdev=pm0 \
    -monitor unix:"$W/mon.sock",server=on,wait=off || exit 1

gq inv.txt "$G inv" 60
echo "dsr info inventory: $(grep -c '^DSRPCI' "$W/inv.txt") PCI functions, $(grep -c '^DSRUSB' "$W/inv.txt") USB devices"
gq kld.txt "kldstat | awk '{print \$5}' | tr '\n' ' '" 30
echo "dsr info modules: $(tr -d '\r' < "$W/kld.txt" | grep -v VSOCK | tail -1)"
# storage
for d in "nvme nvme" "ahci ahci" "cd cd" "mq vtblk 9" "pmem pmem"; do set -- $d; n=$1; shift; gq "disk-$n.txt" "$G disk $*" 30; done
for n in nvme ahci mq pmem; do
	dev=$(v "disk-$n.txt" 'DSRDISK ' dev)
	if [ "$n" = pmem ] && [ "$dev" = none ] && tr -d '\r' < "$W/console-dev" | grep -q "vtpmem0: missing shared-memory-region"; then
		echo "dsr qemu-limit pmem: QEMU virtio-pmem-pci has no shared-memory region capability; vtpmem0 requires one (bhyve exposes region 0)"; continue
	fi
	[ "$n" = pmem ] && mb=8 || mb=16
	gq "blk-$n.txt" "$G blk-write $dev $mb 5" 120
	gq "blkr-$n.txt" "$G blk-read $dev $mb" 120
	[ "$(v "blk-$n.txt" 'DSRBLK ' sha256)" = "$("$SRT" expect $mb 5)" ] && [ "$(v "blkr-$n.txt" 'DSRBLK ' sha256)" = "$("$SRT" expect $mb 5)" ] &&
	    ok "$n: /dev/$dev $mb MiB pattern write+read" || nok "$n: dev=$dev $(tr -d '\r' < "$W/blk-$n.txt" | grep DSRBLK)"
done
gq bgio.txt "$G bgio-start nv $(v disk-nvme.txt 'DSRDISK ' dev); sleep 3; $G bgio-read nv; $G bgio-stop nv" 60
[ "$(v bgio.txt 'DSRBGIO ' errors)" = 0 ] && [ "$(v bgio.txt 'DSRBGIO ' n)" -gt 0 ] 2>/dev/null && ok "bgio read loop: $(tr -d '\r' < "$W/bgio.txt" | grep 'DSRBGIO ' | tail -1)" || nok "bgio $(cat "$W/bgio.txt")"
gq nvid.txt "$G nvme-id" 30; [ "$(v nvid.txt 'DSRNVME ' serial)" = HTNVME01 ] && ok "nvme identify serial HTNVME01" || nok "nvme-id $(cat "$W/nvid.txt")"
gq cd.txt "$G cd-read $(v disk-cd.txt 'DSRDISK ' dev)" 120
[ "$(v cd.txt 'DSRCD ' sha256)" = "$CDSHA" ] && ok "ahci-cd: whole ISO sha256 = host" || nok "cd $(tr -d '\r' < "$W/cd.txt" | grep DSRCD)"
gq vq.txt "$G vtblk-q $(v disk-mq.txt 'DSRDISK ' dev)" 30; echo "dsr info vtblk queues: $(tr -d '\r' < "$W/vq.txt" | grep DSRVQ)"
# e1000 (slirp: host 10.0.2.2; guest->host to 127.0.0.1:HP, host->guest via hostfwd FW)
gq em.txt "$G net-up em0 10.0.2.15/24" 30
timeout 30 nc -l 127.0.0.1 "$HP" > "$W/g2h.txt" 2>&1 & np=$!; sleep 0.5
gq g2h-guest.txt "$R tcp-send 10.0.2.2 $HP tokg2h" 40; wait $np 2>/dev/null
gq h2g-guest.txt "$R tcp-listen 5601" 20
echo tokh2g | timeout 15 nc -N 127.0.0.1 "$FW" > /dev/null 2>&1
g "$R tcp-got 5601" 30 >> "$W/h2g-guest.txt" 2>&1
grep -q -x tokg2h "$W/g2h.txt" && grep -q 'SRTCP-GOT port=5601 data=tokh2g' "$W/h2g-guest.txt" &&
    ok "e1000 em0 $(v em.txt 'DSRNET ' addr): TCP guest->host and host->guest" || nok "e1000 em: $(tr -d '\r' < "$W/em.txt" | grep DSRNET) g2h=$(cat "$W/g2h.txt") h2g=$(grep SRTCP "$W/h2g-guest.txt")"
gq ping.txt "$G ping-start em 10.0.2.2; sleep 3; $G ping-read em; $G ping-stop em" 40
echo "dsr info ping under slirp: $(tr -d '\r' < "$W/ping.txt" | grep 'DSRPING tag=em replies' | tail -1)"
# virtio-console ports and COM2 (same host-side helpers as the phase)
gq vcr.txt "$G tty-reader vc1 /dev/vtcon/htcon1" 30
printf 'vc-a\n' | timeout 10 nc -N -U "$W/vcon1.sock" > /dev/null 2>&1; sleep 1
gq vcg.txt "$G tty-got vc1 vc-a" 20
timeout 12 nc -d -U "$W/vcon2.sock" > "$W/vc2.txt" 2>&1 & np=$!; sleep 1
gq vcs.txt "$G tty-send /dev/vtcon/htcon2 vc-b" 20; sleep 2; kill $np 2>/dev/null
grep -q 'got=yes reader_alive=yes' "$W/vcg.txt" && grep -q vc-b "$W/vc2.txt" && ok "virtio-console: host->htcon1 (reader kept open), htcon2->host" ||
    nok "virtio-console reader=$(v vcr.txt 'DSRTTY ' reader) $(tr -d '\r' < "$W/vcg.txt" | grep DSRTTY) g2h='$(cat "$W/vc2.txt")'"
gq c2r.txt "$G tty-reader c2 /dev/cuau1" 30
printf 'c2-a\n' | timeout 10 nc -N 127.0.0.1 "$C2" > /dev/null 2>&1; sleep 1
gq c2g.txt "$G tty-got c2 c2-a" 20
timeout 12 nc -d 127.0.0.1 "$C2" > "$W/c2.txt" 2>&1 & np=$!; sleep 1
gq c2s.txt "$G tty-send /dev/cuau1 c2-b" 20; sleep 2; kill $np 2>/dev/null
grep -q 'got=yes reader_alive=yes' "$W/c2g.txt" && grep -q c2-b "$W/c2.txt" && ok "COM2 cuau1: host->guest and guest->host over TCP" ||
    nok "com2 $(tr -d '\r' < "$W/c2g.txt" | grep DSRTTY) g2h='$(cat "$W/c2.txt")'"
# USB tablet, sound, GPU, input
gq usb.txt "$G usb-desc" 30
[ "$(v usb.txt 'DSRUSBDESC ' dev)" != none ] && [ -n "$(v usb.txt 'DSRUSBDESC ' idVendor)" ] && ok "xhci tablet: $(tr -d '\r' < "$W/usb.txt" | grep DSRUSBDESC)" || nok "usb $(cat "$W/usb.txt")"
gq snd.txt "$G snd; $G present hdac" 30; echo "dsr info sound: $(tr -d '\r' < "$W/snd.txt" | grep -E '^DSRSND |DSRPRESENT' | tr '\n' ' ')"
for p in "HDA|hdaa hda" "VirtIO|virtio virtio-snd"; do
	set -- $p
	gq "su-$2.txt" "$G snd-unit '$1'" 20; u=$(v "su-$2.txt" 'DSRSNDUNIT ' unit)
	gq "sp-$2.txt" "$G snd-play $u" 40; gq "sr-$2.txt" "$G snd-rec $u" 40
	[ "$u" != none ] && [ "$(v "sp-$2.txt" 'DSRPLAY ' rc)" = 0 ] && [ "$(v "sr-$2.txt" 'DSRREC ' bytes)" = 65536 ] &&
	    ok "$2: pcm$u play rc 0, capture 64 KiB" || nok "$2: unit $u play $(v "sp-$2.txt" 'DSRPLAY ' rc) rec $(v "sr-$2.txt" 'DSRREC ' bytes)"
done
gq ev.txt "$G evfind 'QEMU Virtio Keyboard'" 20; EVD=$(v ev.txt 'DSREVDEV ' dev)
gq evs.txt "$G evread-start $EVD 120" 20
for k in 1 2 3; do mon 'sendkey shift'; sleep 0.5; done; sleep 2
gq evr.txt "$G evread" 20
[ "$(v evr.txt 'DSREV ' count)" -ge 6 ] 2>/dev/null && ok "virtio-input $EVD: $(v evr.txt 'DSREV ' count) key events from 3 injected presses" || nok "virtio-input dev=$EVD $(tr -d '\r' < "$W/evr.txt" | grep DSREV)"
# 9p, balloon, pmem (above), virtio-mem
gq 9p.txt "$G mnt9p htshare /mnt/9p; $G file-write /mnt/9p/g1 4 79; $G file-read /mnt/9p/h1; $G hold-start 9p /mnt/9p/h1 2; $G hold-finish 9p" 120
[ "$(sha256 -q "$W/share/g1" 2>/dev/null)" = "$("$SRT" expect 4 79)" ] && [ "$(v 9p.txt 'DSRFILE path=/mnt/9p/h1' sha256)" = "$("$SRT" expect 4 78)" ] &&
    [ "$(v 9p.txt 'DSRHOLD ' sha256)" = "$("$SRT" expect 4 78)" ] && ok "virtio-9p: guest write on host, host file in guest, held-open read" ||
    nok "9p $(tr -d '\r' < "$W/9p.txt" | grep -E 'DSR9P|DSRFILE|DSRHOLD' | tr '\n' ' ')"
gq 9pc.txt "$G file-write /mnt/9p/c1 1 81" 60
if [ "$(sha256 -q "$W/share/c1" 2>/dev/null)" = "$("$SRT" expect 1 81)" ]; then ok "virtio-9p: guest-created file on the host"
elif tr -d '\r' < "$W/console-dev" | grep -q 'cannot create /mnt/9p/c1: No such file or directory'; then
	echo "dsr UNDETERMINED 9p create: new names in the share fail with ENOENT under QEMU's 9p 'local' backend on this FreeBSD host (existing files are written fine); bhyve's lib9p backend decides on the host (dsr-virtio-9p-create)"
else nok "9p create $(tr -d '\r' < "$W/9pc.txt" | grep DSRFILE)"; fi
mon 'balloon 1920'; sleep 5
gq bal.txt "$G balloon" 20
[ "$(v bal.txt 'DSRBALLOON ' desired)" = 32768 ] && [ "$(v bal.txt 'DSRBALLOON ' current)" = 32768 ] && ok "virtio-balloon inflated: $(tr -d '\r' < "$W/bal.txt" | grep DSRBALLOON)" || nok "balloon $(tr -d '\r' < "$W/bal.txt" | grep DSRBALLOON)"
# virtio-mem: this QEMU build has no virtio-mem-pci (bhyve-only device in the smoke).
gq vmem.txt "$G vmem" 20; echo "dsr info virtio-mem absent in this QEMU; helper without the device: $(tr -d '\r' < "$W/vmem.txt" | grep DSRVMEM)"
# watchdog, crypto, pvpanic
gq wd.txt "$G wdog-start 16; sleep 3; $G wdog-read; $G wdog-stop; $G wdog-off" 60
echo "$(tr -d '\r' < "$W/wd.txt" | grep DSRWDOG-DEV)" | grep -q -i 6300ESB && [ "$(v wd.txt 'DSRWDOG ' pats)" -ge 2 ] 2>/dev/null &&
    ok "i6300esb: $(tr -d '\r' < "$W/wd.txt" | grep -E 'DSRWDOG-DEV|DSRWDOG ' | tr '\n' ' ')" || nok "wdog $(tr -d '\r' < "$W/wd.txt" | grep DSRWDOG | tr '\n' ' ')"
gq cr.txt "$G crypto-start; $G crypto-io 8 80" 180
[ "$(v cr.txt 'DSRCRYPTO-IO ' sha256)" = "$("$SRT" expect 8 80)" ] && [ "$(v cr.txt 'DSRCRYPTO-IO ' crypto)" = hardware ] &&
    ok "virtio-crypto: $(tr -d '\r' < "$W/cr.txt" | grep 'DSRCRYPTO-IO')" || { tr -d '\r' < "$W/console-dev" | grep -q 'GEOM_ELI: Crypto READ request failed (error=45)' && echo "dsr UNDETERMINED crypto: encrypt (writes) ran on vtcrypto, every decrypt came back VIRTIO_CRYPTO_S_NOTSUPP (error 45) from QEMU's builtin backend; bhyve's OpenSSL backend decides on the host: $(tr -d '\r' < "$W/cr.txt" | grep DSRCRYPTO-IO)"; } || nok "crypto $(tr -d '\r' < "$W/cr.txt" | grep DSRCRYPTO | tr '\n' ' ')"
gq pv.txt "$G present 'acpi_pvpanic|pvpanic'" 20
[ "$(v pv.txt 'DSRPRESENT ' dev)" != none ] && ok "pvpanic: $(v pv.txt 'DSRPRESENT ' dev)" || nok "pvpanic $(cat "$W/pv.txt")"
gq inv2.txt "$G inv" 60
set -- $(dsr_inv_diff "$W/inv.txt" "$W/inv2.txt"); [ "$1" = same ] && ok "inventory parser: same $2 entries on a second read" || nok "inventory $*"
gq stop.txt "$G stop; $G errs" 30; echo "dsr info guest errors: $(tr -d '\r' < "$W/stop.txt" | sed -n 's/^DSRERRS //p' | tail -1)"
g 'shutdown -p now' 10 > /dev/null 2>&1
i=0; while kill -0 $qpid 2>/dev/null && [ $i -lt 120 ]; do sleep 1; i=$((i + 1)); done
sp=$(tr -d '\r' < "$W/console-dev" | sed -n '/power-down by root/,$p' | grep -m1 '^panic:')
if [ -z "$sp" ]; then ok "dev guest powered off cleanly"; else
	echo "dsr FINDING shutdown: guest $sp; frames: $(tr -d '\r' < "$W/console-dev" | sed -n '/^panic:/,/^KDB: enter/p' | grep -E '^[a-z_]+\(\) at' | sed -n '4,8p' | cut -d' ' -f1 | tr '\n' ' ')"; fi
stopq

# virtio-gpu alone (its own boot: in the first dm smoke the preloaded vtgpu
# panicked the guest during boot attach). A panic is reported as a FINDING
# (product bug, dm-record.md), not as a smoke failure of the kit.
if [ "${SMOKE_GPU:-yes}" = yes ]; then
	if TIMEOUT=${GPU_TIMEOUT:-600} boot_q gpu -m 1024 -drive file="$W/disk.img",format=raw,if=none,id=root \
	    -device virtio-blk-pci,drive=root,addr=0x3,bootindex=0 -device virtio-gpu-pci -nic none; then
		gq gpu.txt "$G gpu" 20
		[ "$(v gpu.txt 'DSRGPU ' attached)" = yes ] && ok "virtio-gpu attached, errors=$(v gpu.txt 'DSRGPU ' errors)" || nok "gpu $(cat "$W/gpu.txt")"
		g 'shutdown -p now' 10 > /dev/null 2>&1
		i=0; while kill -0 $qpid 2>/dev/null && [ $i -lt 120 ]; do sleep 1; i=$((i + 1)); done
	else
		pl=$(tr -d '\r' < "$W/console-gpu" | grep -m1 '^panic:')
		fr=$(tr -d '\r' < "$W/console-gpu" | sed -n '/^panic:/,/^KDB: enter/p' | grep -E '^(vtgpu|_sleep|sleepq|vtpci)' | cut -d' ' -f1 | tr '\n' ' ')
		[ -n "$pl" ] && echo "dsr FINDING virtio-gpu: guest $pl; frames: $fr" || nok "virtio-gpu boot failed without a panic line"
	fi
	stopq
fi

if [ "${SMOKE_UEFI:-yes}" = yes ]; then
	if [ -f "$EFI" ] && img_has_esp "$IMG" > /dev/null; then
		cp "$EFIVARS" "$W/vars.fd"
		if boot_q uefi -m 1024 -drive if=pflash,format=raw,readonly=on,file="$EFI" -drive if=pflash,format=raw,file="$W/vars.fd" \
		    -drive file="$W/disk.img",format=raw,if=none,id=root -device virtio-blk-pci,drive=root,addr=0x3,bootindex=0 -nic none; then
			gq uefi.txt "sysctl -n machdep.bootmethod" 30
			grep -q UEFI "$W/uefi.txt" && ok "UEFI: image booted through $(basename "$EFI") (machdep.bootmethod=UEFI, ESP $(img_has_esp "$IMG"))" || nok "uefi bootmethod $(cat "$W/uefi.txt")"
			g 'shutdown -p now' 10 > /dev/null 2>&1
			i=0; while kill -0 $qpid 2>/dev/null && [ $i -lt 120 ]; do sleep 1; i=$((i + 1)); done
		else
			nok "UEFI boot failed"
		fi
		stopq
	else
		echo "dsr info UEFI smoke skipped: firmware $EFI or ESP missing ($(img_has_esp "$IMG"))"
	fi
fi
echo "DSR-SMOKE $([ $rc -eq 0 ] && echo PASS || echo FAIL) (logs in $W)"
exit $rc
