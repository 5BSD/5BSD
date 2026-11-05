#!/bin/sh
# Guest side of the devices-sr phase (device save/restore matrix).
# Every answer is one tagged line ("DSR<KIND> key=value ...") that
# lib/common.sh parses with sr_val/dsr_* helpers. Status files live on the
# /tmp tmpfs (not on a disk under test). Background exercisers keep running
# across a checkpoint/suspend/restore, so the restored guest is checked with
# the same processes that held live device state at the suspend.
#   usage: dsr-guest.sh COMMAND [ARGS]
S=/tmp/dsr
SR=/root/hosttest/srtool
DT=/root/hosttest/dsrtool
mkdir -p $S
cmd=${1:-}; shift 2>/dev/null

sha() { sha256 -q 2>/dev/null || sha256sum | cut -d' ' -f1; }
bg() { # bg NAME CMD...: start CMD detached, pid in $S/NAME.pid
	n=$1; shift
	nohup sh -c "$*" > /dev/null 2>&1 &
	echo $! > $S/$n.pid
}

case "$cmd" in
inv)	# PCI functions, device tree and USB devices (compared across restore)
	pciconf -l | tr -s ' \t' ' ' | sort | sed 's/^/DSRPCI /'
	devinfo | sed 's/^ *//' | grep -v -E '^(unknown|nexus0)$' | sort | sed 's/^/DSRDEV /'
	usbconfig list 2>/dev/null | sort | sed 's/^/DSRUSB /'
	;;
disk)	# disk DRIVER [PCISLOT] -> DSRDISK driver= dev=
	d=""
	case $1 in
	nvme) for c in nda0 nvd0; do [ -c /dev/$c ] && { d=$c; break; }; done ;;
	vtblk)
		for u in 0 1 2 3 4 5 6 7; do
			p=$(sysctl -n dev.vtblk.$u.%parent 2>/dev/null); [ -n "$p" ] || continue
			sysctl -n "dev.$(echo "$p" | sed -E 's/([a-z_]+)([0-9]+)$/\1.\2/').%location" 2>/dev/null | grep -q "slot=$2 " && { d=vtbd$u; break; }
		done ;;
	ahci) d=$(camcontrol devlist 2>/dev/null | sed -n 's/.*(\(ada[0-9]*\),.*/\1/p;s/.*(pass[0-9]*,\(ada[0-9]*\)).*/\1/p' | head -1) ;;
	cd) d=$(camcontrol devlist 2>/dev/null | sed -n 's/.*(\(cd[0-9]*\),.*/\1/p;s/.*(pass[0-9]*,\(cd[0-9]*\)).*/\1/p' | head -1) ;;
	scsi) d=$(camcontrol devlist 2>/dev/null | grep -v -E 'ada|cd[0-9]' | sed -n 's/.*(\(da[0-9]*\),.*/\1/p;s/.*(pass[0-9]*,\(da[0-9]*\)).*/\1/p' | head -1) ;;
	pmem) [ -c /dev/vtpmem0 ] && d=vtpmem0 ;;
	esac
	echo "DSRDISK driver=$1 dev=${d:-none}"
	;;
blk-write) # blk-write DEV MB SEED: raw pattern write, sync, read back
	$SR pattern "$2" "$3" | dd of=/dev/$1 bs=1m iflag=fullblock 2>$S/dd.err; rc=$?
	sync
	s=$(dd if=/dev/$1 bs=1m count="$2" 2>/dev/null | sha)
	echo "DSRBLK dev=$1 op=write mb=$2 seed=$3 rc=$rc sha256=$s err=$(tail -1 $S/dd.err | tr ' ' '_')"
	;;
blk-read) # blk-read DEV MB
	s=$(dd if=/dev/$1 bs=1m count="$2" 2>$S/dd.err | sha)
	echo "DSRBLK dev=$1 op=read mb=$2 sha256=$s err=$(grep -v records $S/dd.err | tail -1 | tr ' ' '_')"
	;;
cd-read) # whole medium
	b=$(diskinfo /dev/$1 2>/dev/null | awk '{print $3}')
	s=$(dd if=/dev/$1 bs=2048 2>/dev/null | sha)
	echo "DSRCD dev=$1 bytes=${b:-0} sha256=$s"
	;;
bgio-start) # bgio-start TAG DEV: read loop on DEV (I/O in flight across a checkpoint)
	rm -f $S/bgio.$1.stop
	bg bgio.$1 "n=0 e=0; while [ ! -f $S/bgio.$1.stop ]; do if dd if=/dev/$2 of=/dev/null bs=64k count=64 2>/dev/null; then n=\$((n+1)); else e=\$((e+1)); fi; echo \"DSRBGIO tag=$1 dev=$2 n=\$n errors=\$e\" > $S/bgio.$1.tmp; mv $S/bgio.$1.tmp $S/bgio.$1; done"
	sleep 1; cat $S/bgio.$1 2>/dev/null || echo "DSRBGIO tag=$1 dev=$2 n=0 errors=0 starting"
	;;
bgio-read) cat $S/bgio.$1 2>/dev/null || echo "DSRBGIO tag=$1 missing"
	kill -0 "$(cat $S/bgio.$1.pid 2>/dev/null)" 2>/dev/null && echo "DSRBGIO-ALIVE tag=$1 yes" || echo "DSRBGIO-ALIVE tag=$1 no" ;;
bgio-stop) touch $S/bgio.$1.stop; sleep 1; cat $S/bgio.$1 2>/dev/null ;;
nvme-id) # controller identity through the admin queue
	sn=$(nvmecontrol identify nvme0 2>/dev/null | sed -n 's/^Serial Number: *//p' | tr -d ' ')
	echo "DSRNVME serial=${sn:-none} ns=$(nvmecontrol devlist 2>/dev/null | grep -c 'ns')"
	;;
vtblk-q) # vtblk-q DEV: negotiated queue count (if the driver reports it)
	u=${1#vtbd}
	echo "DSRVQ dev=$1 $(sysctl dev.vtblk.$u 2>/dev/null | grep -i -E 'queue|vq' | sed 's/^dev\.vtblk\.[0-9]*\.//; s/: /=/' | tr '\n' ' ')"
	;;
net-up) # net-up IF ADDR/LEN
	ifconfig "$1" inet "$2" up 2>&1 | tail -1
	sleep 2
	echo "DSRNET if=$1 addr=$(ifconfig "$1" | sed -n 's/.*inet \([0-9.]*\).*/\1/p') status=$(ifconfig "$1" | sed -n 's/.*status: //p' | tr ' ' '_')"
	;;
vtnet-q) u=${1#vtnet}
	echo "DSRVQ if=$1 act=$(sysctl -n dev.vtnet.$u.act_vq_pairs 2>/dev/null) max=$(sysctl -n dev.vtnet.$u.max_vq_pairs 2>/dev/null) req=$(sysctl -n dev.vtnet.$u.req_vq_pairs 2>/dev/null)" ;;
ping-start) # ping-start TAG HOST: continuous ping across the restore
	bg ping.$1 "exec ping -i 0.5 $2 > $S/ping.$1.out 2>&1"
	sleep 2; echo "DSRPING tag=$1 started replies=$(grep -c 'bytes from' $S/ping.$1.out)" ;;
ping-read) echo "DSRPING tag=$1 replies=$(grep -c 'bytes from' $S/ping.$1.out 2>/dev/null) last_seq=$(sed -n 's/.*icmp_seq=\([0-9]*\).*/\1/p' $S/ping.$1.out 2>/dev/null | tail -1)" ;;
ping-stop) kill "$(cat $S/ping.$1.pid 2>/dev/null)" 2>/dev/null; echo "DSRPING tag=$1 stopped" ;;
tty-reader) # tty-reader TAG DEV: keep DEV open and append what arrives
	bg tty.$1 "exec cat $2 >> $S/tty.$1.in"
	sleep 1
	# While cat holds the port open the settings stick (a tty resets to its
	# init termios on first open).
	stty -f "$2" raw -echo clocal 2>/dev/null
	kill -0 "$(cat $S/tty.$1.pid)" 2>/dev/null && echo "DSRTTY tag=$1 reader=yes dev=$2" || echo "DSRTTY tag=$1 reader=no dev=$2"
	;;
tty-got) # tty-got TAG TOKEN
	grep -q -F "$2" $S/tty.$1.in 2>/dev/null && g=yes || g=no
	kill -0 "$(cat $S/tty.$1.pid 2>/dev/null)" 2>/dev/null && a=yes || a=no
	echo "DSRTTY-GOT tag=$1 token=$2 got=$g reader_alive=$a" ;;
tty-send) # tty-send DEV TOKEN
	printf '%s\n' "$2" > "$1" 2>$S/tty.err && echo "DSRTTY-SENT dev=$1 token=$2 rc=0" ||
	    echo "DSRTTY-SENT dev=$1 token=$2 rc=1 err=$(tr ' ' '_' < $S/tty.err)" ;;
usb-desc) # descriptor read through xhci from the tablet (control transfer)
	u=$(usbconfig list 2>/dev/null | grep -i -E 'tablet|bhyve' | head -1 | cut -d: -f1)
	if [ -n "$u" ]; then
		v=$(usbconfig -d "$u" dump_device_desc 2>/dev/null | sed -n 's/^ *idVendor = \(0x[0-9a-f]*\).*/\1/p')
		echo "DSRUSBDESC dev=$u idVendor=${v:-none} driver=$(devinfo | grep -o -E 'hms[0-9]+|ums[0-9]+|uhid[0-9]+|usbhid[0-9]+' | head -1)"
	else
		echo "DSRUSBDESC dev=none"
	fi ;;
snd) # pcm devices: unit and attachment
	cat /dev/sndstat 2>/dev/null | grep '^pcm' | sed 's/^/DSRSND /'
	echo "DSRSND-END" ;;
snd-unit) # snd-unit PATTERN -> DSRSNDUNIT unit=N (first pcm whose sndstat line or parent device matches)
	u=$(grep '^pcm' /dev/sndstat 2>/dev/null | while IFS= read -r l; do n=$(echo "$l" | sed -n 's/^pcm\([0-9]*\):.*/\1/p'); echo "$n $l parent=$(sysctl -n dev.pcm.$n.%parent 2>/dev/null)"; done | grep -i -E "$1" | head -1 | cut -d' ' -f1)
	echo "DSRSNDUNIT pattern=$1 unit=${u:-none}" ;;
snd-play) # snd-play UNIT: about one second of silence
	t0=$(date +%s)
	timeout 20 dd if=/dev/zero of=/dev/dsp$1 bs=8192 count=24 2>/dev/null; rc=$?
	echo "DSRPLAY unit=$1 rc=$rc secs=$(( $(date +%s) - t0 ))" ;;
snd-rec) n=$(timeout 20 dd if=/dev/dsp$1 bs=8192 count=8 iflag=fullblock 2>/dev/null | wc -c | tr -d ' ')
	echo "DSRREC unit=$1 bytes=$n" ;;
gpu) d=$(sysctl -n dev.vtgpu.0.%desc 2>/dev/null)
	echo "DSRGPU attached=$([ -n "$d" ] && echo yes || echo no) errors=$(dmesg | grep -c -i -E 'vtgpu.*(error|fail|timeout)')" ;;
evfind) # evfind NAME -> evdev node whose name is NAME
	for n in $(sysctl -N kern.evdev.input 2>/dev/null | sed -n 's/^kern\.evdev\.input\.\([0-9]*\)\.name$/\1/p'); do
		[ "$(sysctl -n kern.evdev.input.$n.name)" = "$1" ] && { echo "DSREVDEV name=$1 dev=/dev/input/event$n phys=$(sysctl -n kern.evdev.input.$n.phys)"; exit 0; }
	done
	echo "DSREVDEV name=$1 dev=none" ;;
evread-start) # evread-start DEV SECS
	bg evread "exec $DT evread $1 $S/ev.status $2"
	sleep 1; cat $S/ev.status 2>/dev/null || echo "DSREV count=none" ;;
evread) cat $S/ev.status 2>/dev/null || echo "DSREV count=none" ;;
mnt9p) # mnt9p SHARE MNT
	mkdir -p "$2"
	mount -t p9fs "$1" "$2" 2>$S/mnt.err && echo "DSR9P share=$1 mounted=yes" ||
	    echo "DSR9P share=$1 mounted=no err=$(tr ' ' '_' < $S/mnt.err)" ;;
mntvfs) # mntvfs TAG MNT: find /dev/virtiofsN by tag, mount read-only
	mkdir -p "$2"; d=""
	for u in 0 1 2 3; do [ "$(sysctl -n dev.virtio_fs.$u.tag 2>/dev/null)" = "$1" ] && { d=/dev/virtiofs$u; break; }; done
	[ -n "$d" ] && $DT vfsmount "$d" "$2" || echo "DSRVFS error=no-device-with-tag:$1" ;;
file-write) # file-write PATH MB SEED
	$SR pattern "$2" "$3" > "$1" 2>$S/fw.err; rc=$?; sync
	echo "DSRFILE path=$1 op=write rc=$rc sha256=$(sha < "$1" 2>/dev/null) err=$(tr ' ' '_' < $S/fw.err | tail -1)" ;;
file-read) echo "DSRFILE path=$1 op=read sha256=$( [ -f "$1" ] && sha < "$1" || echo missing)" ;;
hold-start) # hold-start TAG FILE MB: open FILE, read MB, wait for $S/hold.TAG.go, read the rest
	rm -f $S/hold.$1.*
	bg hold.$1 "exec 3< $2; dd bs=1m count=$3 <&3 > $S/hold.$1.a 2>/dev/null; touch $S/hold.$1.half; while [ ! -f $S/hold.$1.go ]; do sleep 0.2; done; dd bs=1m <&3 > $S/hold.$1.b 2>/dev/null; cat $S/hold.$1.a $S/hold.$1.b | sha256 -q > $S/hold.$1.sum"
	i=0; while [ ! -f $S/hold.$1.half ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
	echo "DSRHOLD tag=$1 half=$([ -f $S/hold.$1.half ] && echo yes || echo no)" ;;
hold-finish) touch $S/hold.$1.go
	i=0; while [ ! -f $S/hold.$1.sum ] && [ $i -lt 100 ]; do sleep 0.2; i=$((i+1)); done
	echo "DSRHOLD tag=$1 sha256=$(cat $S/hold.$1.sum 2>/dev/null || echo none)" ;;
balloon) echo "DSRBALLOON desired=$(sysctl -n dev.vtballoon.0.desired 2>/dev/null) current=$(sysctl -n dev.vtballoon.0.current 2>/dev/null) physfree_mb=$(( $(sysctl -n vm.stats.vm.v_free_count) * $(sysctl -n hw.pagesize) / 1048576 ))" ;;
vmem) echo "DSRVMEM requested=$(sysctl -n dev.vtmem.0.requested_size 2>/dev/null) plugged=$(sysctl -n dev.vtmem.0.plugged_size 2>/dev/null) blocks=$(sysctl -n dev.vtmem.0.plugged_blocks 2>/dev/null)" ;;
wdog-start) # wdog-start SECS: pat the watchdog every second
	rm -f $S/wdog.stop
	bg wdog "n=0; while [ ! -f $S/wdog.stop ]; do watchdog -t $1 && n=\$((n+1)); echo \"DSRWDOG pats=\$n\" > $S/wdog.tmp; mv $S/wdog.tmp $S/wdog; sleep 1; done"
	sleep 2
	echo "DSRWDOG-DEV $(sysctl -n dev.i6300esbwd.0.%desc 2>/dev/null | tr ' ' '_' || echo none)"
	cat $S/wdog 2>/dev/null ;;
wdog-read) cat $S/wdog 2>/dev/null || echo "DSRWDOG pats=none"; echo "DSRUPTIME s=$(sysctl -n kern.boottime | sed 's/.*sec = \([0-9]*\).*/\1/')" ;;
wdog-stop) touch $S/wdog.stop; sleep 2; echo "DSRWDOG-STOPPED (armed, not petted)" ;;
wdog-off) watchdog -t 0; echo "DSRWDOG-OFF rc=$?" ;;
rtc-alarm) # rtc-alarm SECS: alarm SECS from now on the virtio RTC clock
	# before= is read first: after a restore the guest wall clock can trail the
	# device clock, so a "SECS from now" alarm may already be due and fire at once.
	b=$(sysctl -n dev.vtrtc.0.alarm_count 2>/dev/null)
	t=$(( ($(date +%s) + $1) * 1000000000 ))
	sysctl dev.vtrtc.0.alarm_time_ns=$t > /dev/null 2>$S/rtc.err; rc=$?
	echo "DSRRTC set=$t rc=$rc before=$b count=$(sysctl -n dev.vtrtc.0.alarm_count 2>/dev/null) err=$(tr ' ' '_' < $S/rtc.err)" ;;
rtc) echo "DSRRTC count=$(sysctl -n dev.vtrtc.0.alarm_count 2>/dev/null) alarm=$(sysctl -n dev.vtrtc.0.alarm_time_ns 2>/dev/null) observed=$(sysctl -n dev.vtrtc.0.alarm_observed_time_ns 2>/dev/null) now=$(date +%s)" ;;
crypto-start) # geli onetime (AES-CBC) on a malloc md; crypto(9) prefers vtcrypto
	md=$(mdconfig -a -t malloc -s 32m)
	geli onetime -e AES-CBC -l 128 -s 4096 "$md" 2>$S/geli.err
	echo "$md" > $S/crypto.md
	echo "DSRCRYPTO md=$md crypto=$(geli list "$md.eli" 2>/dev/null | sed -n 's/^Crypto: *//p' | tr ' ' '_') err=$(tr ' ' '_' < $S/geli.err | tail -1)" ;;
crypto-io) # crypto-io MB SEED: pattern through the .eli provider
	md=$(cat $S/crypto.md)
	$SR pattern "$1" "$2" | dd of=/dev/$md.eli bs=1m 2>/dev/null
	s=$(dd if=/dev/$md.eli bs=1m count="$1" 2>/dev/null | sha)
	echo "DSRCRYPTO-IO md=$md sha256=$s crypto=$(geli list "$md.eli" 2>/dev/null | sed -n 's/^Crypto: *//p' | tr ' ' '_') intr=$(p=$(sysctl -n dev.vtcrypto.0.%parent 2>/dev/null); vmstat -i 2>/dev/null | awk -v p="${p:-none}" '{n = $2; sub(/:.*/, "", n)} n == p {s += $(NF-1)} END {print s + 0}')" ;;
tpm) [ -c /dev/tpm0 ] && $DT tpmrand /dev/tpm0 || echo "DSRTPM error=no-/dev/tpm0" ;;
present) # present DRIVER-REGEX: attached in the device tree?
	l=$(devinfo | grep -o -E "^ *($1)[0-9]+" | tr -d ' ' | head -1)
	echo "DSRPRESENT re=$1 dev=${l:-none}" ;;
errs) echo "DSRERRS $(dmesg | grep -i -E 'error|timeout|fail|reset|watchdog|panic' | tail -3 | tr '\n' '|' | tr -s ' ' '_' | cut -c1-300)" ;;
dmesg-tail) echo "DSRDMESG $(dmesg | tail -3 | tr '\n' '|' | tr -s ' ' '_' | cut -c1-300)" ;;
stop)	for p in $S/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
	touch $S/bgio.stop $S/wdog.stop; echo "DSRSTOP" ;;
*)	echo "usage: dsr-guest.sh inv|disk|blk-*|cd-read|bgio-*|nvme-id|net-up|vtnet-q|ping-*|tty-*|usb-desc|snd*|gpu|ev*|mnt9p|mntvfs|file-*|hold-*|balloon|vmem|wdog-*|rtc*|crypto-*|tpm|present|errs|dmesg-tail|stop" >&2
	exit 2 ;;
esac
