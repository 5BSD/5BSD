# hosttest common library (sourced by hosttest.sh and phases/*.sh).
# Conventions:
#   check NAME PASS|FAIL|SKIP "detail"   records one result line
#   need_* functions are preflights; they call refuse() which aborts the
#   phase with REFUSED (no changes made yet).
#   at_cleanup "cmd"   registers an undo action, run LIFO on exit/signal.

HT_KIT=${HT_KIT:?}
HT_RESULTS_ROOT=${HT_RESULTS_ROOT:-/usr/obj/5BSD-otel-validation/hosttest-results}
HT_IMAGES=${HT_IMAGES:-/usr/obj/5BSD-otel-validation/hosttest-images}
HT_WORK_ROOT=${HT_WORK_ROOT:-/usr/obj/5BSD-otel-validation/hosttest-work}
HT_REPO=${HT_REPO:-/usr/obj/usr/src/repo/FreeBSD:16:amd64/latest}
# The generation whose vmm.ko cannot load (dtrace_hypertrace_config_lock).
HT_BROKEN_GENERATIONS=${HT_BROKEN_GENERATIONS:-16.snap20261031171249}
HT_DRYRUN=${HT_DRYRUN:-no}

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

ht_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- results ---------------------------------------------------------------
phase_begin()
{
	HT_PHASE=$1
	HT_OUT=$HT_RUN/$HT_PHASE
	mkdir -p "$HT_OUT"
	: > "$HT_OUT/checks.tsv"
	HT_LOG=$HT_OUT/phase.log
	echo "== phase $HT_PHASE $(ht_ts) (expected duration on an idle host: $(phase_expect "$HT_PHASE"))" | tee -a "$HT_LOG"
}

# Expected wall-clock time per phase (idle host; build load makes it slower).
phase_expect()
{
	case $1 in
	boot-smp) echo "2-3 min (two 60s boot budgets plus CPU captures)" ;;
	hwstat) echo "2-4 min" ;;
	devices) echo "1-2 min" ;;
	hypertrace) echo "8-12 min" ;;
	snapshot) echo "16-32 min (6 guest boots, 2 suspend/restore, 4 migrations, network diagnostics)" ;;
	saverestore) echo "18-35 min (2 guests, 7 restores, 3 cycles, 7 refused restores)" ;;
	devices-sr) echo "28-48 min (7 device-group guests + 1 UEFI guest, each: running checkpoint, suspend, restore; misc waits ~3 min for watchdog/RTC timers; 1 UEFI migration)" ;;
	nested) echo "multiple L2 workloads and L1 save/restore; boot readiness capped at 60s by default" ;;
	*) echo "unknown" ;;
	esac
}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$HT_LOG"; }

check()
{
	name=$1 verdict=$2; shift 2
	printf '%s\t%s\t%s\n' "$name" "$verdict" "$*" >> "$HT_OUT/checks.tsv"
	printf '  %-4s %s %s\n' "$verdict" "$name" "${*:+- $*}" | tee -a "$HT_LOG"
}

# check_cmd NAME CMD...  (PASS when CMD exits 0; output kept in NAME.log)
check_cmd()
{
	name=$1; shift
	if "$@" > "$HT_OUT/$name.log" 2>&1; then
		check "$name" PASS
	else
		check "$name" FAIL "exit $? (see $name.log)"
	fi
}

phase_end()
{
	p=$(grep -c "	PASS	" "$HT_OUT/checks.tsv")
	f=$(grep -c "	FAIL	" "$HT_OUT/checks.tsv")
	s=$(grep -c "	SKIP	" "$HT_OUT/checks.tsv")
	if [ "$f" -gt 0 ]; then v=FAIL; elif [ "$p" -gt 0 ]; then v=PASS; else v=SKIP; fi
	printf '%s %s pass=%s fail=%s skip=%s\n' "$HT_PHASE" "$v" "$p" "$f" "$s" | tee "$HT_OUT/RESULT"
	echo "$HT_PHASE $v pass=$p fail=$f skip=$s" >> "$HT_RUN/SUMMARY"
	[ "$v" != FAIL ]
}

refuse()
{
	if [ "$HT_DRYRUN" = yes ]; then
		echo "WOULD REFUSE: $*" | tee -a "$HT_LOG" >&2
		printf 'preflight\tWOULD-REFUSE\t%s\n' "$*" >> "$HT_OUT/checks.tsv"
		HT_WOULD_REFUSE=yes
		return 0
	fi
	echo "REFUSED: $*" | tee -a "$HT_LOG" >&2
	printf 'preflight\tREFUSED\t%s\n' "$*" >> "$HT_OUT/checks.tsv"
	echo "$HT_PHASE REFUSED $*" | tee "$HT_OUT/RESULT" >> "$HT_RUN/SUMMARY"
	exit 3
}

# --- cleanup ---------------------------------------------------------------
HT_CLEANUP=""
at_cleanup() { HT_CLEANUP="$1
$HT_CLEANUP"; }
run_cleanup()
{
	[ -n "$HT_CLEANUP" ] || return 0
	# Consume the list before executing actions, so signals cannot replay it.
	ht_cleanup_pending=$HT_CLEANUP
	HT_CLEANUP=""
	echo "$ht_cleanup_pending" | while IFS= read -r c; do
		[ -n "$c" ] || continue
		echo "cleanup: $c" >> "${HT_LOG:-/dev/null}"
		eval "$c" >> "${HT_LOG:-/dev/null}" 2>&1 || true
	done
	HT_CLEANUP=""
}
trap 'run_cleanup' EXIT
trap 'run_cleanup; exit 130' INT TERM HUP

# --- preflight -------------------------------------------------------------
need_root()
{
	[ "$(id -u)" -eq 0 ] || refuse "must run as root (sudo/su -m root)"
}

host_generation() { pkg query -g '%v' '5BSD-kernel-*' 2>/dev/null | head -1; }

need_generation()
{
	gen=$(host_generation)
	[ -n "$gen" ] || refuse "cannot determine installed generation (pkg query -g '%v' '5BSD-kernel-*')"
	HT_GENERATION=$gen
	for b in $HT_BROKEN_GENERATIONS; do
		[ "$gen" != "$b" ] || [ "${HT_ALLOW_GENERATION:-}" = "$gen" ] ||
		    refuse "installed generation $gen is the one whose vmm.ko does not load; upgrade first (or HT_ALLOW_GENERATION=$gen for non-vmm phases)"
	done
	# Running kernel must be the installed generation's kernel.
	ksha=$(sha256 -q /boot/kernel/kernel 2>/dev/null)
	booted=$(sysctl -n kern.bootfile 2>/dev/null)
	[ "$booted" = /boot/kernel/kernel ] || refuse "booted kernel is $booted, not /boot/kernel/kernel"
	pub=$(sed -n 's/.*"kernel_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$HT_REPO/publication.json" 2>/dev/null | head -1)
	pubgen=$(basename "$(readlink "$HT_REPO" 2>/dev/null || echo "$HT_REPO")"); pubgen=${pubgen%.complete}
	echo "generation=$gen kernel_sha256=$ksha published=$pubgen published_kernel_sha256=$pub kern.version=$(sysctl -n kern.version | head -1)" > "$HT_OUT/identity.txt"
	if [ "$pubgen" = "$gen" ] && [ -n "$pub" ] && [ "$pub" != "$ksha" ]; then
		refuse "installed /boot/kernel/kernel ($ksha) differs from the published $gen kernel ($pub)"
	fi
	# Running kernel was booted from the file on disk: compare kern.ident and uname build.
	[ "$(sysctl -n kern.ident)" = GENERIC-NODEBUG ] || log "note: kern.ident is $(sysctl -n kern.ident), expected GENERIC-NODEBUG"
	pkg query -g '%n' '5BSD-hardware-abi-*' 2>/dev/null | grep -q "$ksha" ||
	    log "note: no 5BSD-hardware-abi package names kernel $ksha (hardware packages may be stale)"
}

need_module() # need_module MODNAME [devnode]
{
	kldstat -q -m "$1" || kldstat -q -n "$1.ko" || {
	    refuse "kernel module $1 is not loaded (this kit never loads modules; the upgraded generation loads it by default, or add ${1}_load=\"YES\" to loader.conf yourself)"
		return 0; }
	[ -z "${2:-}" ] || [ -e "$2" ] || refuse "$2 is missing although $1 is loaded"
}

need_vmm()
{
	need_module vmm /dev/vmmctl
	kldstat -q -m vmm || return 0
	sysctl -n hw.vmm.svm.features >/dev/null 2>&1 || sysctl -n hw.vmm >/dev/null 2>&1 ||
	    refuse "hw.vmm sysctl tree missing"
	[ "$(sysctl -n hw.vmm.vmx.initialized 2>/dev/null || echo 0)" = 1 ] ||
	    [ -n "$(sysctl -n hw.vmm.svm.features 2>/dev/null)" ] ||
	    refuse "vmm loaded but neither SVM (hw.vmm.svm.features) nor VMX (hw.vmm.vmx.initialized=1) is initialized (host vendor: $(host_vendor))"
}

need_cpuctl() { need_module cpuctl /dev/cpuctl0; }

# --- host identity (sr2: Intel readiness) ------------------------------------
HT_DMESG_BOOT=${HT_DMESG_BOOT:-/var/run/dmesg.boot}

# amd | intel | unknown, from the boot CPU identification (Origin=), falling
# back to which vmm backend initialized.
host_vendor()
{
	case "$(sed -n 's/.*Origin="\([A-Za-z]*\)".*/\1/p' "$HT_DMESG_BOOT" 2>/dev/null | head -1)" in
	AuthenticAMD|HygonGenuine) echo amd; return ;;
	GenuineIntel) echo intel; return ;;
	esac
	if [ -n "$(sysctl -n hw.vmm.svm.features 2>/dev/null)" ]; then echo amd
	elif [ "$(sysctl -n hw.vmm.vmx.initialized 2>/dev/null)" = 1 ]; then echo intel
	else echo unknown; fi
}

# nested_gate VENDOR -> prints "ok" or the reason nested virtualization
# cannot run here; returns 0 only for ok. SVM: hw.vmm.svm.nested=1 (default
# on since fix/devd-nested-ntpd) and DecodeAssists. VMX: hw.vmm.vmx.nested=1,
# a boot-time tunable that is 0 by default while live Intel qualification is
# in progress (sys/amd64/vmm/intel/vmx.c), so "off" is the expected Intel
# result today.
nested_gate()
{
	case $1 in
	amd)
		ng=$(sysctl -n hw.vmm.svm.nested 2>/dev/null || echo unset)
		[ "$ng" = 1 ] || { echo "hw.vmm.svm.nested is $ng"; return 1; }
		grep -q 'SVM:.*DAssist' "$HT_DMESG_BOOT" 2>/dev/null ||
		    { echo "host SVM lacks DecodeAssists (required for nested SVM)"; return 1; }
		echo ok ;;
	intel)
		ng=$(sysctl -n hw.vmm.vmx.nested 2>/dev/null || echo unset)
		[ "$ng" = 1 ] || { echo "Intel nested VMX off: hw.vmm.vmx.nested=$ng (boot-time tunable, 0 by default while live Intel qualification is in progress; to qualify it: nextboot -e hw.vmm.vmx.nested=1)"; return 1; }
		echo ok ;;
	*) echo "unknown CPU vendor; nested virtualization needs AMD SVM or Intel VMX"; return 1 ;;
	esac
}

# One block for RUNINFO: vendor, model, SVM/VMX features, nested policy,
# kernel identity.
host_cap_report()
{
	v=$(host_vendor)
	echo "host: vendor=$v model=\"$(sysctl -n hw.model 2>/dev/null | sed 's/ *$//')\" ncpu=$(sysctl -n hw.ncpu) $(grep -o 'Family=0x[0-9a-f]* *Model=0x[0-9a-f]* *Stepping=[0-9]*' "$HT_DMESG_BOOT" 2>/dev/null | head -1 | tr -s ' ')"
	echo "host: virtualization: $(grep -E '^ *(SVM|VT-x):' "$HT_DMESG_BOOT" 2>/dev/null | head -1 | sed 's/^ *//')"
	echo "host: vmm loaded=$(kldstat -q -m vmm 2>/dev/null && echo yes || echo no) svm.features=$(sysctl -n hw.vmm.svm.features 2>/dev/null || echo -) svm.num_asids=$(sysctl -n hw.vmm.svm.num_asids 2>/dev/null || echo -) svm.nested=$(sysctl -n hw.vmm.svm.nested 2>/dev/null || echo -) vmx.initialized=$(sysctl -n hw.vmm.vmx.initialized 2>/dev/null || echo -) vmx.nested=$(sysctl -n hw.vmm.vmx.nested 2>/dev/null || echo -) vmx.nested_vpid=$(sysctl -n hw.vmm.vmx.nested_vpid 2>/dev/null || echo -)"
	echo "host: nested gate: $(nested_gate "$v")"
	echo "host: kernel ident=$(sysctl -n kern.ident) osreldate=$(sysctl -n kern.osreldate) bootfile=$(sysctl -n kern.bootfile) sha256=$(sha256 -q /boot/kernel/kernel 2>/dev/null || echo unreadable)"
	echo "host: BHYVE_SNAPSHOT=$(sysctl -n kern.conftxt 2>/dev/null | grep -c '^options[[:space:]]*BHYVE_SNAPSHOT') hypertrace.ko=$(kldstat -q -m hypertrace 2>/dev/null && echo loaded || echo absent) cpuctl=$([ -e /dev/cpuctl0 ] && echo yes || echo no)"
}

# --- memory ------------------------------------------------------------------
# MB of memory a new guest can use: free + inactive + half the ZFS ARC.
mem_avail_mb()
{
	pg=$(sysctl -n hw.pagesize)
	free=$(( ( $(sysctl -n vm.stats.vm.v_free_count) + $(sysctl -n vm.stats.vm.v_inactive_count) ) * pg / 1048576 ))
	arc=$(( $(sysctl -n kstat.zfs.misc.arcstats.size 2>/dev/null || echo 0) / 2097152 ))
	echo $((free + arc))
}

# 512M / 1G / 4096 (MB) -> MB
mem_mb_of()
{
	case $1 in
	*[Gg]) echo $(( ${1%[Gg]} * 1024 )) ;;
	*[Mm]) echo "${1%[Mm]}" ;;
	*) echo "$1" ;;
	esac
}

# vm_mem_guard NAME MEM: checked before every VM start and restore (sr2).
# Refuses a guest that would leave less than HT_MEM_MARGIN_MB (1024) free.
vm_mem_guard()
{
	vg_need=$(( $(mem_mb_of "$2") + ${HT_MEM_MARGIN_MB:-1024} ))
	vg_have=$(mem_avail_mb)
	if [ "$vg_have" -lt "$vg_need" ]; then
		HT_GUARD_MSG="not enough memory for $1: needs $(mem_mb_of "$2") MB + ${HT_MEM_MARGIN_MB:-1024} MB margin, about $vg_have MB available"
		log "$HT_GUARD_MSG"
		return 1
	fi
	log "memory for $1 ($2): about $vg_have MB available"
}

need_mem_mb() # need_mem_mb MB
{
	avail=$(mem_avail_mb)
	[ "$avail" -ge "$1" ] || refuse "need ${1} MB free memory for guests, about ${avail} MB available (free+inactive+ARC/2)"
	log "memory: need ${1} MB, about ${avail} MB available"
}

need_disk_mb() # need_disk_mb MB
{
	mkdir -p "$HT_WORK_ROOT"
	avail=$(df -m "$HT_WORK_ROOT" | awk 'NR == 2 {print $4}')
	[ "$avail" -ge "$1" ] || refuse "need ${1} MB free under $HT_WORK_ROOT, have ${avail} MB"
}

need_image() # sets HT_IMAGE, refuses if image generation != host generation
{
	m=$HT_IMAGES/current/guest.manifest
	[ -f "$m" ] || refuse "no guest image; run images/build-guest.sh as an ordinary user first"
	HT_IMAGE=$(sed -n 's/^image=//p' "$m")
	igen=$(sed -n 's/^generation=//p' "$m")
	[ -f "$HT_IMAGE" ] || refuse "guest image $HT_IMAGE missing"
	if [ "$igen" != "${HT_GENERATION:-$(host_generation)}" ] && [ "${HT_ALLOW_IMAGE_MISMATCH:-no}" != yes ]; then
		refuse "guest image generation $igen != host generation ${HT_GENERATION:-?}; rebuild with images/build-guest.sh (HyperTrace needs matched builds; HT_ALLOW_IMAGE_MISMATCH=yes overrides)"
	fi
	# sr2: the image must carry this kit's guest helpers (sr-guest.sh,
	# l2-role.sh, srtool); same digest as images/build-guest.sh records.
	iov=$(sed -n 's/^kit_overlay_sha256=//p' "$m")
	kov=$(kit_overlay_sha256)
	if [ "$iov" != "$kov" ] && [ "${HT_ALLOW_STALE_OVERLAY:-no}" != yes ]; then
		refuse "guest image was built from other kit guest files (image overlay ${iov:-none}, kit $kov); rerun images/build-guest.sh (HT_ALLOW_STALE_OVERLAY=yes overrides)"
	fi
	cp "$m" "$HT_OUT/guest.manifest"
}

# Same digest as images/build-guest.sh writes to guest.manifest.
kit_overlay_sha256() { cat "$HT_KIT"/images/overlay/* "$HT_KIT"/guest/*.sh "$HT_KIT"/guest-bin/* 2>/dev/null | sha256 -q; }

need_tool() { command -v "$1" >/dev/null 2>&1 || refuse "required tool $1 not found"; }

# --- bhyve helpers -----------------------------------------------------------
# All VM names start with "ht-" and every VM is destroyed on cleanup.
HT_VMS=""

free_port()
{
	p=${1:-4700}
	while sockstat -4 -l 2>/dev/null | grep -q "127.0.0.1:$p[[:space:]]"; do p=$((p + 1)); done
	echo "$p"
}

# vm_disk NAME -> path of a private copy of the guest image (sparse/cloned).
vm_disk()
{
	d=$HT_WORK/$1.img
	cp "$HT_IMAGE" "$d"
	echo "$d"
}

# vm_boot NAME DISK MEM CPUS "KENV..." "EXTRA bhyve args..."
#   Starts bhyve in the background with com1 on a loopback TCP port and a
#   console reader. Sets VM_<NAME>_* via files under $HT_WORK/NAME.*
vm_boot()
{
	name=$1 disk=$2 mem=$3 cpus=$4 kenv=$5 extra=$6
	case "$name" in ht-*) ;; *) echo "VM names must start with ht-" >&2; return 2 ;; esac
	date +%s > "$HT_WORK/$name.boot-start"
	port=$(free_port 4700)
	echo "$port" > "$HT_WORK/$name.port"
	: > "$HT_WORK/$name.console"; : > "$HT_WORK/$name.input"
	envargs=""
	for kv in $kenv; do envargs="$envargs -e $kv"; done
	vm_mem_guard "$name" "$mem" || { echo "$HT_GUARD_MSG" >> "$HT_WORK/$name.bhyve.log"; return 1; }
	bhyvectl --vm="$name" --destroy >/dev/null 2>&1 || true
	HT_VMS="$HT_VMS $name"
	at_cleanup "vm_destroy $name"
	# Remembered for vm_restore: vCPUs, memory, slots (same devices).
	printf '%s\n%s\n%s\n' "$cpus" "$mem" "-s 0,hostbridge -s 3,virtio-blk,$disk -s 6,virtio-rnd $extra -s 31,lpc" > "$HT_WORK/$name.args"
	# shellcheck disable=SC2086
	vb_remaining=$(( ${HT_BOOT_TIMEOUT:-60} - $(date +%s) + $(cat "$HT_WORK/$name.boot-start") ))
	[ "$vb_remaining" -gt 0 ] || { log "$name: boot deadline expired before loader"; return 1; }
	timeout -k 1 "$vb_remaining" bhyveload -c /dev/null -m "$mem" -d "$disk" $envargs "$name" >> "$HT_WORK/$name.bhyve.log" 2>&1 ||
	    { log "bhyveload $name failed"; vm_boot_diagnostics "$name"; return 1; }
	# shellcheck disable=SC2086
	bhyve -c "$cpus" -m "$mem" -H -w -D \
	    -s 0,hostbridge -s 3,virtio-blk,"$disk" -s 6,virtio-rnd $extra \
	    -s 31,lpc -l "com1,tcp=127.0.0.1:$port" "$name" \
	    >> "$HT_WORK/$name.bhyve.log" 2>&1 &
	echo $! > "$HT_WORK/$name.pid"
	vm_attach_console "$name"
}

# vm_restore NAME CKP [SLOTS] [OPTS]
#   bhyve -r CKP with the vCPUs, memory and slots NAME was booted with
#   (SLOTS replaces the slot list, e.g. for refused-restore tests; OPTS adds
#   bhyve options such as -o x86.nested_svm=true). Returns 0 when the
#   restored bhyve is still running HT_RESTORE_SETTLE (8) s after its console
#   listens; otherwise 1 with HT_REFUSAL = bhyve's refusal line(s) from this
#   attempt only (CPU contract field, integrity, topology...).
vm_restore()
{
	vr_n=$1 vr_ckp=$2
	case "$vr_n" in ht-*) ;; *) echo "VM names must start with ht-" >&2; return 2 ;; esac
	vr_start=$(date +%s)
	echo "$vr_start" > "$HT_WORK/$vr_n.boot-start"
	vr_cpus=$(sed -n 1p "$HT_WORK/$vr_n.args") vr_mem=$(sed -n 2p "$HT_WORK/$vr_n.args")
	vr_slots=${3-$(sed -n 3p "$HT_WORK/$vr_n.args")}
	vr_opts=${4-}
	HT_REFUSAL=""
	vm_mem_guard "$vr_n" "$vr_mem" || { HT_REFUSAL=$HT_GUARD_MSG; return 1; }
	vr_port=$(free_port 4700); echo "$vr_port" > "$HT_WORK/$vr_n.port"; : > "$HT_WORK/$vr_n.input"
	touch "$HT_WORK/$vr_n.bhyve.log"
	vr_off=$(( $(wc -c < "$HT_WORK/$vr_n.bhyve.log") + 1 ))
	echo "== restore $(ht_ts) from $vr_ckp" >> "$HT_WORK/$vr_n.bhyve.log"
	vm_create_empty "$vr_n" "$vr_start" || { HT_REFUSAL="bhyvectl --create --vm=$vr_n failed: $(tail -1 "$HT_WORK/$vr_n.bhyve.log")"; return 1; }
	# shellcheck disable=SC2086
	bhyve -c "$vr_cpus" -m "$vr_mem" -H -w -D -r "$vr_ckp" $vr_opts $vr_slots \
	    -l "com1,tcp=127.0.0.1:$vr_port" "$vr_n" >> "$HT_WORK/$vr_n.bhyve.log" 2>&1 &
	echo $! > "$HT_WORK/$vr_n.pid"
	if ! vm_attach_console "$vr_n"; then
		HT_REFUSAL=$(bhyve_refusal "$HT_WORK/$vr_n.bhyve.log" "$vr_off")
		return 1
	fi
	# Device-topology refusals come after the console port listens.
	vr_i=0
	while [ $vr_i -lt "${HT_RESTORE_SETTLE:-8}" ] && kill -0 "$(cat "$HT_WORK/$vr_n.pid")" 2>/dev/null; do
		sleep 1; vr_i=$((vr_i + 1))
	done
	if ! kill -0 "$(cat "$HT_WORK/$vr_n.pid")" 2>/dev/null; then
		wait "$(cat "$HT_WORK/$vr_n.pid")" 2>/dev/null
		HT_REFUSAL="bhyve exit $? $(bhyve_refusal "$HT_WORK/$vr_n.bhyve.log" "$vr_off")"
		return 1
	fi
	return 0
}

# bhyve_refusal LOG [BYTE-OFFSET] -> the lines that say why bhyve refused a
# restore or an inbound migration ("Checkpoint CPU contract differs at ...",
# integrity, topology, "Inbound migration topology refused ..."), joined with
# "; ". Falls back to the last two meaningful lines.
bhyve_refusal()
{
	br=$(tail -c +"${2:-1}" "$1" 2>/dev/null | tr -d '\r' | grep -v -E '^== |Unhandled ps2 mouse|^$')
	brm=$(echo "$br" | grep -E 'CPU contract|[Cc]heckpoint .*(incompatible|invalid|not a current|differs)|integrity verification failed|Failed to read checkpoint|Failed to (load|read) |[Mm]igration topology refused|Inbound migration failed|requested but unavailable|HyperTrace|IPC command .* failed|topology|not enough memory' |
	    awk '!s[$0]++' | head -4)
	[ -n "$brm" ] || brm=$(echo "$br" | tail -2)
	echo "$brm" | tr '\n' ';' | sed 's/;$//; s/;/; /g'
}

# vm_diag NAME -> "[bhyve: ...] [console: ...]" for FAIL details.
vm_diag()
{
	printf '[bhyve: %s] [console: %s]' "$(bhyve_refusal "$HT_WORK/$1.bhyve.log" | cut -c1-240)" \
	    "$(tr -d '\r' < "$HT_WORK/$1.console" 2>/dev/null | grep -v -E '^[[:space:]]*$|__VSOCK_' | tail -1 | cut -c1-160)"
}

# Stop the console reader of NAME (a restore that is refused after its
# console listened would otherwise leave one behind).
vm_detach_console()
{
	if [ -s "$HT_WORK/$1.lifetime" ]; then
		rm -f "$(cat "$HT_WORK/$1.lifetime")" "$HT_WORK/$1.lifetime"
	fi
	[ -f "$HT_WORK/$1.conpid" ] || return 0
	pkill -P "$(cat "$HT_WORK/$1.conpid")" 2>/dev/null
	kill "$(cat "$HT_WORK/$1.conpid")" 2>/dev/null
	rm -f "$HT_WORK/$1.conpid"
}

# Start (or restart after a restore) the console reader for NAME.
vm_attach_console()
{
	name=$1 port=$(cat "$HT_WORK/$1.port")
	vm_detach_console "$name"
	va_start=$(cat "$HT_WORK/$name.boot-start" 2>/dev/null || date +%s)
	while ! sockstat -4 -l | grep -q "127.0.0.1:${port}[[:space:]]"; do
		kill -0 "$(cat "$HT_WORK/$name.pid")" 2>/dev/null ||
		    { log "bhyve $name exited:"; tail -20 "$HT_WORK/$name.bhyve.log" | tee -a "$HT_LOG"; return 1; }
		[ $(( $(date +%s) - va_start )) -lt "${HT_BOOT_TIMEOUT:-60}" ] || { log "console of $name never listened within the boot deadline"; vm_boot_diagnostics "$name"; return 1; }
		sleep 0.1
	done
	mktemp "$HT_WORK/$name.console-alive.XXXXXX" > "$HT_WORK/$name.lifetime" || return 1
	(tail -f "$HT_WORK/$name.input" | nc 127.0.0.1 "$port" >> "$HT_WORK/$name.console" 2>&1) &
	echo $! > "$HT_WORK/$name.conpid"
}

# Keep host pressure and the guest vCPU stack with every failed boot.
# Print the failure before collecting these short, best-effort diagnostics.
vm_boot_diagnostics()
{
	bd_vm=$1 bd_out=$HT_OUT/$1.boot-diagnostics.txt
	{
		date -u
		sysctl hw.ncpu vm.loadavg
		timeout -k 1 3 vmstat 1 2
		bd_pid=$(cat "$HT_WORK/$bd_vm.pid" 2>/dev/null)
		if [ -n "$bd_pid" ]; then
			timeout -k 1 3 procstat -kk "$bd_pid"
			timeout -k 1 3 bhyvectl --vm="$bd_vm" --cpu=0 --get-rip --get-rflags --get-intinfo --get-stats
		fi
	} > "$bd_out" 2>&1
}

vm_wait() # vm_wait NAME REGEX TIMEOUT (host elapsed seconds)
{
	vw_start=$(cat "$HT_WORK/$1.boot-start" 2>/dev/null || date +%s); vw_next=$((vw_start + 15))
	log "$1: waiting up to ${3}s for boot; $(sysctl -n vm.loadavg 2>/dev/null) host load"
	while [ $(( $(date +%s) - vw_start )) -lt "$3" ]; do
		if tr -d '\r' < "$HT_WORK/$1.console" | grep -E -q "$2"; then
			case "$2" in *READY*)
				while ! grep -q 'root@' "$HT_WORK/$1.console"; do
					[ $(( $(date +%s) - vw_start )) -lt "$3" ] || { log "$1: no shell prompt within the boot deadline"; vm_boot_diagnostics "$1"; return 1; }
					sleep 0.1
				done
				vw_remaining=$(( $3 - $(date +%s) + vw_start ))
				vm_sync_shell "$1" "$vw_remaining" || {
					log "$1: shell did not answer within the boot deadline"
					vm_boot_diagnostics "$1"
					return 1
				} ;;
			esac
			return 0
		fi
		vw_now=$(date +%s)
		if [ "$vw_now" -ge "$vw_next" ]; then
			log "$1: boot waiting $((vw_now - vw_start))/${3}s; $(vm_diag "$1")"
			vw_next=$((vw_now + 15))
		fi
		grep -E -q 'panic:|Fatal trap|mountroot>' "$HT_WORK/$1.console" && { log "$1: guest panic/mountroot"; return 2; }
		sleep 0.1
	done
	log "$1: boot deadline expired after ${3}s; see $HT_WORK/$1.console"
	vm_boot_diagnostics "$1"
	return 1
}

# vm_cmd NAME "command" [timeout]  -> stdout of command; exit status of command
vm_cmd()
{
	vm_cmd_lifetime=$(cat "$HT_WORK/$1.lifetime" 2>/dev/null)
	if [ -z "$vm_cmd_lifetime" ]; then
		echo "guest console command cancelled: no console attachment" >&2
		return 125
	fi
	CONSOLE_LIFETIME=$vm_cmd_lifetime \
	    CONSOLE_LOG=$HT_WORK/$1.console CONSOLE_INPUT=$HT_WORK/$1.input \
	    sh "$HT_KIT/lib/acmd-console.sh" "$2" "${3:-60}"
}

# vm_sync_shell NAME MAXSECS: retry a no-op guest command until one answers
# (the shell reads commands again, and nothing typed earlier is still running).
vm_sync_shell()
{
	vss_t0=$(date +%s)
	while :; do
		vss_remaining=$(( $2 - $(date +%s) + vss_t0 ))
		[ "$vss_remaining" -gt 0 ] || return 1
		vss_attempt=2
		[ "$vss_remaining" -ge "$vss_attempt" ] || vss_attempt=$vss_remaining
		vm_cmd "$1" : "$vss_attempt" > /dev/null 2>&1 && return 0
		[ "$?" -ne 125 ] || return 1
	done
}

vm_destroy()
{
	name=$1
	echo "$(date -u +%FT%TZ) vm_destroy $name: console detach begin" >> "${HT_LOG:-/dev/null}"
	vm_detach_console "$name"
	echo "$(date -u +%FT%TZ) vm_destroy $name: console detach end; process stop begin" >> "${HT_LOG:-/dev/null}"
	[ -f "$HT_WORK/$name.pid" ] && kill "$(cat "$HT_WORK/$name.pid")" 2>/dev/null
	sleep 1
	echo "$(date -u +%FT%TZ) vm_destroy $name: bhyvectl destroy begin" >> "${HT_LOG:-/dev/null}"
	bhyvectl --vm="$name" --destroy >> "${HT_LOG:-/dev/null}" 2>&1
	vd_rc=$?
	echo "$(date -u +%FT%TZ) vm_destroy $name: bhyvectl destroy end rc=$vd_rc" >> "${HT_LOG:-/dev/null}"
	rm -f "$HT_WORK/$name.pid" "$HT_WORK/$name.conpid"
}

# Create an empty kernel VM for `bhyve -r` (restore) or `bhyve -R`
# (migration destination). The guests boot through bhyveload, not a boot ROM,
# so bhyve(8) (like upstream FreeBSD) refuses to create the VM itself and exits
# "no bootrom was configured". Memory comes from the checkpoint or stream, so
# no loader runs; bhyvectl --create is the documented equivalent.
vm_create_empty() # NAME [BOOT_START]
{
	case "$1" in ht-*) ;; *) echo "VM names must start with ht-" >&2; return 2 ;; esac
	echo "${2:-$(date +%s)}" > "$HT_WORK/$1.boot-start"
	bhyvectl --vm="$1" --destroy >/dev/null 2>&1 || true
	case " $HT_VMS " in *" $1 "*) ;; *) HT_VMS="$HT_VMS $1"; at_cleanup "vm_destroy $1" ;; esac
	bhyvectl --create --vm="$1" >> "$HT_WORK/$1.bhyve.log" 2>&1 ||
	    { log "bhyvectl --create --vm=$1 failed (see $1.bhyve.log)"; return 1; }
}

# ckp_manifest FILE: FILE is a published checkpoint manifest (any version:
# plain checkpoints are version 3, ones carrying a HyperTrace handoff 5).
ckp_manifest()
{
	case "$(sed -n 1p "$1" 2>/dev/null)" in
	BHYVE-CHECKPOINT-MANIFEST-[0-9]*) return 0 ;;
	esac
	return 1
}

# vm_suspend NAME CKP CHECKNAME OUTFILE MAXWAIT
#   bhyvectl --suspend, then waits for bhyve to exit and records CHECKNAME.
#   PASS needs all three: bhyvectl exit 0, bhyve exit status 5
#   (BHYVE_EXIT_SUSPEND) and a published checkpoint manifest. A bhyve that
#   publishes and exits but closes the control socket unanswered (bhyvectl
#   "nvlist_xfer() failed: Socket is not connected", before
#   fix/hypertrace-capplane) is reported as such, so the result says whether
#   the suspend itself worked. Returns 0 when the checkpoint is restorable.
vm_suspend()
{
	vs_vm=$1 vs_ckp=$2 vs_name=$3 vs_out=$4 vs_max=${5:-120}
	vs_pid=$(cat "$HT_WORK/$vs_vm.pid")
	bhyvectl --vm="$vs_vm" --suspend="$vs_ckp" > "$vs_out" 2>&1; vs_rc=$?
	vs_i=0
	while kill -0 "$vs_pid" 2>/dev/null && [ $vs_i -lt "$vs_max" ]; do sleep 1; vs_i=$((vs_i + 1)); done
	vs_st=running
	if ! kill -0 "$vs_pid" 2>/dev/null; then wait "$vs_pid" 2>/dev/null; vs_st=$?; fi
	echo "bhyvectl rc=$vs_rc bhyve exit=$vs_st after ${vs_i}s manifest=$(sed -n 1p "$vs_ckp" 2>/dev/null)" >> "$vs_out"
	vs_pub=no
	ckp_manifest "$vs_ckp" && vs_pub=yes
	if [ $vs_rc -eq 0 ] && [ "$vs_st" = 5 ] && [ $vs_pub = yes ]; then
		check "$vs_name" PASS "bhyve exited suspended (status 5) after ${vs_i}s; checkpoint published"
	elif [ "$vs_st" = 5 ] && [ $vs_pub = yes ]; then
		check "$vs_name" FAIL "suspend worked (checkpoint published, bhyve exit 5) but bhyvectl rc=$vs_rc: $(head -1 "$vs_out") - bhyve exited without answering"
	else
		check "$vs_name" FAIL "bhyvectl rc=$vs_rc bhyve=$vs_st published=$vs_pub: $(head -2 "$vs_out" | tr '\n' ' ')"
	fi
	[ $vs_pub = yes ] && [ "$vs_st" != running ]
}

# Guest power-off (clean) then destroy.
vm_shutdown()
{
	vm_cmd "$1" "shutdown -p now" 10 >/dev/null 2>&1 || true
	i=0; while [ $i -lt 60 ] && kill -0 "$(cat "$HT_WORK/$1.pid" 2>/dev/null)" 2>/dev/null; do sleep 1; i=$((i + 1)); done
	vm_destroy "$1"
}

phase_workdir()
{
	HT_WORK=$HT_WORK_ROOT/$(basename "$HT_RUN")-$HT_PHASE
	mkdir -p "$HT_WORK"
	HT_CKP=$HT_WORK/ckp; mkdir -p "$HT_CKP"
	at_cleanup "cp -p $HT_WORK/*.console $HT_WORK/*.log $HT_OUT/ 2>/dev/null"
	# sr2: checkpoints live under ckp/ (members are NAME.data.<gen> etc.; the
	# old *.ckp* / *.kern patterns never matched them and leaked ~1 GB
	# sparse files per checkpoint), private TLS keys under tls/.
	at_cleanup "[ \"\${HT_KEEP_WORK:-no}\" = yes ] || rm -rf $HT_WORK/*.img $HT_CKP $HT_WORK/tls"
}

# --- checkpoint files (sr2) -----------------------------------------------------
# Members named by a checkpoint manifest (data/kern/meta/trace), one per line.
ckp_members_re() { sed -n -E 's/^(data|kern|meta|trace)=//p' "$1" 2>/dev/null; }

# ckp_copy CKP DIR: copy the manifest and its members (same basename; bhyve
# resolves members relative to the manifest's directory). Never the lock.
ckp_copy()
{
	mkdir -p "$2" || return 1
	cp "$1" "$2/" || return 1
	for cm in $(ckp_members_re "$1"); do cp "$(dirname "$1")/$cm" "$2/" || return 1; done
}

# Digest over manifest + members: proves negative tests never touched the
# original checkpoint.
ckp_digest()
{
	{ sha256 -q "$1"; for cm in $(ckp_members_re "$1"); do sha256 -q "$(dirname "$1")/$cm"; done; } | sha256 -q
}

# ckp_member CKP KIND -> path of that member (KIND data|kern|meta)
ckp_member() { echo "$(dirname "$1")/$(sed -n -E "s/^$2=//p" "$1")"; }

# flip_byte FILE OFFSET: invert one byte in place (copies only).
flip_byte()
{
	fb=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
	[ -n "$fb" ] || return 1
	printf "$(printf '\\%03o' $(( (fb ^ 255) & 255 )))" |
	    dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null
}

# --- guest probe parsing (sr2; see guest/sr-guest.sh) -----------------------------
# sr_val FILE TAG KEY -> value of KEY= on the last line containing TAG
sr_val() { grep -- "$2" "$1" 2>/dev/null | tail -1 | tr ' ' '\n' | sed -n "s/^$3=//p" | head -1; }

# sr_hold_verdict FILE EXPECTED -> "ok <detail>" or "bad <detail>"
sr_hold_verdict()
{
	sh_d=$(sr_val "$1" 'SRHOLD ' digest) sh_l=$(sr_val "$1" 'SRHOLD ' last)
	sh_ok=$(sr_val "$1" 'SRHOLD ' ok) sh_v=$(sr_val "$1" 'SRHOLD ' verifies) sh_p=$(sr_val "$1" 'SRHOLD ' pid)
	if [ -n "$sh_d" ] && [ "$sh_d" = "$2" ] && [ "$sh_l" = "$2" ] && [ "$sh_ok" = yes ]; then
		echo "ok holder pid $sh_p verification $sh_v: $(echo "$sh_l" | cut -c1-16)... = expected"
	elif grep -q 'SRHOLD-' "$1" 2>/dev/null; then
		echo "bad $(grep -o 'SRHOLD-[A-Z]*.*' "$1" | tail -1)"
	else
		echo "bad holder digest=$(echo "${sh_d:-none}" | cut -c1-16) now=$(echo "${sh_l:-none}" | cut -c1-16) expected=$(echo "$2" | cut -c1-16) ok=${sh_ok:-?}"
	fi
}

# sr_spin_verdict BEFORE AFTER N -> "ok ..." when every worker i is alive,
# pinned on CPU i and its count advanced between the two reads.
sr_spin_verdict()
{
	ss_ok=ok ss_d="" ss_i=0
	while [ $ss_i -lt "$3" ]; do
		ss_a=$(sr_val "$1" "SRSPIN-$ss_i " n) ss_b=$(sr_val "$2" "SRSPIN-$ss_i " n) ss_c=$(sr_val "$2" "SRSPIN-$ss_i " cpu)
		if [ -z "$ss_a" ] || [ -z "$ss_b" ] || [ "$ss_b" -le "$ss_a" ] || [ "$ss_c" != "$ss_i" ]; then ss_ok=bad; fi
		ss_d="$ss_d vcpu$ss_i:${ss_a:-?}->${ss_b:-?}@cpu${ss_c:-?}"
		ss_i=$((ss_i + 1))
	done
	echo "$ss_ok$ss_d"
}

# sr_clock_verdict BEFORE AFTER HOST_SECONDS -> "ok|backwards ..." comparing the
# first SRCLOCK of BEFORE with the first SRCLOCK of AFTER. The jump (guest
# realtime advance minus host elapsed) is reported, never judged; only a
# clock that went backwards fails (hangs show up as a missing AFTER).
sr_clock_verdict()
{
	sc_r0=$(grep SRCLOCK "$1" 2>/dev/null | head -1 | sed -n 's/.*real=\([0-9.]*\).*/\1/p')
	sc_m0=$(grep SRCLOCK "$1" 2>/dev/null | head -1 | sed -n 's/.*mono=\([0-9.]*\).*/\1/p')
	sc_r1=$(grep SRCLOCK "$2" 2>/dev/null | head -1 | sed -n 's/.*real=\([0-9.]*\).*/\1/p')
	sc_m1=$(grep SRCLOCK "$2" 2>/dev/null | head -1 | sed -n 's/.*mono=\([0-9.]*\).*/\1/p')
	if [ -z "$sc_r0" ] || [ -z "$sc_r1" ] || [ -z "$sc_m0" ] || [ -z "$sc_m1" ]; then
		echo "missing clock reading (before '$sc_r0' after '$sc_r1')"; return
	fi
	echo "$sc_r0 $sc_m0 $sc_r1 $sc_m1 ${3:-0}" | awk '{
		dr = $3 - $1; dm = $4 - $2
		v = (dr < 0 || dm < 0) ? "backwards" : "ok"
		printf "%s guest realtime +%.3f s, monotonic +%.3f s, host elapsed %d s, realtime jump vs host %+.3f s\n", v, dr, dm, $5, dr - $5
	}'
}

# sr_leaf_verdict FILE LEAF -> "ok|bad|skip detail" for one host-CPU-local
# CPUID leaf read on every vCPU (guest/sr-guest.sh cpuleaves). A leaf the
# guest does not enumerate is ok; an enumerated one must read zero on every
# vCPU (gen4 vmm stops passing the executing host CPU's value through,
# which differed between checkpoint and restore on the same host).
sr_leaf_verdict()
{
	grep -q SRLEAF-NOCPUCTL "$1" 2>/dev/null && { echo "skip guest has no /dev/cpuctl0 (image without cpuctl_load)"; return; }
	sl_lines=$(grep "SRLEAF .*leaf=$2 " "$1" 2>/dev/null)
	[ -n "$sl_lines" ] || { echo "bad no SRLEAF lines for leaf $2 (guest command failed?)"; return; }
	sl_n=0 sl_en="" sl_bad="" sl_first="" sl_diff=no sl_d=""
	while read -r _t sl_c _l sl_mb sl_me sl_v1 sl_v2 sl_v3 sl_v4; do
		sl_c=${sl_c#cpu=} sl_mb=${sl_mb#maxbasic=} sl_me=${sl_me#maxext=} sl_v1=${sl_v1#value=}
		sl_v="$sl_v1 $sl_v2 $sl_v3 $sl_v4"
		case "$sl_mb$sl_me$sl_v" in *[!0-9a-fx\ ]*) sl_bad="cpu$sl_c: unreadable ($sl_v)"; continue ;; esac
		if [ $(($2)) -ge $((0x80000000)) ]; then sl_max=$sl_me; else sl_max=$sl_mb; fi
		if [ $(($2)) -gt $((sl_max)) ]; then sl_en=${sl_en:-no}; else sl_en=yes; fi
		[ -n "$sl_first" ] || sl_first=$sl_v
		[ "$sl_v" = "$sl_first" ] || sl_diff=yes
		sl_d="$sl_d cpu$sl_c=[$sl_v]"
		sl_n=$((sl_n + 1))
	done <<EOF
$sl_lines
EOF
	if [ -n "$sl_bad" ]; then echo "bad $sl_bad"
	elif [ "$sl_en" = no ]; then echo "ok leaf $2 not enumerated by the guest (max $sl_max) on $sl_n vCPUs"
	elif [ $sl_diff = yes ]; then echo "bad leaf $2 differs across vCPUs (host-CPU passthrough):$sl_d"
	elif [ "$sl_first" != "0x00000000 0x00000000 0x00000000 0x00000000" ]; then echo "bad leaf $2 nonzero on all $sl_n vCPUs [$sl_first] (host value passed through?)"
	else echo "ok leaf $2 reads zero on all $sl_n vCPUs"; fi
}

# --- HyperTrace delivery evidence (sr2) ----------------------------------------
# ht_delivered SESSION VM -> 0 when a live sample during SESSION shows
# outbound and installed deliveries above zero (the gen4 bare-ELF fix).
ht_delivered()
{
	hd_o=$(sed -n 's/^outbound deliveries: //p' "$HT_OUT/$1.stats.$2" 2>/dev/null | tail -1)
	hd_i=$(sed -n 's/^installed deliveries: //p' "$HT_OUT/$1.stats.$2" 2>/dev/null | tail -1)
	[ -n "$hd_o" ] && [ -n "$hd_i" ] && [ "$hd_o" -gt 0 ] && [ "$hd_i" -gt 0 ]
}
# First and last dtraced job-failure lines (for FAIL details).
ht_jobfail_lines() { grep 'failed to handle job' "$HT_OUT/dtraced.log" 2>/dev/null | sed -n '1p;$p' | awk '!s[$0]++' | cut -c1-200 | tr '\n' ' '; }

dry() { [ "$HT_DRYRUN" = yes ]; }

# End a dry run after the preflights: report whether the phase would run.
dry_end()
{
	if [ "${HT_WOULD_REFUSE:-no}" = yes ]; then
		echo "$HT_PHASE WOULD-REFUSE (see $HT_PHASE/checks.tsv)" | tee "$HT_OUT/RESULT" >> "$HT_RUN/SUMMARY"
	else
		echo "$HT_PHASE READY (preflight passed)" | tee "$HT_OUT/RESULT" >> "$HT_RUN/SUMMARY"
	fi
	exit 0
}

# --- HyperTrace host side ------------------------------------------------------
HT_VTDTR_ARGS="-o enable_hypertrace=true -s 7,virtio-dtrace"
HT_GUEST_DTRACE_KENV="hosttest.dtraced=yes"

need_hypertrace_host()
{
	need_module dtrace /dev/dtrace/dtrace
	need_module hypertrace /dev/dtrace/hypertrace
	need_tool dtracedctl
}

# Start a host dtraced overlord unless one is already running; create the
# spool directories bhyve requires and remove them afterwards if we made them.
ht_dtraced_up()
{
	for d in /var/ddtrace /var/ddtrace/inbound; do
		if [ ! -d "$d" ]; then
			mkdir -m 0700 "$d" && at_cleanup "rmdir $d 2>/dev/null"
		fi
	done
	if pgrep -x dtraced >/dev/null; then
		log "using running dtraced: $(ps -o pid=,args= -p "$(pgrep -x dtraced | head -1)")"
		ps -o args= -p "$(pgrep -x dtraced | head -1)" | grep -q -- '-m' &&
		    refuse "running dtraced is a minion (-m); the host needs an overlord"
		return 0
	fi
	dtraced -O -d -D /var/ddtrace > "$HT_OUT/dtraced.log" 2>&1 &
	echo $! > "$HT_WORK/dtraced.pid"
	at_cleanup "kill \$(cat $HT_WORK/dtraced.pid) 2>/dev/null; sleep 1; rm -f /var/ddtrace/sub.sock"
	i=0; while [ ! -S /var/ddtrace/sub.sock ] && [ $i -lt 40 ]; do sleep 0.25; i=$((i + 1)); done
	[ -S /var/ddtrace/sub.sock ] || { check dtraced-start FAIL "no /var/ddtrace/sub.sock"; return 1; }
	check dtraced-start PASS "overlord pid $(cat "$HT_WORK/dtraced.pid")"
}

# Wait until dtraced reports both forwarder channels (rx and wx) for VM NAME.
# --show-stats=NAME already selects that VM; its output never names it, so
# the channel count is the evidence (htcap: grepping the name never matched).
ht_forwarder_channels() # STATSFILE -> count (empty if unparsable)
{
	sed -n 's/^forwarder channels: \([0-9][0-9]*\)$/\1/p' "$1" 2>/dev/null | tail -1
}
ht_wait_forwarder() # NAME TIMEOUT
{
	hf_start=$(date +%s)
	while [ $(( $(date +%s) - hf_start )) -lt "$2" ]; do
		hf_remaining=$(( $2 - $(date +%s) + hf_start ))
		[ "$hf_remaining" -gt 0 ] || break
		hf_query=3; [ "$hf_remaining" -ge 3 ] || hf_query=$hf_remaining
		if timeout -k 1 "$hf_query" dtracedctl --show-stats="$1" > "$HT_WORK/stats.$1" 2>&1; then
			n=$(ht_forwarder_channels "$HT_WORK/stats.$1")
			[ -n "$n" ] && [ "$n" -ge 2 ] && return 0
		fi
		sleep 0.1
	done
	return 1
}

# Keep a live delivery sample: these counts are current ledger entries, not
# cumulative counters. SESSION_STOP can remove all of them before dtrace exits.
ht_sample_delivery() (
	sample_session=$1 sample_vm=$2
	sample_file="$HT_OUT/$sample_session.stats.$sample_vm"
	if timeout -k 2 5 dtracedctl --show-stats="$sample_vm" > "$sample_file.tmp" 2>&1; then
		sample_n=$(sed -n 's/^installed deliveries: //p' "$sample_file.tmp" | tail -1)
		sample_old=$(sed -n 's/^installed deliveries: //p' "$sample_file" 2>/dev/null | tail -1)
		case $sample_n in ''|*[!0-9]*) rm -f "$sample_file.tmp"; exit ;; esac
		sample_out=$(sed -n 's/^outbound deliveries: //p' "$sample_file.tmp" | tail -1)
		sample_oldout=$(sed -n 's/^outbound deliveries: //p' "$sample_file" 2>/dev/null | tail -1)
		case $sample_out in ''|*[!0-9]*) rm -f "$sample_file.tmp"; exit ;; esac
		if [ "${sample_old:-0}" -eq 0 ] || [ "${sample_oldout:-0}" -eq 0 ]; then
			mv "$sample_file.tmp" "$sample_file"
			date -u +%Y-%m-%dT%H:%M:%SZ > "$sample_file.time"
		fi
	fi
	rm -f "$sample_file.tmp"
)

ht_guest_diagnostics() (
	diag_session=$1
	for diag_vm in $HT_VMS; do
		vm_cmd "$diag_vm" 'date -u; pgrep -lf dtrace; procstat -kk $(pgrep -x dtrace) 2>/dev/null; timeout -k 2 5 dtracedctl --show-stats; ls -la /var/ddtrace /var/ddtrace/inbound /var/ddtrace/outbound; tail -300 /var/log/hosttest-dtraced.log /var/log/messages 2>/dev/null' 20 > "$HT_OUT/$diag_session.diagnostics.$diag_vm" 2>&1
	done
)

# ht_session NAME SECONDS DELAY "guest-cmd VM:cmd ..." -- dtrace args
#   Runs `dtrace -E` for SECONDS (SIGINT at the end), starts the guest
#   commands DELAY seconds in (after program delivery). Output in NAME.*
#   --foreground: SIGINT goes to dtrace itself. In timeout(1)'s default
#   reaper mode a dtrace -E consumer did not end within 40 s of the
#   PROC_REAP_KILL SIGINT and timeout then waited for every descendant
#   (htcap VM passes 7/8 hung); a plain SIGINT ends it in ~8 s (pass 10).
#   -k 15 bounds a session that ignores SIGINT.
ht_session()
{
	sn=$1 secs=$2 delay=$3 gcmds=$4; shift 5
	# A caller may reuse an output directory/session name.  Old success is
	# never evidence for this invocation, even if every new sample fails.
	for sample_vm in $HT_VMS; do
		rm -f "$HT_OUT/$sn.stats.$sample_vm" \
		    "$HT_OUT/$sn.stats.$sample_vm.time" \
		    "$HT_OUT/$sn.stats.$sample_vm.tmp" \
		    "$HT_OUT/$sn.stats-after.$sample_vm"
	done
	timeout --preserve-status --foreground -s INT -k 15 "$secs" dtrace -E -q "$@" > "$HT_OUT/$sn.out" 2> "$HT_OUT/$sn.err" &
	dpid=$!
	rm -f "$HT_OUT/$sn.sampler-stop"
	(
		while [ ! -f "$HT_OUT/$sn.sampler-stop" ] && kill -0 "$dpid" 2>/dev/null; do
			for sample_vm in $HT_VMS; do
				[ ! -f "$HT_OUT/$sn.sampler-stop" ] || break
				ht_sample_delivery "$sn" "$sample_vm"
			done
			sleep 2
		done
	) &
	spid=$!
	sleep "$delay"
	_ifs=$IFS; IFS=';'; set -f; gpids=""
	for g in $gcmds; do
		IFS=$_ifs
		vm=${g%%:*} cmd=${g#*:}
		[ -n "$vm" ] || continue
		vm_cmd "$vm" "$cmd" "$secs" > "$HT_OUT/$sn.$vm.guest" 2>&1 &
		gpids="$gpids $!"
	done
	IFS=$_ifs; set +f
	wait "$dpid"; echo $? > "$HT_OUT/$sn.rc"
	: > "$HT_OUT/$sn.sampler-stop"
	wait "$spid"
	rm -f "$HT_OUT/$sn.sampler-stop"
	for gp in $gpids; do wait "$gp"; done
	# Preserve teardown evidence separately from the live installation sample.
	for vm in $HT_VMS; do
		timeout -k 2 5 dtracedctl --show-stats="$vm" > "$HT_OUT/$sn.stats-after.$vm" 2>&1
	done
	# A nested phase may have an L2 command still using the L1 console.
	[ "$HT_PHASE" != hypertrace ] || ht_guest_diagnostics "$sn"
	grep -c 'failed to handle job' "$HT_OUT/dtraced.log" 2>/dev/null > "$HT_OUT/$sn.jobfail" || true
}

# "VM=outbound/installed ..." after session NAME, and the dtraced job
# failures seen so far (a forwarder that never ACKed an ELF shows here).
ht_delivery()
{
	_d=""
	for vm in $HT_VMS; do
		_o=$(sed -n 's/^outbound deliveries: //p' "$HT_OUT/$1.stats.$vm" 2>/dev/null | tail -1)
		_i=$(sed -n 's/^installed deliveries: //p' "$HT_OUT/$1.stats.$vm" 2>/dev/null | tail -1)
		_d="$_d $vm=${_o:-?}/${_i:-?}"
	done
	printf '[deliveries out/inst:%s; dtraced job failures: %s]' "$_d" "$(cat "$HT_OUT/$1.jobfail" 2>/dev/null)"
	_jf=$(ht_jobfail_lines)
	[ -z "$_jf" ] || printf ' [dtraced: %s]' "$_jf"
}

# Value of "WORKLOAD tag=T runs=N" printed by a guest command.
ht_runs() { sed -n 's/.*WORKLOAD tag=[^ ]* runs=\([0-9]*\).*/\1/p' "$1" | tail -1; }

# First line of a session's dtrace stderr plus its exit status, for FAIL
# details (a session that cannot start must say why in checks.tsv).
ht_err() { printf '[%s.err rc=%s: %s] %s' "$1" "$(cat "$HT_OUT/$1.rc" 2>/dev/null)" "$(head -1 "$HT_OUT/$1.err" 2>/dev/null)" "$(ht_delivery "$1")"; }

# --- devices-sr (dm): device save/restore matrix helpers ------------------------
HT_UEFI_FD=${HT_UEFI_FD:-/usr/local/share/uefi-firmware/BHYVE_UEFI.fd}
HT_UEFI_VARS=${HT_UEFI_VARS:-/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd}

# vm_boot_uefi NAME DISK MEM CPUS VARS "EXTRA bhyve args..."
#   Like vm_boot, but the guest boots through the UEFI firmware
#   (-l bootrom,HT_UEFI_FD[,VARS]); bhyve creates the VM itself. The bootrom
#   is part of the remembered slots, so vm_restore uses the same config.
vm_boot_uefi()
{
	name=$1 disk=$2 mem=$3 cpus=$4 vars=$5 extra=$6
	case "$name" in ht-*) ;; *) echo "VM names must start with ht-" >&2; return 2 ;; esac
	date +%s > "$HT_WORK/$name.boot-start"
	port=$(free_port 4700)
	echo "$port" > "$HT_WORK/$name.port"
	: > "$HT_WORK/$name.console"; : > "$HT_WORK/$name.input"
	vm_mem_guard "$name" "$mem" || { echo "$HT_GUARD_MSG" >> "$HT_WORK/$name.bhyve.log"; return 1; }
	bhyvectl --vm="$name" --destroy >/dev/null 2>&1 || true
	HT_VMS="$HT_VMS $name"
	at_cleanup "vm_destroy $name"
	rom="-l bootrom,$HT_UEFI_FD${vars:+,$vars}"
	printf '%s\n%s\n%s\n' "$cpus" "$mem" "$rom -s 0,hostbridge -s 3,virtio-blk,$disk -s 6,virtio-rnd $extra -s 31,lpc" > "$HT_WORK/$name.args"
	# shellcheck disable=SC2086
	bhyve -c "$cpus" -m "$mem" -H -w -D $rom \
	    -s 0,hostbridge -s 3,virtio-blk,"$disk" -s 6,virtio-rnd $extra \
	    -s 31,lpc -l "com1,tcp=127.0.0.1:$port" "$name" \
	    >> "$HT_WORK/$name.bhyve.log" 2>&1 &
	echo $! > "$HT_WORK/$name.pid"
	vm_attach_console "$name"
}

# dsr_inv_diff BEFORE AFTER -> "same N" | "differs: -<lost> +<new>" | "empty"
#   Compares the guest's PCI functions, device tree and USB devices
#   (dsr-guest.sh inv) before the suspend and after the restore.
dsr_inv_diff()
{
	di_a=$(tr -d '\r' < "$1" 2>/dev/null | grep -E '^DSR(PCI|DEV|USB) ' | sort -u)
	di_b=$(tr -d '\r' < "$2" 2>/dev/null | grep -E '^DSR(PCI|DEV|USB) ' | sort -u)
	if [ -z "$di_a" ] || [ -z "$di_b" ]; then echo "empty"; return; fi
	if [ "$di_a" = "$di_b" ]; then echo "same $(echo "$di_a" | wc -l | tr -d ' ')"; return; fi
	di_lost=$(echo "$di_a" | while IFS= read -r l; do echo "$di_b" | grep -q -x -F "$l" || echo "$l"; done | sed 's/^DSR[A-Z]* //' | head -3 | tr '\n' '|')
	di_new=$(echo "$di_b" | while IFS= read -r l; do echo "$di_a" | grep -q -x -F "$l" || echo "$l"; done | sed 's/^DSR[A-Z]* //' | head -3 | tr '\n' '|')
	echo "differs: -${di_lost:-none} +${di_new:-none}"
}

# dsr_rfb FILE -> "ok RFB xxx.yyy" when FILE starts with an RFB banner
dsr_rfb()
{
	dr_b=$(head -c 12 "$1" 2>/dev/null | tr -d '\n')
	case "$dr_b" in "RFB "[0-9][0-9][0-9].[0-9][0-9][0-9]) echo "ok $dr_b" ;; *) echo "bad '${dr_b:-nothing}'" ;; esac
}

# dsr_wdog_fires LOG OFFSET -> number of i6300esb expiry lines after OFFSET
dsr_wdog_fires() { tail -c +"${2:-1}" "$1" 2>/dev/null | grep -c 'i6300esb: watchdog expired'; }

# dsr_grew FILE1 FILE2 TAG KEY -> "ok a->b" when KEY grew between the two
dsr_grew()
{
	dg_a=$(sr_val "$1" "$3" "$4" | tr -d '\r') dg_b=$(sr_val "$2" "$3" "$4" | tr -d '\r')
	for dg_x in "$dg_a" "$dg_b"; do
		case "$dg_x" in ""|*[!0-9]*) echo "bad '$dg_a'->'$dg_b'"; return ;; esac
	done
	[ "$dg_b" -gt "$dg_a" ] && echo "ok $dg_a->$dg_b" || echo "bad $dg_a->$dg_b"
}

# dsr_nosnap_devices BHYVE_SRC_DIR -> emulations whose pci_devemu has no
#   pe_snapshot (checkpoint of a guest using one returns ENOTSUP).
dsr_nosnap_devices()
{
	for dn_f in "$1"/*.c "$1"/amd64/*.c; do
		[ -f "$dn_f" ] || continue
		grep -q '\.pe_emu[[:space:]]*=' "$dn_f" || continue
		grep -q '\.pe_snapshot[[:space:]]*=' "$dn_f" && continue
		sed -n 's/.*\.pe_emu[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$dn_f"
	done | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# img_has_esp IMAGE -> "yes pN" when one of the first four GPT entries is an
#   EFI system partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B), else "no".
img_has_esp()
{
	for ie_i in 0 1 2 3; do
		ie_t=$(dd if="$1" bs=1 skip=$((1024 + ie_i * 128)) count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')
		[ "$ie_t" = 28732ac11ff8d211ba4b00a0c93ec93b ] && { echo "yes p$((ie_i + 1))"; return 0; }
	done
	echo no; return 1
}

# ---- L0-side capture of a nested L1 while its L2 starts (nl2, 2026-11-02) ----
# The 2026-11-02 L1 freeze was only explained by L0 evidence (one L1 vCPU
# asleep in vm_map_delete under svm_nested_npt_root_clear, its siblings
# spinning).  These run on L0 as root; every command is time-bounded, and the
# bhyvectl vCPU queries (which must freeze the vCPU) run in the background so
# a vCPU that never returns to userland shows up as BLOCKED, not as a hang.

# l0diag_dscript: the D program (arg: L1 bhyve pid as $1, seconds as $2).
l0diag_dscript()
{
	cat <<'EOD'
#pragma D option quiet
#pragma D option aggsize=4m
#pragma D option dynvarsize=16m
fbt:vmm::entry /pid == $1/ { @fn[probefunc] = count(); }
/*
 * fbt return arg1 is all of %rax: a bool return only defines %al and an int
 * return only %eax, so the upper bits are garbage (gen6 printed "true" as
 * 140735669460737).  Cast to the C return type before testing.
 */
fbt:vmm:svm_nested_*_valid:return /pid == $1 && (arg1 & 0xff) == 0/ { @vf[probefunc] = count(); }
fbt:vmm:svm_nested_npt_root_populate:return, fbt:vmm:svm_nested_npt_root_resolve:return,
fbt:vmm:svm_nested_npt_root_translate:return, fbt:vmm:svm_nested_npt_root_clear:return,
fbt:vmm:svm_nested_npt_root_vmrun:return, fbt:vmm:svm_nested_npt_walk:return,
fbt:vmm:svm_nested_npt_commit_ad:return, fbt:vmm:svm_handle_internal_exit:return
/pid == $1 && (int)arg1 != 0/ { @err[probefunc, (int)arg1] = count(); }
fbt:vmm:vm_exitinfo:return /pid == $1/ { @ex[*(int *)arg1] = count(); }
vmm:svm:nested:vmexit /pid == $1/ { @l2x[arg1, arg3] = count(); }
vmm:svm:nested:npf /pid == $1/ { @npf[arg1] = count(); @npfpage[arg2 & 0xfffffffffffff000, arg3] = count(); }
/* Distinct L2 pages: NPFs beyond these refault a page L0 already mapped. */
vmm:svm:nested:npf /pid == $1 && !npfseen[arg2 & 0xfffffffffffff000]/ { npfseen[arg2 & 0xfffffffffffff000] = 1; @npfdist = count(); }
/* What each NPF installed: L2 GPA, L1 GPA, NPT12 permissions, access. */
fbt:vmm:svm_nested_npt_root_populate:entry /pid == $1/ { @pop[arg2, arg3, arg4 & 0xff, arg5 & 0xff] = count(); }
/* NPT02 discards, and the VMCB12 ASID / TLB_CONTROL of each VMRUN. */
fbt:vmm:svm_nested_npt_root_clear:entry /pid == $1/ { @clr = count(); }
fbt:vmm:svm_nested_npt_root_vmrun:entry /pid == $1/ { @vmrun[arg1 & 0xffffffff, arg4 & 0xff] = count(); }
vmm:svm:nested:failure /pid == $1/ { @fail[arg1, arg2, arg3, arg4] = count(); }
vmm:kernel:internal_exit:handled /pid == $1 && arg1 != 0/ { @ie[arg1] = count(); }
tick-$2s { exit(0); }
END {
	trunc(@fn, 60);
	trunc(@npfpage, 20);
	trunc(@pop, 20);
	trunc(@vmrun, 10);
	printf("== fbt-top60\n"); printa("fn %s %@d\n", @fn);
	printf("== nested-errors fn errno\n"); printa("err %s %d %@d\n", @err);
	printf("== nested-validity-false fn\n"); printa("vf %s %@d\n", @vf);
	printf("== exitinfo-previous-exitcode\n"); printa("ex %d %@d\n", @ex);
	printf("== l2-exits vcpu code\n"); printa("l2x %d 0x%x %@d\n", @l2x);
	printf("== nested-npf vcpu\n"); printa("npf %d %@d\n", @npf);
	printf("== nested-npf distinct L2 pages\n"); printa("npfdist %@d\n", @npfdist);
	printf("== nested-npf top L2 page info1\n"); printa("npfpage 0x%x 0x%x %@d\n", @npfpage);
	printf("== npt02-populate top l2gpa l1gpa perms access\n"); printa("pop 0x%x 0x%x %d %d %@d\n", @pop);
	printf("== npt02-clears\n"); printa("clears %@d\n", @clr);
	printf("== l1-vmrun top asid tlb_ctrl\n"); printa("vmrun %d %d %@d\n", @vmrun);
	printf("== nested-failure vcpu error code kind\n"); printa("fail %d %d 0x%x %d %@d\n", @fail);
	printf("== internal-exit-errors\n"); printa("ie %d %@d\n", @ie);
}
EOD
}

# l0diag_bg SECS OUT CMD...: run CMD in the background, wait at most SECS;
# a command still running then is reported BLOCKED and left alone.
l0diag_bg()
{
	lb_s=$1 lb_o=$2; shift 2
	( "$@" > "$lb_o" 2>&1; echo "rc=$?" >> "$lb_o" ) &
	lb_p=$! lb_t=0
	while kill -0 $lb_p 2>/dev/null && [ $lb_t -lt "$lb_s" ]; do sleep 1; lb_t=$((lb_t + 1)); done
	kill -0 $lb_p 2>/dev/null && { echo "BLOCKED after ${lb_s}s (still running)" >> "$lb_o"; return 1; }
	return 0
}

# l0diag_snap VM PID DIR TAG SECS NCPU: one capture; appends a summary line.
l0diag_snap()
{
	ls_vm=$1 ls_pid=$2 ls_dir=$3 ls_tag=$4 ls_secs=$5 ls_ncpu=$6
	ls_f=$ls_dir/$ls_tag
	kill -0 "$ls_pid" 2>/dev/null || { echo "$ls_tag: L1 bhyve pid $ls_pid gone" >> "$ls_dir/summary.txt"; return 0; }
	{
		echo "== l0diag $ls_tag $(date -u +%Y-%m-%dT%H:%M:%SZ) vm=$ls_vm pid=$ls_pid"
		echo "-- threads"; ps -H -o lwp,state,%cpu,time,wchan,tdname -p "$ls_pid" 2>&1
		echo "-- procstat -kk"; timeout -k 5 20 procstat -kk "$ls_pid" 2>&1
	} > "$ls_f.threads.txt"
	if [ "${HT_L0DIAG_DTRACE:-yes}" = yes ]; then
		l0diag_dscript > "$ls_dir/l0diag.d"
		timeout -k 5 $((ls_secs + 40)) dtrace -Z -s "$ls_dir/l0diag.d" "$ls_pid" "$ls_secs" > "$ls_f.dtrace.txt" 2> "$ls_f.dtrace.err"
		echo "rc=$?" >> "$ls_f.dtrace.err"
	else
		: > "$ls_f.dtrace.txt"
		echo "disabled for isolation (HT_L0DIAG_DTRACE=no)" > "$ls_f.dtrace.err"
	fi
	# vCPU queries last: they force each vCPU to a userland boundary.
	# A query that returns an error (gen6: "--vcpu" is not a bhyvectl
	# option) is reported as failed, not as a vCPU that never returned.
	ls_b="" ls_e="" ls_v=0
	while [ $ls_v -lt "$ls_ncpu" ]; do
		if l0diag_bg ${HT_L0DIAG_QSECS:-15} "$ls_f.vcpu$ls_v.txt" timeout -k 2 10 bhyvectl --vm="$ls_vm" --cpu=$ls_v \
		    --get-rip --get-intinfo --get-vmcb-exit-details --get-vmcb-virq --get-vmcb-asid --get-vmcb-tlb-ctrl --get-stats; then
			grep -q '^rc=0' "$ls_f.vcpu$ls_v.txt" 2>/dev/null || ls_e="$ls_e $ls_v"
		else
			ls_b="$ls_b $ls_v"
		fi
		ls_v=$((ls_v + 1))
	done
	l0diag_summary "$ls_tag" "$ls_f" "$ls_b" "$ls_e" >> "$ls_dir/summary.txt"
}

# l0diag_summary TAG PREFIX BLOCKED: one line from a capture's files.
l0diag_summary()
{
	lu_f=$2
	if grep -q '^disabled for isolation' "$lu_f.dtrace.err" 2>/dev/null; then
		echo "$1: DTrace disabled for isolation; see $lu_f.threads.txt and $lu_f.vcpu*.txt; vCPU queries blocked:${3:- none}; failed:${4:- none}"
		return
	fi
	# procstat -kk: PID TID COMM "vcpu N" frames...; name the first three
	# frames below the scheduler for every vCPU thread that is asleep.
	lu_sleep=$(awk '$3 == "bhyve" && $4 == "vcpu" && / mi_switch/ {
		o = "vcpu" $5 ":"; k = 0
		for (i = 6; i <= NF && k < 3; i++) {
			f = $i; sub(/\+0x[0-9a-f]+$/, "", f)
			if (f ~ /^(mi_switch|_sleep|sleepq_.*|_cv_.*|msleep.*|sched_.*)$/) continue
			o = o (k ? "<" : "") f; k++
		}
		print o }' "$lu_f.threads.txt" 2>/dev/null | head -4 | tr '\n' ' ')
	lu_top=$(awk '$1 == "fn" {print $2 "=" $3}' "$lu_f.dtrace.txt" 2>/dev/null | sort -t= -k2 -n -r | head -3 | tr '\n' ' ')
	lu_l2x=$(awk '$1 == "l2x" {n += $4} END {print n + 0}' "$lu_f.dtrace.txt" 2>/dev/null)
	lu_npf=$(awk '$1 == "npf" {n += $3} END {print n + 0}' "$lu_f.dtrace.txt" 2>/dev/null)
	lu_err=$(awk '$1 == "err" {print $2 "=" $3 "x" $4}' "$lu_f.dtrace.txt" 2>/dev/null | head -3 | tr '\n' ' ')
	lu_vf=$(awk '$1 == "vf" {print $2 "x" $3}' "$lu_f.dtrace.txt" 2>/dev/null | head -3 | tr '\n' ' ')
	lu_fail=$(awk '$1 == "fail" {n += $6} END {print n + 0}' "$lu_f.dtrace.txt" 2>/dev/null)
	# Refault ratio: NPFs per distinct L2 page; the top page and its info1.
	lu_dist=$(awk '$1 == "npfdist" {n = $2} END {print n + 0}' "$lu_f.dtrace.txt" 2>/dev/null)
	lu_rep=$(awk -v n="$lu_npf" -v d="$lu_dist" 'BEGIN {if (d > 0) printf "%.1f", n / d; else print "-"}')
	lu_pg=$(awk '$1 == "npfpage" && $4 + 0 > m {m = $4 + 0; p = $2 " info1 " $3 " x" $4} END {print p}' "$lu_f.dtrace.txt" 2>/dev/null)
	lu_clr=$(awk '$1 == "clears" {n = $2} END {print n + 0}' "$lu_f.dtrace.txt" 2>/dev/null)
	lu_drc=$(sed -n 's/^rc=//p' "$lu_f.dtrace.err" 2>/dev/null | tail -1)
	echo "$1: sleeping vCPU threads: ${lu_sleep:-none}; dtrace rc=${lu_drc:-?} top: ${lu_top:-none}; L2 exits ${lu_l2x:-0}, nested NPF ${lu_npf:-0} over ${lu_dist:-0} L2 pages (x${lu_rep} per page, top ${lu_pg:-none}), NPT02 clears ${lu_clr:-0}, nested failures ${lu_fail:-0}; nested errors: ${lu_err:-none}; false validity checks: ${lu_vf:-none}; vCPU queries blocked:${3:- none}; failed:${4:- none}"
}

# l0diag_watch VM CONSOLE FROMLINE DIR NCPU MAXWAIT: wait for L1's console to
# show the L2 bhyve stage after line FROMLINE, then capture at the offsets in
# HT_L0DIAG_AT (default "0 60 300"; seconds after the stage line), each with
# HT_L0DIAG_SECS (20) of DTrace.  DIR/stop ends it early (L2 run finished).
l0diag_watch()
{
	lw_vm=$1 lw_con=$2 lw_from=$3 lw_dir=$4 lw_ncpu=$5 lw_max=$6
	mkdir -p "$lw_dir"; : > "$lw_dir/summary.txt"
	lw_t=0
	until tail -n +"$lw_from" "$lw_con" 2>/dev/null | grep -q 'L2 stage: bhyve ('; do
		[ -e "$lw_dir/stop" ] && { echo "no capture: the L2 run ended before its bhyve stage" >> "$lw_dir/summary.txt"; return 0; }
		[ $lw_t -ge "$lw_max" ] && { echo "no capture: L2 bhyve stage not seen on L1's console in ${lw_max}s" >> "$lw_dir/summary.txt"; return 0; }
		sleep 2; lw_t=$((lw_t + 2))
	done
	lw_pid=$(cat "$HT_WORK/$lw_vm.pid" 2>/dev/null)
	lw_t0=$(date +%s)
	for lw_at in ${HT_L0DIAG_AT:-0 60 300}; do
		while [ $(( $(date +%s) - lw_t0 )) -lt "$lw_at" ]; do
			[ -e "$lw_dir/stop" ] && return 0
			sleep 2
		done
		[ -e "$lw_dir/stop" ] && return 0
		l0diag_snap "$lw_vm" "$lw_pid" "$lw_dir" "t+${lw_at}s" "${HT_L0DIAG_SECS:-20}" "$lw_ncpu"
	done
}

# Read validated OTLP metric output, not stdout or event/resource names.
ht_otlp_has_count()
{
	awk -v tag="$2" '$1 == "point" && $2 == "dtrace.dtrace.count" &&
	    $3 == "[key.0=" tag "]" && $4 ~ /^[0-9]+$/ && $4 + 0 > 0 { found = 1 } END { exit !found }' "$1"
}

# Publish parsed OTLP evidence only if every captured document validates.
ht_otlp_parse()
{
	_hop_dir=$1 _hop_out=$2
	rm -f "$_hop_out"
	: > "$_hop_out.errors"
	_hop_tmp=$(mktemp "$_hop_out.tmp.XXXXXX") || return 1
	_hop_any=no
	for _hop_file in "$_hop_dir"/*.json; do
		[ -f "$_hop_file" ] || continue
		_hop_any=yes
		if ! "$HT_KIT/bin/otlp_json_validate" "$_hop_file" >> "$_hop_tmp" 2>> "$_hop_out.errors"; then
			rm -f "$_hop_tmp"
			return 1
		fi
	done
	if [ "$_hop_any" != yes ]; then
		echo "no OTLP JSON documents" >> "$_hop_out.errors"
		rm -f "$_hop_tmp"
		return 1
	fi
	mv "$_hop_tmp" "$_hop_out"
}

# Check that no interface already has an address in the requested /24.
# Do not destroy existing interfaces: they may belong to another live run.
ht_private_net_preflight()
{
	_hnp_prefix=$1 _hnp_out=$2
	HT_NET_CONFLICT=""
	if ! ifconfig -a > "$_hnp_out.interfaces" 2>&1; then
		HT_NET_CONFLICT="cannot inspect host interfaces; see $_hnp_out.interfaces"
		return 1
	fi
	netstat -rn -f inet > "$_hnp_out.routes" 2>&1
	_hnp_used=$(awk -v prefix="$_hnp_prefix." '
	    /^[^[:space:]]/ { iface = $1; sub(/:$/, "", iface) }
	    $1 == "inet" && index($2, prefix) == 1 { print iface "=" $2 }
	    ' "$_hnp_out.interfaces")
	if [ -n "$_hnp_used" ]; then
		HT_NET_CONFLICT="private subnet $_hnp_prefix.0/24 already used by $_hnp_used; inspect the existing run before retrying"
		return 1
	fi
	return 0
}

# Read-only diagnostics. Each external query is bounded independently, with
# stderr and status retained even when a command is absent or times out.
ht_net_capture()
(
	file=$1; shift
	printf 'start=%s command=' "$(date -u +%FT%TZ)" > "$file"
	printf ' %s' "$@" >> "$file"
	printf '\n' >> "$file"
	timeout -k 1 5 "$@" >> "$file" 2>&1
	rc=$?
	printf 'end=%s rc=%s\n' "$(date -u +%FT%TZ)" "$rc" >> "$file"
)

ht_net_diagnostics() # OUTPUT-PREFIX BRIDGE TAP GUEST-IP
(
	out=$1 br=$2 tap=$3 peer=$4
	ht_net_capture "$out.interfaces" ifconfig -a
	ht_net_capture "$out.routes" netstat -rn -f inet
	ht_net_capture "$out.route-to-guest" route -n get -inet "$peer"
	ht_net_capture "$out.arp" arp -an
	ht_net_capture "$out.counters" netstat -inb
	ht_net_capture "$out.bridge" ifconfig "$br" addr
	ht_net_capture "$out.tap" ifconfig "$tap"
	ht_net_capture "$out.bridge-sysctls" sysctl net.link.bridge.pfil_member net.link.bridge.pfil_bridge
)

# Keep the original ICMP-only verdict: diagnostics cannot turn a failure into
# a pass, and a missing/truncated ping summary is a failure.
ht_net_ping_ok()
{
	grep -Eq '^[[:space:]]*[1-9][0-9]* packets transmitted, [1-9][0-9]* packets received, 0\.0% packet loss$' "$1"
}
