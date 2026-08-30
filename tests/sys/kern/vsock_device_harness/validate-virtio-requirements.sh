#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
catalog=${1:-"$script_dir/virtio-1.4-requirements.tsv"}
activation_catalog=${4:-"$script_dir/virtio-feature-activation.tsv"}
test_dir=${2:-"$script_dir"}
oracle=$test_dir/virtio_1_4_spec.h
compat_oracle=$test_dir/bhyve_virtio_compat.h
source_root=${3:-}

if [ -z "$source_root" ]; then
	for candidate in "$test_dir/../../../.." /usr/src; do
		if [ -r "$candidate/sys/dev/virtio/mmio/virtio_mmio.c" ]; then
			source_root=$candidate
			break
		fi
	done
fi

# This is a source-to-test traceability audit, not a self-contained runtime
# device test.  In particular it checks production sources, the qualification
# manifest, and the durable review record against the installed test fixtures.
# Do not turn a missing or mismatched source tree into a later, misleading
# missing-manifest diagnostic.
if [ -z "$source_root" ] ||
    [ ! -r "$source_root/sys/dev/virtio/mmio/virtio_mmio.c" ] ||
    [ ! -r "$source_root/usr.sbin/bhyve/virtio.c" ]; then
	echo "virtio requirements: requires a source tree matching the installed test suite" >&2
	exit 1
fi
lab_manifest="$source_root/tests/sys/kern/vsock_e2e/virtio-lab.yaml"
review_prompt="$script_dir/VIRTIO_1_4_FULL_REVIEW_PROMPT.md"
validation_record="$source_root/docs/bhyve-virtio-1.4-validation-review.md"
harness_runner="$script_dir/run.sh"
snapshot_model_runner="$script_dir/run-snapshot-model.sh"
harness_makefile="$script_dir/Makefile"

test -r "$catalog" || {
	echo "virtio requirements: cannot read $catalog" >&2
	exit 1
}
test -r "$oracle" || {
	echo "virtio requirements: cannot read independent oracle $oracle" >&2
	exit 1
}
test -r "$compat_oracle" || {
	echo "virtio requirements: cannot read compatibility oracle $compat_oracle" >&2
	exit 1
}
test -r "$activation_catalog" || {
	echo "virtio requirements: cannot read feature activation ledger $activation_catalog" >&2
	exit 1
}
test -r "$lab_manifest" || {
	echo "virtio requirements: cannot read qualification manifest $lab_manifest" >&2
	exit 1
}
test -r "$review_prompt" || {
	echo "virtio requirements: cannot read review procedure $review_prompt" >&2
	exit 1
}
test -r "$validation_record" || {
	echo "virtio requirements: cannot read validation record $validation_record" >&2
	exit 1
}
test -r "$harness_runner" || {
	echo "virtio requirements: cannot read rootless harness $harness_runner" >&2
	exit 1
}
test -x "$snapshot_model_runner" || {
	echo "virtio requirements: cannot execute snapshot model runner $snapshot_model_runner" >&2
	exit 1
}
test -r "$harness_makefile" || {
	echo "virtio requirements: cannot read harness Makefile $harness_makefile" >&2
	exit 1
}

# Device-unit fixtures deliberately use a small VirtQueue model, but its
# request token must not omit lifecycle identity carried by the production
# contract.  Otherwise a device test can compile while silently bypassing
# split tail-return or packed completion fencing exercised by the real core.
production_virtio_header=$source_root/usr.sbin/bhyve/virtio.h
mock_virtio_header=$test_dir/virtio.h
for request_member in split_avail_next queue_layout queue_generation; do
	rg -q "[[:space:]]$request_member;" "$production_virtio_header" || {
		echo "virtio requirements: production vi_req lacks $request_member" >&2
		exit 1
	}
	rg -q "[[:space:]]$request_member;" "$mock_virtio_header" || {
		echo "virtio requirements: mock vi_req lacks $request_member" >&2
		exit 1
	}
done
echo "virtio requirements: mock request lifecycle identity matches production"

# Every production callback which exposes an encoded device configuration
# must use the common alignment-safe little-endian decoder.  In particular,
# copying one or two bytes directly into a host uint32_t passes on the current
# little-endian builder while reversing the numeric MMIO value on a future
# big-endian host.
for config_model in pci_virtio_9p.c pci_virtio_balloon.c \
    pci_virtio_block.c pci_virtio_console.c pci_virtio_fs.c \
    pci_virtio_gpu.c pci_virtio_input.c pci_virtio_iommu.c \
    pci_virtio_mem.c pci_virtio_net.c pci_virtio_pmem.c \
    pci_virtio_scsi.c pci_virtio_snd.c pci_virtio_vsock.c; do
	rg -q -F 'vi_config_read_le(' \
	    "$source_root/usr.sbin/bhyve/$config_model" || {
		echo "virtio requirements: $config_model bypasses vi_config_read_le" >&2
		exit 1
	}
done
for guarded_model in pci_virtio_balloon.c pci_virtio_input.c; do
	rg -q -U 'if \(retval == NULL\)[[:space:]]*return \(EINVAL\);[[:space:]]*\*retval = 0;' \
	    "$source_root/usr.sbin/bhyve/$guarded_model" || {
		echo "virtio requirements: $guarded_model dereferences a nullable config output" >&2
		exit 1
	}
done
if rg -n -U 'cfgread\([^)]*\)[[:space:]]*\{([^}]|}[[:space:]]*else)*memcpy\((retval|value)' \
    "$source_root/usr.sbin/bhyve"/pci_virtio_*.c; then
	echo "virtio requirements: device cfgread copies encoded bytes into a host integer" >&2
	exit 1
fi
echo "virtio requirements: device configuration reads use the portable decoder"

# The console driver posts receive storage while newbus is attaching, but it
# must not notify or issue DEVICE_READY until the transport has published
# DRIVER_OK.  Its synchronous control and tty-output queues also carry
# caller-owned stack buffers, so neither path may use virtqueue_poll()'s
# unbounded wait: failure must reset and reclaim the descriptor before return.
console_driver=$source_root/sys/dev/virtio/console/virtio_console.c
rg -q -F 'DEVMETHOD(virtio_attach_completed, vtcon_attach_completed)' \
    "$console_driver" || {
	echo "virtio requirements: console lacks post-DRIVER_OK activation" >&2
	exit 1
}
console_attach=$(sed -n '/^vtcon_attach(device_t dev)/,/^}/p' \
    "$console_driver")
if printf '%s\n' "$console_attach" | \
    rg -q 'virtqueue_notify|vtcon_enable_interrupts|vtcon_ctrl_send_control'; then
	echo "virtio requirements: console uses the device before DRIVER_OK" >&2
	exit 1
fi
console_completed=$(sed -n \
    '/^vtcon_attach_completed(device_t dev)/,/^}/p' "$console_driver")
for contract in \
    'virtqueue_notify(sc->vtcon_ctrl_rxvq)' \
    'virtqueue_notify(port->vtcport_invq)' \
    'vtcon_enable_interrupts(sc)' \
    'VIRTIO_CONSOLE_DEVICE_READY'; do
	printf '%s\n' "$console_completed" | rg -q -F "$contract" || {
		echo "virtio requirements: console activation lacks: $contract" >&2
		exit 1
	}
done
for bounded_function in vtcon_ctrl_poll vtcon_port_out; do
	bounded_body=$(sed -n "/^${bounded_function}(/,/^}/p" \
	    "$console_driver")
	for contract in \
	    'sbinuptime() + VTCON_IO_TIMEOUT' \
	    'DELAY(VTCON_POLL_DELAY_US)' \
	    'atomic_set_32(&sc->vtcon_flags, VTCON_FLAG_FAILED)' \
	    'virtio_stop(sc->vtcon_dev)' \
	    'virtqueue_drain(vq, &last)'; do
		printf '%s\n' "$bounded_body" | rg -q -F "$contract" || {
			echo "virtio requirements: $bounded_function lacks: $contract" >&2
			exit 1
		}
	done
	if printf '%s\n' "$bounded_body" |
	    rg -q 'virtqueue_poll|pause(_sbt)?|msleep|cv_wait'; then
		echo "virtio requirements: $bounded_function is unbounded or sleeps while lock-constrained" >&2
		exit 1
	fi
done
echo "virtio requirements: console activation and synchronous I/O are bounded"

# run.sh deliberately rebuilds the real source fixtures instead of relying on
# a stale installed binary.  Keep its source set inside PACKAGEFILES: an ATF
# registration alone only installs an executable and cannot make the
# rootless installed-harness path reproducible.  Parse the payload lists,
# rather than accepting a coincidental mention in a CFLAGS or CLEANFILES rule.
missing_harness_sources=$(awk '
NR == FNR {
	if ($0 ~ /^VIRTIO_VALIDATION_FILES=/ ||
	    $0 ~ /^SANITIZER_HARNESS_FILES=/)
		payload = 1
	if ($0 ~ /^VIRTIO_REQUIREMENTS_COMPANION_FILES=/)
		payload = 0
	if (payload) {
		for (i = 1; i <= NF; i++) {
			entry = $i
			sub(/\\$/, "", entry)
			if (entry ~ /\.c$/)
				installed[entry] = 1
		}
	}
	next
}
{
	line = $0
	while (match(line, /"\$here\/[^" ]+\.c"/)) {
		entry = substr(line, RSTART, RLENGTH)
		sub(/^"\$here\//, "", entry)
		sub(/"$/, "", entry)
		required[entry] = 1
		line = substr(line, RSTART + RLENGTH)
	}
}
END {
	for (entry in required)
		if (!(entry in installed))
			print entry
}' "$harness_makefile" "$harness_runner")
if [ -n "$missing_harness_sources" ]; then
	echo "virtio requirements: installed harness payload omits source fixture(s):" >&2
	printf '%s\n' "$missing_harness_sources" >&2
	exit 1
fi
echo "virtio requirements: installed harness source payload is complete"

# The sound PCI test includes the production snapshot callback only when the
# snapshot build option is defined.  Keep the installed ATF configuration and
# the rootless harness aligned: otherwise the latter can report a green sound
# lane while silently compiling out the callback-level save/validate/restore
# cases.
rg -q -F 'CFLAGS.virtio_snd_test+= -DBHYVE_SNAPSHOT' "$harness_makefile" || {
	echo "virtio requirements: sound ATF test omits BHYVE_SNAPSHOT" >&2
	exit 1
}
awk '
/^"\$cc"/ {
	block = $0 "\n"
	inblock = 1
	next
}
inblock {
	block = block $0 "\n"
	if ($0 ~ /virtio_snd_test\.c/) {
		if (block ~ /-DBHYVE_SNAPSHOT/)
			found = 1
		inblock = 0
	} else if ($0 ~ /^$/) {
		inblock = 0
	}
}
END {
	exit(found ? 0 : 1)
}' "$harness_runner" || {
	echo "virtio requirements: rootless sound test omits BHYVE_SNAPSHOT" >&2
	exit 1
}
echo "virtio requirements: sound snapshot callback is enabled in both test lanes"

# GPU's PCI envelope carries display geometry, event state, and the complete
# portable 2D model.  Keep its direct callback test in the same snapshot
# configuration in both test lanes; helper-only geometry coverage cannot
# prove validate-before-publication or restore ordering.
rg -q -F 'CFLAGS.virtio_gpu_2d_pci_test+= -DBHYVE_SNAPSHOT' \
    "$harness_makefile" || {
	echo "virtio requirements: GPU ATF test omits BHYVE_SNAPSHOT" >&2
	exit 1
}
awk '
/^"\$cc"/ {
	block = $0 "\n"
	inblock = 1
	next
}
inblock {
	block = block $0 "\n"
	if ($0 ~ /virtio_gpu_2d_pci_test\.c/) {
		if (block ~ /-DBHYVE_SNAPSHOT/)
			found = 1
		inblock = 0
	} else if ($0 ~ /^$/) {
		inblock = 0
	}
}
END {
	exit(found ? 0 : 1)
}' "$harness_runner" || {
	echo "virtio requirements: rootless GPU test omits BHYVE_SNAPSHOT" >&2
	exit 1
}
echo "virtio requirements: GPU snapshot callback is enabled in both test lanes"

# The review procedure is part of the definition of done.  Keep the two
# independent kernel traversals, the private-interface inventory, and the
# composed-boundary pass machine checked so a documentation cleanup cannot
# silently collapse them back into one self-confirming review.
for phase in \
    'Pass 15: second independent kernel implementation review' \
    'Pass 16: non-standard interfaces and operational policy review' \
    'Pass 17: final post-private kernel replay' \
    'Pass 18: non-standard boundary composition' \
    'Pass 19: second independent non-standard inventory replay' \
    'Pass 20: kernel/private adapter failure-atomicity replay' \
    'Pass 21: withheld, unsupported, and implementation-defined behavior review' \
    'Pass 22: second final-source kernel implementation review' \
    'Pass 23: second final-source non-standard and private-policy review' \
    'Pass 24: repeated common-kernel primitive lifecycle review' \
    'Pass 25: repeated private and non-standard activation review' \
    'Pass 26: terminal production-kernel source review' \
    'Pass 27: terminal non-standard and private-contract review' \
    'Pass 28: independent common-production-kernel contract replay' \
    'Pass 29: independent non-standard decoder and policy replay' \
    'Pass 30: second kernel-source replay' \
    'Pass 31: non-standard behavior and seam inventory' \
    'Pass 32: kernel callback identity and recycle-boundary review' \
    'Pass 33: independent common-kernel contract replay' \
    'Pass 34: independent non-standard policy and decoder replay' \
    'Pass 35: doubled final kernel-code and device-lifecycle replay' \
	'Pass 36: doubled non-standard policy, operator, and test replay' \
	'Pass 37: terminal kernel mutation and rollback review' \
	'Pass 38: terminal implementation-defined behavior replay' \
	'Pass 39: withheld-feature and host-policy boundary replay' \
	'Pass 40: independent feature-activation and oracle replay' \
	'Pass 41: independent production-kernel implementation replay' \
	'Pass 42: independent implementation-defined contract replay' \
	'Pass 43: clean-room kernel invariant replay' \
	'Pass 44: clean-room non-standard contract replay'; do
	rg -q -F "$phase" "$review_prompt" || {
		echo "virtio requirements: required review phase is missing: $phase" >&2
		exit 1
	}
done
# A terminal review phase must be unique as well as present.  Otherwise a
# stale duplicate heading could satisfy the textual check while leaving the
# documented cycle ambiguous about the authoritative final traversal.
for number in 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44; do
	# The review document uses level-three headings for the detailed review
	# passes and level-two headings for the final additions.  Count either
	# form, and do not let rg's zero-match status bypass the diagnostic under
	# set -e; that previously made this validator return success after the two
	# early snapshot checks without checking the remaining requirements.
	count=$(rg -c "^#{2,3} Pass ${number}:" "$review_prompt" || true)
	count=${count:-0}
	if [ "$count" -ne 1 ]; then
		echo "virtio requirements: review phase ${number} must occur exactly once" >&2
		exit 1
	fi
done
rg -q -F 'one complete Pass 0 through Pass 44 cycle' "$review_prompt" || {
	echo "virtio requirements: termination may bypass Passes 24 through 44" >&2
	exit 1
}
if rg -q -F 'one complete Pass 0 through Pass 42 cycle' "$review_prompt"; then
	echo "virtio requirements: obsolete Pass 42 termination remains" >&2
	exit 1
fi
if rg -q -F 'one complete Pass 0 through Pass 40 cycle' "$review_prompt"; then
	echo "virtio requirements: obsolete Pass 40 termination remains" >&2
	exit 1
fi
if rg -q -F 'one complete Pass 0 through Pass 36 cycle' "$review_prompt"; then
	echo "virtio requirements: obsolete Pass 36 termination remains" >&2
	exit 1
fi
if rg -q -F 'one complete Pass 0 through Pass 32 cycle' "$review_prompt"; then
	echo "virtio requirements: obsolete Pass 32 termination remains" >&2
	exit 1
fi
if rg -q -F 'one complete Pass 0 through Pass 27 cycle' "$review_prompt"; then
	echo "virtio requirements: obsolete Pass 27 termination remains" >&2
	exit 1
fi
rg -q -F 'Passes H through AC require separately recorded clean results' \
    "$source_root/tests/sys/kern/vsock_e2e/DEEP_REVIEW_PROMPT.md" || {
	echo "virtio requirements: AF_VSOCK termination may bypass Passes V through AC" >&2
	exit 1
}
rg -q -F 'invalidates both Passes 15 and 17' \
    "$review_prompt" || {
	echo "virtio requirements: review restart rule is missing" >&2
	exit 1
}
rg -q 'restarts Passes[[:space:]]+24 through 36' "$review_prompt" || {
	echo "virtio requirements: extended review restart rule is missing" >&2
	exit 1
}
rg -q -F 'The cycle closes only after a final synthesis' "$review_prompt" || {
	echo "virtio requirements: final kernel/private review synthesis is missing" >&2
	exit 1
}
rg -q -F 'untracked production, header, test, fixture, ledger, script, and' \
    "$review_prompt" || {
	echo "virtio requirements: final review manifest omits untracked files" >&2
	exit 1
}
rg -q -F 'git diff --name-only' "$review_prompt" || {
	echo "virtio requirements: final review still permits a diff-only manifest" >&2
	exit 1
}
echo "virtio requirements: doubled kernel and private-boundary reviews required"

# The durable validation record must retain the same final-source double
# review shape as the executable procedure.  This prevents a future summary
# edit from claiming completion after only the producer-side traversal.
for phase in \
    'Pass 17: post-fix shared-kernel execution-context review' \
    'Pass 18: post-fix non-standard consumer and composition review' \
    'Pass 19: independent final-source kernel reverse-lifetime review' \
    'Pass 20: independent final-source private-boundary rediscovery' \
    'Pass 21: repeated common-kernel primitive lifecycle review' \
    'Pass 22: repeated private/non-standard activation review'; do
	rg -q -F "$phase" "$validation_record" || {
		echo "virtio requirements: validation record phase is missing: $phase" >&2
		exit 1
	}
done
rg -q -F 'restarts Passes 17 through 22' "$validation_record" || {
	echo "virtio requirements: validation record double-review restart rule is missing" >&2
	exit 1
}
rg -q -F 'common-contract and decoder-policy replay phases' "$validation_record" &&
    rg -q -F 'Either pass restarts the complete final' "$validation_record" || {
	echo "virtio requirements: validation record omits terminal common/private replay" >&2
	exit 1
}
rg -q -F 'second common-kernel and non-standard policy replays' \
    "$validation_record" &&
    rg -q -F 'A correction in either phase restarts' "$validation_record" || {
	echo "virtio requirements: validation record omits second common/private replay" >&2
	exit 1
}
echo "virtio requirements: final-source review record requires two kernel and two private passes"

# The durable review record must also identify the complete terminal sequence.
# Keep the detailed 37/38 replay phases and the clean-room 43/44 replays
# visible here: checking only a closing sentence would let a future edit
# collapse the rollback, implementation-defined, and independent traversals.
rg -q -F 'every terminal phase, Passes' "$validation_record" &&
    rg -q -F '35 through 42, exactly once' "$validation_record" &&
    rg -q -F 'Passes 37 and 38 provide the mutation/rollback' \
    "$validation_record" &&
    rg -q -F 'validator rejects an obsolete completion' "$validation_record" &&
    rg -q -F 'rule at Pass 36 or Pass 40' "$validation_record" || {
	echo "virtio requirements: validation record omits the complete terminal review sequence" >&2
	exit 1
}
echo "virtio requirements: validation record includes all terminal review phases"

rg -q -F 'doubled clean-room kernel and non-standard replays' \
    "$validation_record" &&
    rg -q -F 'Passes 43 and 44' "$validation_record" &&
    rg -q -F 'Both phases restart the final' "$validation_record" || {
	echo "virtio requirements: validation record omits clean-room terminal replays" >&2
	exit 1
}
echo "virtio requirements: validation record includes clean-room terminal replays"

# The roadmap is the implementation plan that drives the scoped prompt.  Keep
# the two additional terminal passes visible there as well: otherwise the
# executable review procedure can require them while a later planning update
# accidentally schedules only the earlier mutation/policy passes.
for roadmap_phase in \
    'Second production-kernel replay.' \
    'Second implementation-defined contract replay.'; do
	rg -q -F "$roadmap_phase" "$source_root/usr.sbin/bhyve/VIRTIO_1_4_ROADMAP.md" || {
		echo "virtio requirements: roadmap phase is missing: $roadmap_phase" >&2
		exit 1
	}
done
echo "virtio requirements: roadmap includes the doubled terminal review phases"

# The aggregate device harness is deliberately broad; retain a compact,
# independently enumerable checkpoint lane so save-state tests are visible
# even when a future device-only runner is split or sharded.
for snapshot_test in checkpoint_compat_test checkpoint_machine_test \
    pci_checkpoint_test snapshot_identity_test snapshot_portable_test \
    snapshot_manifest_test; do
	rg -q -F "$snapshot_test" "$snapshot_model_runner" || {
		echo "virtio requirements: snapshot model runner omits $snapshot_test" >&2
		exit 1
	}
done
rg -q -F 'PASS virtio-snapshot-model cases=' "$snapshot_model_runner" || {
	echo "virtio requirements: snapshot model runner lacks a terminal result" >&2
	exit 1
}
for snapshot_runner_contract in \
    'list_atf_cases()' \
    '"$program" -l >"$case_log" 2>&1' \
    'run_atf_case()' \
    '"$program" -r /dev/stdout "$test_case"' \
    'tail -n 1 "$case_log" | grep -qx passed' \
    'rm -f "$case_log" 2>/dev/null || :' \
    "trap 'cleanup 130' INT" \
    "trap 'cleanup 143' TERM"; do
	rg -q -F "$snapshot_runner_contract" "$snapshot_model_runner" || {
		echo "virtio requirements: snapshot model runner omits ATF result validation: $snapshot_runner_contract" >&2
		exit 1
	}
done
echo "virtio requirements: rootless snapshot model lane is independently enumerated"

# Snapshot-model callers use the same durable completion protocol as the
# broader device harness.  In particular, a detached executor needs a PID in
# RUNNING and must never retain that marker after an early failure or signal.
# Keep this separate from the ATF transcript checks above: the transcript
# proves test-case handling while RESULT_FILE proves orchestration handling.
for snapshot_result_contract in \
    'result_file=${RESULT_FILE:-}' \
    "printf 'RUNNING virtio-snapshot-model pid=%s\\n' \"\$\$\"" \
    "printf 'FAIL virtio-snapshot-model exit=%s\\n' \"\$status\"" \
    "printf 'PASS virtio-snapshot-model cases=%s\\n' \"\$passed\"" \
    "trap 'cleanup 130' INT" \
    "trap 'cleanup 143' TERM"; do
	rg -q -F "$snapshot_result_contract" "$snapshot_model_runner" || {
		echo "virtio requirements: snapshot model RESULT_FILE contract is missing: $snapshot_result_contract" >&2
		exit 1
	}
done
snapshot_pass_line=$(rg -n -F "printf 'PASS virtio-snapshot-model cases=%s\\n' \"\$passed\"" \
    "$snapshot_model_runner" | head -n 1 | cut -d: -f1)
snapshot_stdout_line=$(rg -n -F 'echo "PASS virtio-snapshot-model cases=$passed"' \
    "$snapshot_model_runner" | head -n 1 | cut -d: -f1)
case "$snapshot_pass_line:$snapshot_stdout_line" in
    *[!0-9:]*|:*)
        echo "virtio requirements: snapshot model completion ordering missing" >&2
        exit 1
        ;;
esac
if [ "$snapshot_pass_line" -ge "$snapshot_stdout_line" ]; then
    echo "virtio requirements: snapshot model publishes PASS after stdout" >&2
    exit 1
fi
echo "virtio requirements: snapshot model RESULT_FILE contract is guarded"

# RESULT_FILE is the durable contract for detached device-harness callers.
# Retain the worker PID in the nonterminal record: an external executor can
# otherwise leave a stale RUNNING marker after it has reaped the process, with
# no safe way to distinguish that state from a genuinely active harness.
for device_runner_contract in \
    "printf 'RUNNING device harness pid=%s workdir=%s\\n' \"\$\$\" \"\$work\"" \
    "printf 'FAIL device harness exit=%s workdir=%s\\n' \"\$status\"" \
    "printf '%s\\n' 'PASS device harness all tests passed'" \
    "trap 'cleanup 130' INT" \
    "trap 'cleanup 143' TERM"; do
	rg -q -F "$device_runner_contract" "$script_dir/run.sh" || {
		echo "virtio requirements: device harness RESULT_FILE contract is missing: $device_runner_contract" >&2
		exit 1
	}
done
echo "virtio requirements: device harness RESULT_FILE contract is guarded"

# RESULT_FILE is the durable executor-facing completion state.  Publish it
# before the cosmetic stdout marker so a supervisor that reaps immediately
# after the final test returns cannot retain a stale RUNNING record.
pass_line=$(rg -n -F "printf '%s\\n' 'PASS device harness all tests passed'" \
    "$script_dir/run.sh" | head -n 1 | cut -d: -f1)
stdout_line=$(rg -n -F 'echo "device harness all tests passed"' \
    "$script_dir/run.sh" | head -n 1 | cut -d: -f1)
case "$pass_line:$stdout_line" in
    *[!0-9:]*|:*)
        echo "virtio requirements: device harness completion ordering missing" >&2
        exit 1
        ;;
esac
if [ "$pass_line" -ge "$stdout_line" ]; then
    echo "virtio requirements: device harness publishes PASS after stdout" >&2
    exit 1
fi
echo "virtio requirements: device harness completion ordering validated"

sh "$script_dir/validate-virtio-nonstandard-interfaces.sh" \
    "$script_dir/virtio-nonstandard-interfaces.tsv" "$source_root"

# Keep the oracle independent from production headers.  Derived oracle
# expressions may refer only to another VIRTIO14_ value; implementation
# prefixes in the right-hand side would make a wrong implementation
# self-confirming.
awk '
/^#define[[:space:]]+VIRTIO14_/ {
	line = $0
	name = $2
	sub(/\(.*/, "", name)
	if (seen[name]++) {
		printf "virtio requirements: duplicate oracle name %s\n",
		    name > "/dev/stderr"
		errors++
	}
	while (line ~ /\\$/ && getline continuation > 0) {
		sub(/\\$/, "", line)
		line = line continuation
	}
	rhs = line
	sub(/^#define[[:space:]]+VIRTIO14_[A-Za-z0-9_]+(\([^)]*\))?[[:space:]]*/,
	    "", rhs)
	scrubbed = rhs
	gsub(/VIRTIO14_[A-Za-z0-9_]+/, "", scrubbed)
	if (scrubbed ~ /(VIRTIO_|VRING_|VTCON_|VTINPUT_|VTNET_|VTBLK_|VBH_)/) {
		printf "virtio requirements: oracle derives from implementation: %s\n",
		    line > "/dev/stderr"
		errors++
	}
	definitions++
}
END {
	if (definitions == 0) {
		print "virtio requirements: independent oracle is empty" > "/dev/stderr"
		errors++
	}
	if (errors != 0)
		exit 1
	printf "virtio requirements: %d oracle definitions checked for independence\n",
	    definitions
}
' "$oracle"

awk -F '\t' '
function validate_evidence(field, column, requirement,    count, entry, i) {
	count = split(field, evidence, ";")
	for (i = 1; i <= count; i++) {
		entry = evidence[i]
		sub(/^[[:space:]]+/, "", entry)
		sub(/[[:space:]]+$/, "", entry)
		if (entry == "-" && count == 1)
			continue
		if (entry ~ /^[A-Za-z0-9_]+_test:[A-Za-z0-9_]+$/)
			continue
		if (entry == "build:bhyve-dtrace" ||
		    entry == "build:freebsd-virtio-kmods")
			continue
		printf "virtio requirements: %s has invalid %s evidence %s\n",
		    requirement, column, entry > "/dev/stderr"
		errors++
	}
}
BEGIN {
	expected = "requirement_id\tspec_section\tlevel\tstatus\tadvertised\timplementation\tpositive_test\tnegative_test\tinterop\tnotes"
	errors = 0
}
NR == 1 {
	if ($0 != expected) {
		print "virtio requirements: invalid header" > "/dev/stderr"
		errors++
	}
	next
}
{
	rows++
	if (NF != 10) {
		printf "virtio requirements: line %d has %d fields, expected 10\n",
		    NR, NF > "/dev/stderr"
		errors++
		next
	}
	if ($1 !~ /^[A-Z0-9][A-Z0-9-]*$/) {
		printf "virtio requirements: line %d has invalid id %s\n",
		    NR, $1 > "/dev/stderr"
		errors++
	}
	if (seen[$1]++) {
		printf "virtio requirements: duplicate id %s\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($3 != "mandatory" && $3 != "optional" &&
	    $3 != "not-applicable") {
		printf "virtio requirements: %s has invalid level %s\n",
		    $1, $3 > "/dev/stderr"
		errors++
	}
	if ($4 != "implemented-tested" &&
	    $4 != "implemented-unverified" &&
	    $4 != "unsupported-optional" &&
	    $4 != "not-applicable" && $4 != "gap") {
		printf "virtio requirements: %s has invalid status %s\n",
		    $1, $4 > "/dev/stderr"
		errors++
	}
	# An unsupported optional feature is a reviewed policy exception, not a
	# generic escape hatch for an implementation gap.  Secure erase is the one
	# present exception: a generic block backend cannot promise physical erasure
	# and must not advertise the feature.  Any additional exception requires an
	# explicit validator-policy update alongside its review.
	if ($4 == "unsupported-optional") {
		if ($1 != "DEVICE-BLOCK-SECURE-ERASE" || $5 != "no") {
			printf "virtio requirements: unsupported optional feature is not an approved unadvertised exception: %s\n",
			    $1 > "/dev/stderr"
			errors++
		}
		unsupported_optional[$1]++
	}
	if ($5 != "yes" && $5 != "no" && $5 != "device-dependent") {
		printf "virtio requirements: %s has invalid advertised value %s\n",
		    $1, $5 > "/dev/stderr"
		errors++
	}
	if ($3 == "mandatory" &&
	    ($4 == "gap" || $4 == "implemented-unverified" ||
	    $4 == "unsupported-optional")) {
		printf "virtio requirements: mandatory %s is unresolved (%s)\n",
		    $1, $4 > "/dev/stderr"
		errors++
	}
	if (($5 == "yes" || $5 == "device-dependent") &&
	    $4 != "implemented-tested") {
		printf "virtio requirements: advertised %s is not tested\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($4 == "implemented-tested" &&
	    ($6 == "-" || $7 == "-")) {
		printf "virtio requirements: tested %s lacks implementation or positive test\n",
		    $1 > "/dev/stderr"
		errors++
	}
	validate_evidence($7, "positive", $1)
	validate_evidence($8, "negative", $1)
}
END {
	if (rows == 0) {
		print "virtio requirements: empty catalog" > "/dev/stderr"
		errors++
	}
	if (unsupported_optional["DEVICE-BLOCK-SECURE-ERASE"] != 1) {
		print "virtio requirements: secure-erase exception is missing or duplicated" > "/dev/stderr"
		errors++
	}
	if (errors != 0)
		exit 1
	printf "virtio requirements: %d entries validated\n", rows
}
' "$catalog"
echo "virtio requirements: optional omission policy is explicit"

# A production anchor is review evidence, not prose.  For the common
# file:symbol form, require both the named source file and the exact identifier
# to exist.  File-only and deliberately compound anchors retain their existing
# syntax, but a stale simple anchor must not let the catalog claim code which
# was renamed, removed, or never implemented.
production_refs=$(mktemp "${TMPDIR:-/tmp}/virtio-production.XXXXXX")
source_index=$(mktemp "${TMPDIR:-/tmp}/virtio-sources.XXXXXX")
awk -F '\t' '
NR > 1 {
	count = split($6, anchors, ";")
	for (i = 1; i <= count; i++) {
		anchor = anchors[i]
		sub(/^[[:space:]]+/, "", anchor)
		sub(/[[:space:]]+$/, "", anchor)
		if (anchor ~ /^[^:;[:space:]]+:[A-Za-z_][A-Za-z0-9_]*$/)
			print $1 "\t" anchor
	}
}
' "$catalog" | sort -u >"$production_refs"
find -H "$source_root/usr.sbin/bhyve" "$source_root/usr.sbin/virtiofsd" \
    "$source_root/sys" \
    "$source_root/lib" "$source_root/contrib/lib9p" \
    "$source_root/tests/sys" -type f -print \
    >"$source_index"
anchor_errors=0
while IFS="	" read -r requirement anchor; do
	file=${anchor%%:*}
	symbol=${anchor#*:}
	matches=$(awk -v suffix="/$file" '
	    length($0) >= length(suffix) &&
	    substr($0, length($0) - length(suffix) + 1) == suffix
	' "$source_index")
	if [ -z "$matches" ]; then
		echo "virtio requirements: $requirement names missing production file $file" >&2
		anchor_errors=$((anchor_errors + 1))
		continue
	fi
	found=false
	for source in $matches; do
		if rg -q "\\b${symbol}\\b" "$source"; then
			found=true
			break
		fi
	done
	if [ "$found" != true ]; then
		echo "virtio requirements: $requirement names missing production symbol $anchor" >&2
		anchor_errors=$((anchor_errors + 1))
	fi
done <"$production_refs"
rm -f "$production_refs" "$source_index"
if [ "$anchor_errors" -ne 0 ]; then
	echo "virtio requirements: $anchor_errors stale production symbol anchor(s)" >&2
	exit 1
fi
echo "virtio requirements: production symbol anchors validated"

# Device Suspend and queue reset are transport-visible optional features.  An
# implementation that adds either bit to a device's offered feature mask has
# made a lifecycle promise even when its private callbacks are intentionally
# synchronous no-ops.  Keep every such producer named in the normative ledger:
# otherwise a newly added device can inherit common lifecycle machinery
# without a reviewable explanation of its private ownership and restore
# contract.
for feature_contract in \
    'VIRTIO_F_SUSPEND:suspend' \
    'VIRTIO_F_RING_RESET:queue-reset'; do
	feature=${feature_contract%%:*}
	contract=${feature_contract#*:}
	producers=0
	for source in $(rg -l "$feature" \
	    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c | sort); do
		base=${source##*/}
		if ! rg -q -F "$base:" "$catalog"; then
			echo "virtio requirements: $contract producer lacks ledger entry: $base" >&2
			exit 1
		fi
		# Suspend is a guest-visible lifecycle promise, not merely a common
		# transport bit.  A producer must install the private quiesce and
		# resume-device callbacks.  Either callback may deliberately be the
		# documented no-op for a stateless device, but omitting it would let
		# a future device advertise suspend while bypassing the common
		# device-lifecycle transaction altogether.
		if [ "$feature" = VIRTIO_F_SUSPEND ] &&
		    (! rg -q '^[[:space:]]*\.vc_suspend[[:space:]]*=' "$source" ||
		    ! rg -q '^[[:space:]]*\.vc_resume_device[[:space:]]*=' "$source"); then
			echo "virtio requirements: suspend producer lacks lifecycle callbacks: $base" >&2
			exit 1
		fi
		producers=$((producers + 1))
	done
	if [ "$producers" -eq 0 ]; then
		echo "virtio requirements: no $contract feature producers found" >&2
		exit 1
	fi
	echo "virtio requirements: $producers $contract feature producers are ledgered"
done

# A host event source or worker can retain a device-private reference after a
# queue callback returns.  Such a model must declare its own lifecycle edge;
# accepting the common default would leave future asynchronous work outside
# the suspend/checkpoint ownership transaction.  This is deliberately a
# source relationship rather than a feature-bit check: it protects a future
# model before it decides whether Device Suspend is safe to advertise.
async_models=0
for source in $(rg -l 'mevent_add|pthread_create' \
    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c | sort); do
	base=${source##*/}
	if ! rg -q '^[[:space:]]*\.vc_suspend[[:space:]]*=' "$source" ||
	    ! rg -q '^[[:space:]]*\.vc_resume_device[[:space:]]*=' "$source"; then
		echo "virtio requirements: asynchronous model lacks lifecycle callbacks: $base" >&2
		exit 1
	fi
	async_models=$((async_models + 1))
done
if [ "$async_models" -eq 0 ]; then
	echo "virtio requirements: no asynchronous PCI VirtIO models found" >&2
	exit 1
fi

# IOMMU completion and fault callbacks come from protected endpoint DMA rather
# than a private event descriptor.  Its intentionally synchronous lifecycle
# hooks are valid only because the callback entry itself applies the same
# common fence and retains a pending notification for resume.  Keep that
# exceptional ownership rule explicit rather than making it an untested
# exemption from the worker/event-source check above.
iommu_source=$source_root/usr.sbin/bhyve/pci_virtio_iommu.c
if ! awk '
/^pci_vtiommu_callback_ready_locked\(/ { in_function = 1 }
in_function && /vs->vs_quiescing \|\| vs->vs_suspended/ { fence = 1 }
in_function && /vs->vs_checkpoint_paused/ { checkpoint = 1 }
in_function && /vq->vq_notify_pending = true/ { pending = 1 }
in_function && /^}/ { exit(fence && checkpoint && pending ? 0 : 1) }
END { if (!in_function) exit 1 }
' "$iommu_source"; then
	echo "virtio requirements: IOMMU callback path lacks lifecycle fence" >&2
	exit 1
fi
echo "virtio requirements: $async_models asynchronous models and IOMMU callbacks own lifecycle fences"

# Live feature coverage is deliberately separate from the normative
# implementation ledger.  A feature bit, a configuration value, and even
# ordinary device I/O do not prove that a distinct optional mechanism was
# selected.  Track Linux and 5BSD independently and require guest plus host
# evidence for every exercised claim.
awk -F '\t' '
function valid_status(value) {
	return value == "exercised" || value == "pending" ||
	    value == "driver-gap" || value == "not-applicable"
}
function valid_evidence(value) {
	# Evidence is an auditable source artifact plus a named assertion/path.
	# A prose token such as "passed" must never satisfy the live gate.
	return value ~ /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.+,-]+$/
}
function valid_cases(value) {
	return value == "-" ||
	    value ~ /^[a-z0-9][a-z0-9._-]*(,[a-z0-9][a-z0-9._-]*)*$/
}
BEGIN {
	expected = "feature_id\trequirement_id\tlinux_status\tlinux_guest_evidence\tfivebsd_status\tfivebsd_guest_evidence\thost_evidence\tlinux_case\tfivebsd_case\tnotes"
	gate = ENVIRON["VIRTIO_ACTIVATION_GATE"]
	if (gate == "")
		gate = "ledger"
	if (gate != "ledger" && gate != "linux" && gate != "both") {
		printf "virtio activation: invalid VIRTIO_ACTIVATION_GATE=%s\n",
		    gate > "/dev/stderr"
		errors++
	}
}
NR == 1 {
	if ($0 != expected) {
		print "virtio activation: invalid header" > "/dev/stderr"
		errors++
	}
	next
}
{
	rows++
	if (NF != 10) {
		printf "virtio activation: line %d has %d fields, expected 10\n",
		    NR, NF > "/dev/stderr"
		errors++
		next
	}
	if ($1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || seen[$1]++) {
		printf "virtio activation: invalid or duplicate feature id %s\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($2 !~ /^[A-Z0-9][A-Z0-9-]*$/) {
		printf "virtio activation: %s has invalid requirement id %s\n",
		    $1, $2 > "/dev/stderr"
		errors++
	}
	if (!valid_status($3) || !valid_status($5)) {
		printf "virtio activation: %s has invalid guest status\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if (($3 == "exercised") != ($4 != "-")) {
		printf "virtio activation: %s Linux evidence/status disagree\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($3 == "exercised" && !valid_evidence($4)) {
		printf "virtio activation: %s has unstructured Linux evidence %s\n",
		    $1, $4 > "/dev/stderr"
		errors++
	}
	if (!valid_cases($8) ||
	    ($3 == "exercised" && $8 == "-")) {
		printf "virtio activation: %s has invalid or missing Linux qualification case %s\n",
		    $1, $8 > "/dev/stderr"
		errors++
	}
	if (($5 == "exercised") != ($6 != "-")) {
		printf "virtio activation: %s 5BSD evidence/status disagree\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($5 == "exercised" && !valid_evidence($6)) {
		printf "virtio activation: %s has unstructured 5BSD evidence %s\n",
		    $1, $6 > "/dev/stderr"
		errors++
	}
	if (!valid_cases($9) ||
	    ($5 == "exercised" && $9 == "-")) {
		printf "virtio activation: %s has invalid or missing 5BSD qualification case %s\n",
		    $1, $9 > "/dev/stderr"
		errors++
	}
	if (($3 == "exercised" || $5 == "exercised") && $7 == "-") {
		printf "virtio activation: %s lacks host-path evidence\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if (($3 == "exercised" || $5 == "exercised") &&
	    !valid_evidence($7)) {
		printf "virtio activation: %s has unstructured host evidence %s\n",
		    $1, $7 > "/dev/stderr"
		errors++
	}
	if ($10 == "") {
		printf "virtio activation: %s lacks qualification notes\n",
		    $1 > "/dev/stderr"
		errors++
	}
	if ($3 != "exercised" && $3 != "not-applicable")
		linux_unresolved++
	if ($5 != "exercised" && $5 != "not-applicable")
		fivebsd_unresolved++
	if ((gate == "linux" || gate == "both") &&
	    $3 != "exercised" && $3 != "not-applicable") {
		printf "virtio activation: Linux release gate unresolved for %s (%s)\n",
		    $1, $3 > "/dev/stderr"
		errors++
	}
	if (gate == "both" &&
	    $5 != "exercised" && $5 != "not-applicable") {
		printf "virtio activation: 5BSD release gate unresolved for %s (%s)\n",
		    $1, $5 > "/dev/stderr"
		errors++
	}
	requirements[$2] = 1
}
END {
	if (rows == 0) {
		print "virtio activation: empty ledger" > "/dev/stderr"
		errors++
	}
	if (errors != 0)
		exit 1
	printf "virtio activation: %d live feature claims checked; Linux unresolved=%d, 5BSD unresolved=%d, gate=%s\n",
	    rows, linux_unresolved, fivebsd_unresolved, gate
}
' "$activation_catalog"

# An exercised feature must be part of the repeatable qualification graph.
# Case lists permit a cross-device claim (for example packed data paths) to
# name every device case rather than treating one representative device as
# proof for all devices.
scheduled_cases=$(mktemp "${TMPDIR:-/tmp}/virtio-lab-cases.XXXXXX")
awk '
/^cases:/ {
	in_cases = 1
	next
}
in_cases && /^  - id: [a-z0-9][a-z0-9._-]*$/ {
	print $3
}
' "$lab_manifest" | sort -u >"$scheduled_cases"

awk -F '\t' '
NR > 1 {
	if ($8 != "-")
		print $8
	if ($9 != "-")
		print $9
}
' "$activation_catalog" | tr ',' '\n' | sort -u |
while IFS= read -r case_id; do
	if ! grep -Fqx "$case_id" "$scheduled_cases"; then
		echo "virtio activation: qualification case is not scheduled: $case_id" >&2
		rm -f "$scheduled_cases"
		exit 1
	fi
done
rm -f "$scheduled_cases"
echo "virtio activation: qualification case references validated"

# The activation ledger is also the durable plan for work that has not yet
# been exercised.  Do not permit a pending Linux or 5BSD claim to point at a
# smoke-only, VM-free, or wrong-guest case: it would look scheduled in the
# ledger while being impossible to promote through the complete release
# qualification.  `full-qualification` is the union of release, checkpoint,
# soak, nested, audio, and checkpoint-audio; all current live guest cases use
# one of those direct profiles.  Keep that finite expansion here rather than
# teaching this shell audit a second YAML implementation.
full_qualification_cases=$(mktemp "${TMPDIR:-/tmp}/virtio-lab-full-qualification.XXXXXX")
case_executors=$(mktemp "${TMPDIR:-/tmp}/virtio-lab-executors.XXXXXX")
awk '
/^cases:/ {
	in_cases = 1
	next
}
in_cases && /^  - id: [a-z0-9][a-z0-9._-]*$/ {
	if (id != "" && qualified)
		print id
	id = $3
	qualified = 0
	next
}
in_cases && id != "" && /^    profiles: \[/ {
	profiles = $0
	sub(/^.*\[/, "", profiles)
	sub(/\].*$/, "", profiles)
	count = split(profiles, value, ",")
	for (item = 1; item <= count; item++) {
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", value[item])
		if (value[item] == "release" || value[item] == "checkpoint" ||
		    value[item] == "soak" || value[item] == "nested" ||
		    value[item] == "audio" || value[item] == "checkpoint-audio")
			qualified = 1
	}
	next
}
END {
	if (id != "" && qualified)
		print id
}
' "$lab_manifest" | sort -u >"$full_qualification_cases"
awk '
/^cases:/ {
	in_cases = 1
	next
}
in_cases && /^  - id: [a-z0-9][a-z0-9._-]*$/ {
	if (id != "")
		print id "\t" executor
	id = $3
	executor = ""
	next
}
in_cases && id != "" && /^    executor: / {
	executor = $2
	next
}
END {
	if (id != "")
		print id "\t" executor
}
' "$lab_manifest" >"$case_executors"

awk -F '\t' '
NR > 1 {
	if ($8 != "-") {
		count = split($8, cases, ",")
		for (item = 1; item <= count; item++)
			print "linux\t" cases[item]
	}
	if ($9 != "-") {
		count = split($9, cases, ",")
		for (item = 1; item <= count; item++)
			print "fivebsd\t" cases[item]
	}
}
' "$activation_catalog" | sort -u |
while IFS="$(printf '\t')" read -r guest case_id; do
	if ! grep -Fqx "$case_id" "$full_qualification_cases"; then
		echo "virtio activation: planned $guest qualification is outside full-qualification: $case_id" >&2
		rm -f "$full_qualification_cases" "$case_executors"
		exit 1
	fi
	executor=$(awk -F '\t' -v case_id="$case_id" '$1 == case_id { print $2; found = 1; exit } END { if (!found) exit 1 }' "$case_executors") || {
		echo "virtio activation: planned qualification has no executor: $case_id" >&2
		rm -f "$full_qualification_cases" "$case_executors"
		exit 1
	}
	case "$guest:$executor" in
	linux:alpine-auto|fivebsd:fivebsd-auto)
		;;
	*)
		echo "virtio activation: planned $guest qualification uses wrong executor $executor: $case_id" >&2
		rm -f "$full_qualification_cases" "$case_executors"
		exit 1
		;;
	esac
done
rm -f "$full_qualification_cases" "$case_executors"
echo "virtio activation: planned guest qualifications reach full-qualification with matching executors"

# A row marked exercised is a historical live claim, not a statement that a
# helper merely exists.  Keep that claim reachable from the complete
# qualification graph.  Otherwise an evidence row can accidentally point at
# a smoke-only or ad-hoc case which the release/checkpoint/soak gate never
# runs.  The qualification profile is deliberately the union of these three
# base profiles (see virtio-lab.yaml); nested and audio profiles add further
# gates but do not replace them.
qualification_cases=$(mktemp "${TMPDIR:-/tmp}/virtio-lab-qualification.XXXXXX")
awk '
/^  - id: [a-z0-9][a-z0-9._-]*$/ {
	if (id != "" && qualified)
		print id
	id = $3
	qualified = 0
	next
}
id != "" && /^    profiles: \[/ {
	profiles = $0
	sub(/^.*\[/, "", profiles)
	sub(/\].*$/, "", profiles)
	count = split(profiles, value, ",")
	for (item = 1; item <= count; item++) {
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", value[item])
		if (value[item] == "release" || value[item] == "checkpoint" ||
		    value[item] == "soak")
			qualified = 1
	}
	next
}
END {
	if (id != "" && qualified)
		print id
}
' "$lab_manifest" | sort -u >"$qualification_cases"

awk -F '\t' '
NR > 1 {
	if ($3 == "exercised" && $8 != "-")
		print $8
	if ($5 == "exercised" && $9 != "-")
		print $9
}
' "$activation_catalog" | tr ',' '\n' | sort -u |
while IFS= read -r case_id; do
	if ! grep -Fqx "$case_id" "$qualification_cases"; then
		echo "virtio activation: exercised evidence is outside the qualification profile: $case_id" >&2
		rm -f "$qualification_cases"
		exit 1
	fi
done
rm -f "$qualification_cases"
echo "virtio activation: exercised evidence reaches qualification"

# Evidence must resolve to a real source artifact and to an explicit assertion
# marker in that artifact.  A human-readable suffix that is not tied to source
# can drift away from the check it claims to describe.  Requiring
# "VIRTIO_ACTIVATION_ASSERTION: marker" keeps the ledger auditable without
# coupling it to an implementation constant.
awk -F '\t' '
NR > 1 {
	if ($3 == "exercised") {
		print $4
	}
	if ($5 == "exercised") {
		print $6
	}
	if (($3 == "exercised" || $5 == "exercised") && $7 != "-") {
		print $7
	}
}
' "$activation_catalog" | sort -u |
while IFS=: read -r artifact assertion; do
	evidence_paths=$(find "$source_root/tests/sys/kern/vsock_e2e" \
	    "$source_root/usr.sbin/bhyve" -type f -name "$artifact" \
	    -print 2>/dev/null)
	if [ -z "$evidence_paths" ]; then
		echo "virtio activation: evidence artifact not found: $artifact" >&2
		exit 1
	fi
	resolved=no
	for evidence_path in $evidence_paths; do
		if grep -Fq "VIRTIO_ACTIVATION_ASSERTION: $assertion" \
		    "$evidence_path"; then
			resolved=yes
			break
		fi
	done
	if [ "$resolved" != yes ]; then
		echo "virtio activation: evidence assertion not found: $artifact:$assertion" >&2
		exit 1
	fi
done
echo "virtio activation: exercised evidence assertions resolved"

# A common packed-ring engine is not sufficient to support a device's packed
# queue ABI: the individual model must explicitly opt in during construction
# and thereby make the bit available to the modern transport.  Keep the
# device-specific release anchors above tied to that production decision.
# This deliberately inspects only the opt-in surface, not a broad feature-mask
# match, because a device may carry an unrelated common capability mask.  The
# list is also an allow-list: scan the production sources afterwards so that a
# new packed producer cannot be added without its own activation row.
packed_sources=''
for packed_device in \
    vt9p:pci_virtio_9p.c \
    vtballoon:pci_virtio_balloon.c \
    vtblk:pci_virtio_block.c \
    vtcon:pci_virtio_console.c \
    vtcrypto:pci_virtio_crypto.c \
    vtfs:pci_virtio_fs.c \
    vtgpu:pci_virtio_gpu.c \
    vtinput:pci_virtio_input.c \
    vtiommu:pci_virtio_iommu.c \
    vtmem:pci_virtio_mem.c \
    vtpmem:pci_virtio_pmem.c \
    vtnet:pci_virtio_net.c \
    vtrnd:pci_virtio_rnd.c \
    vtrtc:pci_virtio_rtc.c \
    vtscsi:pci_virtio_scsi.c \
    vtsnd:pci_virtio_snd.c \
    vtvsock:pci_virtio_vsock.c; do
    packed_name=${packed_device%%:*}
    packed_source=$source_root/usr.sbin/bhyve/${packed_device#*:}
    packed_sources="$packed_sources ${packed_device#*:}"
    if ! grep -Fq "enabled-packed-${packed_name}-queue" \
        "$source_root/usr.sbin/bhyve/virtio_pci_modern.c"; then
        echo "virtio activation: missing packed release anchor for $packed_name" >&2
        exit 1
    fi
    # One generic RING_PACKED row is not enough evidence for an individual
    # device.  Tie each source opt-in and release anchor to its own ledger
    # row, so a future device can neither inherit another device's guest run
    # nor lose its deferred Linux qualification during a ledger cleanup.
    if ! awk -F '\t' -v anchor="virtio_pci_modern.c:enabled-packed-${packed_name}-queue" '
        NR > 1 && $2 == "RING-PACKED" && $7 == anchor { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$activation_catalog"; then
        echo "virtio activation: packed opt-in $packed_name lacks a device-specific ledger row" >&2
        exit 1
    fi
    if ! grep -Eq 'get_config_bool_node_default\(nvl, "packed", false\)' \
        "$packed_source" || ! grep -Fq 'VIRTIO_F_RING_PACKED' \
        "$packed_source"; then
        echo "virtio activation: $packed_name lacks explicit packed opt-in" >&2
        exit 1
    fi

    # Packed virtqueues are a VirtIO 1 transport feature.  A modern-only
    # device is constrained by its transport policy; a dual-transport device
    # must reject an explicit legacy selection before publishing the feature
    # bit.  Checking one of those two production shapes keeps a future
    # opt-in from advertising a ring format that its selected PCI transport
    # cannot expose.
    if ! grep -Fq 'VIRTIO_PCI_MODERN_ONLY' "$packed_source" &&
        ! grep -Eq 'packed[[:space:]]*&&[[:space:]]*![[:space:]]*vi_pci_is_modern' \
        "$packed_source"; then
        echo "virtio activation: $packed_name does not constrain packed queues to modern transport" >&2
        exit 1
    fi
done
for packed_source in $(rg -l 'VIRTIO_F_RING_PACKED' \
    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c | sort); do
	# A mention used solely to reject, mask, or document the feature is not a
	# producer.  Match the same explicit constructor opt-in shape required for
	# the allow-listed models above before demanding a release-ledger row.
	if ! rg -q 'get_config_bool_node_default\(nvl, "packed", false\)' \
	    "$packed_source"; then
		continue
	fi
	packed_base=${packed_source##*/}
    case " $packed_sources " in
    *" $packed_base "*)
        ;;
    *)
        echo "virtio activation: unledgered packed producer: $packed_base" >&2
        exit 1
        ;;
    esac
done
echo "virtio activation: packed release anchors and transport constraints match device opt-ins"

# Runtime capacity changes are a valid VirtIO block configuration mechanism,
# but they are not ordinary backing-file I/O.  In particular, automatically
# subscribing a partitioned root disk to EVF_VNODE capacity changes can make a
# guest reconfigure its mounted root provider.  Keep that potentially
# disruptive ABI explicit: the default device remains fixed-capacity, and the
# resize callback may be registered only behind the operator's resize=true
# selection.  This is deliberately a small production-contract check rather
# than a host-OS mock; the callback's aligned, deferred suspend, and
# checkpoint behavior is exercised by virtio_block_test.
vtblk_source="$source_root/usr.sbin/bhyve/pci_virtio_block.c"
if ! rg -q 'get_config_bool_node_default\(nvl, "resize", false\)' \
    "$vtblk_source"; then
	echo "virtio block: runtime resize is not explicit opt-in" >&2
	exit 1
fi
if ! awk '
    /if \(resize\)[[:space:]]*\{/ { in_resize = 1; next }
    in_resize && /blockif_register_resize_callback\(/ { found = 1 }
    in_resize && /^[[:space:]]*\}/ { in_resize = 0 }
    END { exit(found ? 0 : 1) }
' "$vtblk_source"; then
	echo "virtio block: resize callback is not guarded by resize=true" >&2
	exit 1
fi
if ! rg -q '\.Cm resize=true' "$source_root/usr.sbin/bhyve/bhyve.8" ||
    ! rg -q 'disabled by default' "$source_root/usr.sbin/bhyve/bhyve.8"; then
	echo "virtio block: resize opt-in policy is undocumented" >&2
	exit 1
fi
echo "virtio block: runtime resize remains explicit opt-in"

# Snapshot is a machine-level transaction.  A PCI VirtIO model which registers
# only the save callback can appear checkpointable while bypassing the
# validate-before-publication and destination-compatibility passes.  Require
# the complete framework registration for every production model, including
# stateless devices whose device callback is intentionally absent.
snapshot_models=0
for snapshot_source in "$source_root"/usr.sbin/bhyve/pci_virtio_*.c; do
	snapshot_base=${snapshot_source##*/}
	for snapshot_hook in pe_snapshot pe_snapshot_validate pe_snapshot_compat; do
		if ! rg -q "^[[:space:]]*\.${snapshot_hook}[[:space:]]*=" \
		    "$snapshot_source"; then
			echo "virtio requirements: snapshot registration missing ${snapshot_hook}: $snapshot_base" >&2
			exit 1
		fi
	done
	snapshot_models=$((snapshot_models + 1))
done
if [ "$snapshot_models" -eq 0 ]; then
	echo "virtio requirements: no PCI VirtIO snapshot registrations found" >&2
	exit 1
fi
echo "virtio requirements: $snapshot_models PCI VirtIO snapshot registrations are complete"

# Restore preflight rejects any PCI model that cannot validate its record
# before destination state is published.  Keep the source registrations in
# lockstep with that runtime rule, including non-VirtIO models and the dummy
# device used by the PCI-emulation tests.
if ! awk '
/struct pci_devemu[[:space:]]+[[:alnum:]_]+[[:space:]]*=[[:space:]]*\{/ {
	in_model = 1
	model = $0
	snapshot = 0
	validator = 0
	next
}
in_model && /[.]pe_snapshot[[:space:]]*=/ { snapshot = 1 }
in_model && /[.]pe_snapshot_validate[[:space:]]*=/ { validator = 1 }
in_model && /^[[:space:]]*};/ {
	if (snapshot && !validator) {
		printf "%s: %s\n", FILENAME, model > "/dev/stderr"
		failed = 1
	}
	in_model = 0
}
END { exit(failed ? 1 : 0) }
' "$source_root"/usr.sbin/bhyve/*.c \
    "$source_root"/usr.sbin/bhyve/amd64/*.c \
    "$source_root"/usr.sbin/bhyve/aarch64/*.c; then
	echo "virtio requirements: PCI snapshot registration lacks a restore validator" >&2
	exit 1
fi
echo "virtio requirements: every checkpointable PCI model has a restore validator"

# The legacy snapshot records predate portable checkpointing and are explicitly
# host-architecture-local.  Modern VirtIO state, by contrast, is a portable
# checkpoint format: it must never acquire a native-width SNAPSHOT_VAR field
# merely because that helper is convenient.  Track the enclosing snapshot
# function rather than grepping the whole file, since the legacy functions
# below intentionally retain their established native records.
modern_snapshot_native_width=$(awk '
/^vi_pci_snapshot_[[:alnum:]_]+\(/ {
	function_name = $1
	sub(/\(.*/, "", function_name)
}
/SNAPSHOT_VAR(_CMP)?_OR_LEAVE/ && function_name ~ /_modern$/ {
	printf "%s:%d:%s\n", function_name, FNR, $0
	found = 1
}
END {
	exit(found ? 0 : 1)
}' "$source_root/usr.sbin/bhyve/virtio.c" || true)
if [ -n "$modern_snapshot_native_width" ]; then
	echo "virtio requirements: modern common snapshot uses native-width helper:" >&2
	printf '%s\n' "$modern_snapshot_native_width" >&2
	exit 1
fi
echo "virtio requirements: modern common snapshot state uses fixed-width wire helpers"

# Every activation row must name an existing advertised optional requirement,
# and every such requirement must have an explicit live disposition.  This
# makes omissions visible without pretending that host-only operational
# requirements can be guest-activated.
awk -F '\t' '
NR == FNR {
	if (FNR > 1) {
		requirement[$1] = 1
		level[$1] = $3
		advertised[$1] = $5
		if ($3 == "optional" &&
		    ($5 == "yes" || $5 == "device-dependent"))
			needs_activation[$1] = 1
	}
	next
}
FNR > 1 {
	if (!($2 in requirement)) {
		printf "virtio activation: %s references missing requirement %s\n",
		    $1, $2 > "/dev/stderr"
		errors++
	} else if (level[$2] != "optional" ||
	    (advertised[$2] != "yes" &&
	    advertised[$2] != "device-dependent")) {
		printf "virtio activation: %s references non-advertised optional requirement %s\n",
		    $1, $2 > "/dev/stderr"
		errors++
	}
	covered[$2] = 1
}
END {
	for (id in needs_activation) {
		if (!(id in covered)) {
			printf "virtio activation: advertised optional requirement %s lacks a live disposition\n",
			    id > "/dev/stderr"
			errors++
		}
	}
	exit(errors != 0)
}
' "$catalog" "$activation_catalog"

references=$(mktemp "${TMPDIR:-/tmp}/virtio-requirements.XXXXXX")
used=$(mktemp "${TMPDIR:-/tmp}/virtio-used.XXXXXX")
aliased=$(mktemp "${TMPDIR:-/tmp}/virtio-aliased.XXXXXX")
trap 'rm -f "$references" "$used" "$aliased"' EXIT HUP INT TERM
awk -F '\t' '
NR > 1 {
	print $7
	print $8
}
' "$catalog" |
    tr ';' '\n' |
    sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' |
	    awk '/^[A-Za-z0-9_]+_test:[A-Za-z0-9_]+$/ { print }' |
    sort -u >"$references"

while IFS=: read -r program test_case; do
	source=$test_dir/$program.c
	shell_source=$test_dir/$program.sh
	binary=$test_dir/$program
	case "$program" in
	vsock_rx_test|virtio_vsock_transport_test)
		source=$test_dir/../vsock_rx_harness/$program.c
		shell_source=$test_dir/../vsock_rx_harness/$program.sh
		binary=$test_dir/../vsock_rx_harness/$program
		;;
	vsock_test)
		source=$test_dir/../vsock_test.c
		shell_source=$test_dir/../vsock_test.sh
		binary=$test_dir/../vsock_test
		;;
	vmm_snapshot_envelope_test|vmm_event_state_test)
		source=$test_dir/../../vmm/$program.c
		shell_source=$test_dir/../../vmm/$program.sh
		binary=$test_dir/../../vmm/$program
		;;
	esac
	if [ ! -r "$source" ] && [ -n "$source_root" ]; then
		for candidate in \
		    "$source_root/tests/sys/kern/vsock_device_harness/$program.c" \
		    "$source_root/tests/sys/kern/vsock_rx_harness/$program.c" \
		    "$source_root/tests/sys/kern/$program.c" \
		    "$source_root/tests/sys/vmm/$program.c"; do
			if [ -r "$candidate" ]; then
				source=$candidate
				break
			fi
		done
	fi

	if [ -r "$source" ]; then
		if ! grep -Eq \
		    "ATF_TC(_(WITHOUT_HEAD|WITH_CLEANUP))?\\($test_case\\)" \
		    "$source"; then
			echo "virtio requirements: unknown test $program:$test_case" >&2
			exit 1
		fi
	elif [ -r "$shell_source" ]; then
		if ! grep -Eq \
		    "^atf_test_case[[:space:]]+$test_case([[:space:]]|$)" \
		    "$shell_source"; then
			echo "virtio requirements: unknown test $program:$test_case" >&2
			exit 1
		fi
	elif [ -x "$binary" ]; then
		if ! "$binary" -l |
		    grep -Fqx "ident: $test_case"; then
			echo "virtio requirements: unknown test $program:$test_case" >&2
			exit 1
		fi
	else
		echo "virtio requirements: cannot inspect tests for $program" >&2
		exit 1
	fi
done <"$references"

echo "virtio requirements: test references validated"

# The catalog has both a common ring-reset inventory row and a device-specific
# 9P row.  Keep their implementation/advertisement claims identical so a
# historical limitation cannot silently survive beside the implemented
# capability.
awk -F '\t' '
$1 == "RING-RESET-9P" {
	common_status = $4
	common_advertised = $5
}
$1 == "DEVICE-9P-QUEUE-RESET" {
	device_status = $4
	device_advertised = $5
}
END {
	if (common_status == "" || device_status == "") {
		print "virtio requirements: missing 9P queue-reset catalog row" \
		    > "/dev/stderr"
		exit 1
	}
	if (common_status != device_status ||
	    common_advertised != device_advertised) {
		print "virtio requirements: contradictory 9P queue-reset claims" \
		    > "/dev/stderr"
		exit 1
	}
}
' "$catalog"
echo "virtio requirements: duplicate capability claims are consistent"

# Device tests include the production .c file first, then remap protocol
# names to the independent oracle.  Enforce that discipline mechanically.
# Contract tests are deliberate exceptions because they compare public
# production constants directly with the oracle.  The packed model is also
# independent by construction and includes no production implementation.
protocol_names='((VIRTIO_CONFIG|VIRTIO_F|VIRTIO_RING_F|VIRTIO_PCI_CAP|VIRTIO_PCI_COMMON|VIRTIO_PCI_ISR|VIRTIO_MSI|VIRTIO_ID|VIRTIO_DEV|VIRTIO_9P_F|VIRTIO_NET_F|VIRTIO_SCSI|VIRTIO_VSOCK|VRING|VTCON_F|VTCON_DEVICE|VTCON_PORT|VTINPUT_CFG|VTNET_HDR|VTBLK_S|VTBLK_F|VBH_OP|VBH_FLAG)_[A-Z0-9_]+|VIRTIO_PCI_(CONFIG_OFF|HOST_FEATURES|GUEST_FEATURES|QUEUE_PFN|QUEUE_NUM|QUEUE_SEL|QUEUE_NOTIFY|STATUS|ISR)|VTINPUT_(EVENTQ|STATUSQ)|VTNET_(RXQ|TXQ|CTLQ)|VTBLK_(BSIZE|BLK_ID_LEN))'
for source in "$test_dir"/*_test.c; do
	[ -r "$source" ] || continue
	case "${source##*/}" in
	virtio_guest_contract_test.c|virtio_host_contract_test.c|\
	virtio_packed_model_test.c)
		continue
		;;
	esac
	grep -q 'virtio_1_4_spec.h' "$source" || continue

	# A protocol-boundary helper may use only its own private parser names
	# while its test obtains all expectations from the independent fixture.
	# Such a test has no production protocol macro that needs post-DUT
	# aliasing.
	if ! tr -cs 'A-Za-z0-9_' '\n' <"$source" |
	    grep -Eq "^$protocol_names$"; then
		continue
	fi

	# Oracle aliases must be introduced only after every production .c file
	# has been included.  Otherwise the device under test would compile with
	# the expected values and a wrong production definition could pass.
	if ! awk -v pattern="$protocol_names" '
	/^#include[[:space:]]+[<"].*\.c[>"]/ {
		last_dut = NR
	}
	$1 == "#undef" && $2 ~ ("^" pattern "$") && first_alias == 0 {
		first_alias = NR
	}
	END {
		if (last_dut == 0 || first_alias == 0 ||
		    first_alias <= last_dut)
			exit 1
	}
	' "$source"; then
		echo "virtio requirements: oracle aliases precede the DUT in ${source##*/}" >&2
		exit 1
	fi

	tr -cs 'A-Za-z0-9_' '\n' <"$source" |
	    grep -E "^$protocol_names$" | sort -u >"$used" || true
	grep -E '^[[:space:]]*#undef[[:space:]]+' "$source" |
	    awk '{ print $2 }' | sort -u >"$aliased"
	if ! comm -23 "$used" "$aliased" | grep -q .; then
		:
	else
		echo "virtio requirements: production protocol values used by ${source##*/}:" >&2
		comm -23 "$used" "$aliased" >&2
		exit 1
	fi

	awk -v pattern="$protocol_names" '
	$1 == "#undef" && $2 ~ ("^" pattern "$") {
		required[$2] = 1
		next
	}
	$1 == "#define" {
		defined = $2
		sub(/\(.*/, "", defined)
		if (!(defined in required))
			next
		line = $0
		while (line ~ /\\$/ && getline continuation > 0) {
			sub(/\\$/, "", line)
			line = line continuation
		}
		if (line !~ /VIRTIO14_/) {
			printf "virtio requirements: %s is not mapped to the oracle\n",
			    defined > "/dev/stderr"
			errors++
		}
		delete required[defined]
	}
	END {
		for (name in required) {
			printf "virtio requirements: %s has no oracle mapping\n",
			    name > "/dev/stderr"
			errors++
		}
		if (errors != 0)
			exit 1
	}
	' "$source"
done

echo "virtio requirements: protocol tests use independent oracle values"

if grep -Eq '#include[[:space:]]+.*(sys/dev/virtio|usr.sbin/bhyve)|VIRTIO14_' \
    "$compat_oracle"; then
	echo "virtio requirements: compatibility oracle depends on the standard oracle or implementation" >&2
	exit 1
fi
if grep -Eq 'value[[:space:]]*==[[:space:]]*0x1052U' \
    "$test_dir/virtio_input_test.c"; then
	echo "virtio requirements: input compatibility test duplicates a raw implementation value" >&2
	exit 1
fi
echo "virtio requirements: non-standard compatibility values are isolated"

# Modern transports cannot inherit legacy-only bits 24 and 27 or the
# legacy-network meanings assigned to bits 41 and 42.  In VirtIO 1.4 bit 41
# is ADMIN_VQ for a modern PCI device and bit 42 is reserved; FreeBSD
# implements neither.  Every transport must also discard reserved bits
# 25--26 and 44--49.  Legacy MMIO may preserve the defined legacy bits, but
# its version 1 register layout cannot implement RING_RESET.  The numeric
# meanings are checked independently by virtio_guest_contract_test; these
# checks ensure each real negotiation path actually applies the policy.
if [ -n "$source_root" ]; then
	feature_header=$source_root/sys/dev/virtio/virtio.h
	modern_pci_source=$source_root/sys/dev/virtio/pci/virtio_pci_modern.c
	mmio_source=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
	# The common administration transport is deliberately present but not
	# guest-visible: no current bhyve device has the concrete PF/VF
	# owner/member topology required by VirtIO 1.4.  Keep that policy as an
	# executable boundary.  A future production offer must add the topology,
	# live evidence, and an explicit ledger/policy update in the same change;
	# merely adding the bit to a device capability set is not a valid shortcut.
	admin_offer_sources=$(rg -l 'VIRTIO_F_ADMIN_VQ' \
	    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c 2>/dev/null || true)
	if [ -n "$admin_offer_sources" ]; then
		echo "virtio requirements: administration VQ is offered without a reviewed production topology:" >&2
		printf '%s\n' "$admin_offer_sources" >&2
		exit 1
	fi
	echo "virtio requirements: administration VQ remains unadvertised without a PF/VF topology"

	if ! awk '
/^virtio_modern_supported_transport_features\(/ {
	in_function = 1
}
in_function && /features[[:space:]]*&=[[:space:]]*~VIRTIO_F_ADMIN_VQ;/ {
	admin = 1
}
in_function && /features[[:space:]]*&=[[:space:]]*~VIRTIO_F_NOTIFY_ON_EMPTY;/ {
	notify_empty = 1
}
in_function && /features[[:space:]]*&=[[:space:]]*~VIRTIO_F_ANY_LAYOUT;/ {
	any_layout = 1
}
in_function && /features[[:space:]]*&=[[:space:]]*~\(1ULL[[:space:]]*<<[[:space:]]*42\);/ {
	reserved = 1
}
in_function && /^}/ {
	exit(admin && notify_empty && any_layout && reserved ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$feature_header"; then
		echo "virtio requirements: modern guest feature filter retains legacy-only or unsupported modern bits" >&2
		exit 1
	fi
	if ! awk '
/^vtpci_modern_negotiate_features\(/ {
	in_function = 1
}
in_function && /virtio_modern_supported_transport_features\(child_features\)/ {
	filtered = NR
}
in_function && /vtpci_modern_notification_data_valid\(sc\)/ {
	layout = NR
}
in_function && /virtio_modern_notification_data_features\(/ {
	notification = NR
}
in_function && /vtpci_negotiate_features\(&sc->vtpci_common,/ {
	negotiated = NR
}
in_function && /^}/ {
	exit(filtered != 0 && layout > filtered &&
	    notification > layout && negotiated > notification ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$modern_pci_source"; then
		echo "virtio requirements: modern PCI negotiation bypasses transport or NotificationData layout validation" >&2
		exit 1
	fi
	if ! awk '
/^virtio_mmio_supported_transport_features\(/ {
	in_function = 1
}
in_function && /virtio_modern_supported_transport_features\(features\)/ {
	modern = 1
}
in_function && /features[[:space:]]*&=[[:space:]]*~VIRTIO_F_RING_RESET;/ {
	legacy = 1
}
in_function && /^}/ {
	exit(modern && legacy ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$feature_header"; then
		echo "virtio requirements: MMIO feature filter does not separate modern and legacy rules" >&2
		exit 1
	fi
	if ! awk '
/^vtmmio_negotiate_features\(/ {
	in_function = 1
}
in_function && /virtio_mmio_supported_transport_features\(/ {
	found = 1
}
in_function && /^}/ {
	exit(found ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$mmio_source"; then
		echo "virtio requirements: MMIO negotiation bypasses its transport feature filter" >&2
		exit 1
	fi
	echo "virtio requirements: modern and legacy guest feature allocations validated"
else
	echo "virtio requirements: source-only guest feature-allocation check unavailable"
fi

# Keep implementation wire layouts out of functional-test stimuli and
# expectations.  sizeof/offsetof of a production protocol structure is useful
# only in the dedicated layout contract, where it is compared directly with a
# document-derived VIRTIO14 value.  Elsewhere it can make a malformed DUT
# structure generate the same malformed request that the test expects.
for source in "$test_dir"/*_test.c; do
	[ -r "$source" ] || continue
	case "${source##*/}" in
	virtio_guest_contract_test.c)
		continue
		;;
	esac
	awk '
	/^ATF_TC_BODY\((virtio_1_4_wire_layout|receive_header_layout|packed_engine_layout),/ {
		in_layout = 1
		next
	}
	/^ATF_TC_BODY\(/ {
		in_layout = 0
	}
	!in_layout &&
	    $0 ~ /(sizeof|offsetof)\(struct (virtio_|vring_|pci_vt|vtblk_config|vtinput_)/ {
		printf "%s:%d: functional protocol value derives from DUT layout\n",
		    FILENAME, FNR > "/dev/stderr"
		errors++
	}
	END {
		if (errors != 0)
			exit 1
	}
	' "$source"
done

echo "virtio requirements: functional tests do not derive wire values from DUT layouts"

# Catch the same dependency when a production wire structure is named
# indirectly.  For example, sizeof(h) is just as self-confirming as
# sizeof(struct virtio_vsock_hdr) when h has that production type.  Using the
# real object size to initialize its C storage is harmless; using it as a wire
# length, allocation size, or expected result is not.  Record wire-typed local
# names, then permit sizeof only in memset initialization and the dedicated
# layout contracts.
wire_type='(virtio_(vsock_hdr|vsock_config|net_rxhdr|net_config|blk_hdr|blk_discard_write_zeroes)|pci_vt9p_config|pci_vtcon_(config|control)|pci_vtscsi_(config|ctrl_tmf|ctrl_an|event|req_cmd_rd|req_cmd_wr)|vtinput_(config|absinfo|devids|event)|vtblk_config|vring_(desc|avail|used|used_elem))'
for source in "$test_dir"/*_test.c; do
	[ -r "$source" ] || continue
	case "${source##*/}" in
	virtio_guest_contract_test.c)
		continue
		;;
	esac
	awk -v wire_type="$wire_type" '
	function remember_declaration(text,    rest, count, fields, i, name) {
		# Anchor at the start of a declaration.  An unanchored match can
		# mistake a cast in a function argument for a declaration and
		# then remember later argument names as wire objects.
		if (match(text,
		    "^[[:space:]]*((static|const|volatile)[[:space:]]+)*struct[[:space:]]+" \
		    wire_type "[[:space:]]+")) {
			rest = substr(text, RSTART + RLENGTH)
			sub(/[;{].*$/, "", rest)
			count = split(rest, fields, ",")
			for (i = 1; i <= count; i++) {
				name = fields[i]
				sub(/^[[:space:]]*\**[[:space:]]*/, "", name)
				sub(/[[:space:]\[=(].*$/, "", name)
				if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/)
					wire_name[name] = 1
			}
		}
	}
	/^ATF_TC_BODY\((virtio_1_4_wire_layout|receive_header_layout),/ {
		in_layout = 1
		next
	}
	/^ATF_TC_BODY\(/ {
		in_layout = 0
	}
	{
		remember_declaration($0)
		if (in_layout || $0 ~ /memset[[:space:]]*\(/)
			next
		for (name in wire_name) {
			pattern = "sizeof[[:space:]]*\\([[:space:]]*\\*?[[:space:]]*" \
			    name "([[:space:]]*\\[[^]]+\\]|[[:space:]]*\\." \
			    "[[:space:]]*[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*\\)"
			if ($0 ~ pattern) {
				printf "%s:%d: functional wire size for %s derives from DUT object\n",
				    FILENAME, FNR, name > "/dev/stderr"
				errors++
			}
		}
	}
	END {
		if (errors != 0)
			exit 1
	}
	' "$source"
done

echo "virtio requirements: indirect functional wire sizes use document values"

# A wire-layout assertion is meaningful only when its expected size or offset
# comes from an independent transcribed standard or ABI oracle, not from
# another production structure or a duplicated implementation expression.
# Accumulate multiline ATF calls and require one of those independent oracles
# on the expected side.
for source in "$test_dir"/*_test.c; do
	[ -r "$source" ] || continue
	awk '
	/ATF_(CHECK|REQUIRE)_EQ(_MSG)?\([[:space:]]*(sizeof|offsetof)\(/ {
		collecting = 1
		statement = $0
		start = FNR
	}
	collecting && FNR != start {
		statement = statement " " $0
	}
	collecting && /;/ {
		if (statement !~ /(VIRTIO14_|VMMABI_)/) {
			printf "%s:%d: wire-layout assertion lacks independent oracle\n",
			    FILENAME, start > "/dev/stderr"
			errors++
		}
		collecting = 0
		statement = ""
	}
	END {
		if (errors != 0)
			exit 1
	}
	' "$source"
done

echo "virtio requirements: wire-layout assertions use document values"

# Structured device protocols need at least one functional request/response
# test whose bytes are assembled from the transcribed document offsets.  A
# layout-only sizeof/offsetof comparison is insufficient: the same production
# structure must not create both the input and the expected result.
for program in virtio_block_test virtio_console_test virtio_net_test \
    virtio_scsi_test vsock_device_test; do
	source=$test_dir/$program.c
	if ! grep -q '^ATF_TC_BODY(document_wire_vectors,' "$source"; then
		echo "virtio requirements: $program lacks document wire vectors" >&2
		exit 1
	fi
	if ! awk '
	/^ATF_TC_BODY\(document_wire_vectors,/ {
		in_vector = 1
	}
	in_vector && /^ATF_TC_(WITHOUT_HEAD|WITH_CLEANUP|BODY)\(/ &&
	    $0 !~ /^ATF_TC_BODY\(document_wire_vectors,/ {
		in_vector = 0
	}
	in_vector {
		text = text "\n" $0
	}
	END {
		if (text !~ /VIRTIO14_/ ||
		    text !~ /virtio14_(store|load)_le(16|32|64)/)
			exit 1
		if (text ~ /sizeof\(struct (virtio_|pci_vtcon_control|pci_vtscsi_ctrl)/ ||
		    text ~ /offsetof\(struct (virtio_|pci_vtcon_control|pci_vtscsi_ctrl)/)
			exit 1
	}
	' "$source"; then
		echo "virtio requirements: $program wire vectors are not independent" >&2
		exit 1
	fi
done

if grep -Eq '#include[[:space:]]+.*(sys/dev/virtio|usr.sbin/bhyve)|VIRTIO_(CONFIG|F|PCI|NET|SCSI|VSOCK|RING)_' \
    "$test_dir/virtio_1_4_wire.h"; then
	echo "virtio requirements: byte-vector helpers depend on implementation" >&2
	exit 1
fi

echo "virtio requirements: structured requests use document-derived byte vectors"

# Endian contract tests must not decode an encoded value with the same
# production conversion primitive under test.  That pattern self-confirms if
# both halves make the same mistake, and is especially weak on a little-endian
# development host.  The guest contract uses virtio_1_4_wire.h for an
# independent byte-level decode instead.
if ! awk '
/ATF_(CHECK|REQUIRE)(_EQ)?\(/ {
	collecting = 1
	statement = $0
	start = FNR
}
collecting && FNR != start {
	statement = statement " " $0
}
collecting && /;/ {
	if (statement ~ /virtio_(htog|gtoh)(16|32|64)[[:space:]]*\(/) {
		printf "%s:%d: guest endian expectation reuses a production conversion helper\n",
		    FILENAME, start > "/dev/stderr"
		errors++
	}
	collecting = 0
	statement = ""
}
END {
	if (errors != 0)
		exit 1
}
' "$test_dir/virtio_guest_contract_test.c"; then
	exit 1
fi

echo "virtio requirements: guest endian expectations use independent bytes"

# Transport device-config readers return host-endian scalar values.  A child
# driver must not convert those values again: that is invisible on the current
# little-endian Intel host but corrupts the value on a big-endian guest.  Keep
# the first 5BSD GPU consumer tied to this bus contract until broader
# cross-architecture live coverage is available.
if [ -n "$source_root" ]; then
	gpu_source=$source_root/sys/dev/virtio/gpu/virtio_gpu.c
	if ! awk '
/^vtgpu_get_display_info\(/ {
		in_function = 1
	}
	in_function && /num_scanouts[[:space:]]*=[[:space:]]*sc->vtgpu_gpucfg\.num_scanouts;/ {
		direct = 1
	}
	in_function && /virtio_(gtoh|htog)(16|32|64)[[:space:]]*\(/ {
		double_conversion = 1
	}
	in_function && /^}/ {
		exit(direct && !double_conversion ? 0 : 1)
	}
	END {
		if (!in_function)
			exit 1
	}
	' "$gpu_source"; then
		echo "virtio requirements: 5BSD GPU double-converts host-endian device configuration" >&2
		exit 1
	fi
	echo "virtio requirements: 5BSD GPU consumes host-endian device configuration"

	# vt_timer() invokes drawing methods from callout/critical context.  The
	# memory draw is permitted there, but a VirtIO request takes a sleep mutex
	# and waits for an interrupt.  Require a non-sleeping damage producer and a
	# drained taskqueue consumer so neither panic nor detach can race it.
	for callback in vtgpu_fb_blank vtgpu_fb_bitblt_text \
	    vtgpu_fb_bitblt_bitmap vtgpu_fb_drawrect vtgpu_fb_setpixel; do
		callback_body=$(sed -n "/^${callback}(/,/^}/p" "$gpu_source")
		[ -n "$callback_body" ] || {
			echo "virtio requirements: missing GPU VT callback: $callback" >&2
			exit 1
		}
		if printf '%s\n' "$callback_body" | rg -q \
		    'vtgpu_op_enter|vtgpu_transfer_to_host_2d|vtgpu_resource_flush|msleep|mtx_lock\(&sc->vtgpu_mtx'; then
			echo "virtio requirements: $callback can sleep in VT context" >&2
			exit 1
		fi
		printf '%s\n' "$callback_body" | rg -q -F 'vtgpu_fb_changed(' || {
			echo "virtio requirements: $callback does not publish damage" >&2
			exit 1
		}
	done
	for contract in \
	    'mtx_lock_spin(&sc->vtgpu_dirty_mtx)' \
	    'taskqueue_create_fast("vtgpu_flush", M_WAITOK,' \
	    'taskqueue_thread_enqueue, &sc->vtgpu_flush_tq)' \
	    'taskqueue_start_threads(&sc->vtgpu_flush_tq, 1, PI_TTY,' \
	    'taskqueue_enqueue(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task)' \
	    'TASK_INIT(&sc->vtgpu_flush_task, 0, vtgpu_flush_task, sc)' \
	    'taskqueue_drain(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task)' \
	    'taskqueue_free(sc->vtgpu_flush_tq)'; do
		rg -q -F "$contract" "$gpu_source" || {
			echo "virtio requirements: GPU deferred flush lacks: $contract" >&2
			exit 1
		}
	done
	flush_body=$(sed -n '/^vtgpu_flush_task(/,/^}/p' "$gpu_source")
	for contract in vtgpu_transfer_to_host_2d vtgpu_resource_flush; do
		printf '%s\n' "$flush_body" | rg -q -F "$contract" || {
			echo "virtio requirements: GPU flush worker lacks: $contract" >&2
			exit 1
		}
	done
	detach_body=$(sed -n '/^vtgpu_detach(device_t dev)/,/^}/p' \
	    "$gpu_source")
	printf '%s\n' "$detach_body" | awk '
/atomic_set_rel_int\(&sc->vtgpu_flags, VTGPU_FLAG_DETACH\)/ && flag == 0 { flag = NR }
/vt_deallocate\(/ && deallocate == 0 { deallocate = NR }
/taskqueue_drain\(/ && drain == 0 { drain = NR }
/taskqueue_free\(/ && tqfree == 0 { tqfree = NR }
/free\(\(void \*\)sc->vtgpu_fb_info.fb_vbase/ && release == 0 { release = NR }
END { exit(flag > 0 && flag < deallocate && deallocate < drain && drain < tqfree && tqfree < release ? 0 : 1) }
	' || {
		echo "virtio requirements: GPU detach does not drain VT flush ownership" >&2
		exit 1
	}
	echo "virtio requirements: 5BSD GPU VT callbacks defer sleeping requests"
else
	echo "virtio requirements: source-only 5BSD GPU configuration-endian check unavailable"
fi

# A host-side multiqueue offer is useful only when the guest driver both
# requests it and allocates more than one request queue after reading the
# device configuration.  These source checks intentionally do not stand in
# for the Linux/5BSD live activation rows in virtio-feature-activation.tsv;
# they prevent a future driver cleanup from silently turning those rows into
# host-only claims while the privileged matrix is still pending.
if [ -n "$source_root" ]; then
	block_source=$source_root/sys/dev/virtio/block/virtio_blk.c
	scsi_source=$source_root/sys/dev/virtio/scsi/virtio_scsi.c
	net_source=$source_root/sys/dev/virtio/network/if_vtnet.c
	net_header=$source_root/sys/dev/virtio/network/if_vtnetvar.h
	rg -q 'VIRTIO_BLK_F_MQ' "$block_source" &&
	    rg -q 'virtio_with_feature\(dev, VIRTIO_BLK_F_MQ\)' "$block_source" &&
	    rg -q 'blkcfg->num_queues' "$block_source" || {
		echo "virtio requirements: 5BSD block multiqueue activation path is incomplete" >&2
		exit 1
	}
	# BIO_DELETE is the FreeBSD block-layer operation whose contract permits
	# deterministic zeroing.  Require all three parts of the translation: the
	# optional feature is requested, its bounded configuration is consumed, and
	# the request header selects WRITE_ZEROES only when that configuration made
	# the path available.  This is intentionally separate from the host block
	# wire tests: it prevents a guest cleanup from leaving the negotiated bit
	# inert while a Linux-only test still passes.
	rg -q 'VIRTIO_BLK_F_WRITE_ZEROES' "$block_source" &&
	    rg -q 'max_write_zeroes_sectors' "$block_source" &&
	    rg -q 'max_write_zeroes_seg' "$block_source" &&
	    rg -q 'vtblk_delete_uses_write_zeroes' "$block_source" &&
	    rg -q 'VIRTIO_BLK_T_WRITE_ZEROES' "$block_source" || {
		echo "virtio requirements: 5BSD block WRITE_ZEROES translation is incomplete" >&2
		exit 1
	}
	rg -q 'VTSCSI_MAX_REQUEST_VQS' "$scsi_source" &&
	    rg -q 'scsicfg->num_queues' "$scsi_source" &&
	    rg -q 'vtscsi_num_request_vqs = nrequest_vqs' "$scsi_source" || {
		echo "virtio requirements: 5BSD SCSI multiqueue activation path is incomplete" >&2
		exit 1
	}
	rg -q 'VIRTIO_NET_F_MQ' "$net_header" &&
	    rg -q 'virtio_with_feature\(dev, VIRTIO_NET_F_MQ\)' "$net_source" &&
	    rg -q 'vtnet_act_vq_pairs' "$net_source" || {
		echo "virtio requirements: 5BSD network multiqueue activation path is incomplete" >&2
		exit 1
	}
	echo "virtio requirements: 5BSD multiqueue and WRITE_ZEROES driver activation paths are present"
else
	echo "virtio requirements: source-only 5BSD multiqueue activation check unavailable"
fi

# Keep simple fixed-size resource fallback loops bounded by the array they
# index.  This source-level regression check covers a failure path which the
# userland contract harness cannot execute without a kernel bus.
if [ -n "$source_root" ] && grep -Eq \
    'for[[:space:]]*\([^;]*;[[:space:]]*nitems\([^)]*\)[[:space:]]*;' \
    "$source_root/sys/dev/virtio/pci/virtio_pci_legacy.c"; then
	echo "virtio requirements: unbounded legacy PCI resource loop" >&2
	exit 1
fi

if [ -n "$source_root" ]; then
	# Portable guest drivers must be reachable through both supported build
	# modes.  A module-only source can pass its focused build while silently
	# making `device foo` unusable.  VirtIO PMEM is intentionally module-only,
	# matching the amd64-only, module-only nvdimm provider it consumes.
	for guest_driver in input rtc; do
		grep -Eq "^dev/virtio/$guest_driver/virtio_$guest_driver\\.c[[:space:]]+optional[[:space:]]+virtio_$guest_driver([[:space:]]|$)" \
		    "$source_root/sys/conf/files" || {
			echo "virtio requirements: virtio_$guest_driver is absent from sys/conf/files" >&2
			exit 1
		}
		grep -Eq "^[[:space:]]*$guest_driver([[:space:]]|$)|[[:space:]]$guest_driver([[:space:]]|\\\\$)" \
		    "$source_root/sys/modules/virtio/Makefile" || {
			echo "virtio requirements: virtio_$guest_driver module is not registered" >&2
			exit 1
		}
	done
	grep -Eq '^dev/virtio/input/virtio_input\.c[[:space:]]+optional[[:space:]]+virtio_input[[:space:]]+evdev([[:space:]]|$)' \
	    "$source_root/sys/conf/files" || {
		echo "virtio requirements: static virtio_input does not require evdev" >&2
		exit 1
	}
	module_makefile=$source_root/sys/modules/virtio/Makefile
	grep -Eq '^SUBDIR\+=[[:space:]]+pmem([[:space:]]|$)' \
	    "$module_makefile" || {
		echo "virtio requirements: virtio_pmem module is not registered" >&2
		exit 1
	}
	grep -Eq '^\.if \$\{MACHINE_CPUARCH\} == "amd64"$' \
	    "$module_makefile" || {
		echo "virtio requirements: virtio_pmem lacks its amd64 nvdimm build fence" >&2
		exit 1
	}
	if grep -Eq '^dev/virtio/pmem/virtio_pmem\\.c' \
	    "$source_root/sys/conf/files"; then
		echo "virtio requirements: module-only virtio_pmem entered the portable static kernel list" >&2
		exit 1
	fi
	echo "virtio requirements: portable guest drivers reach modules and static kernels"
	echo "virtio requirements: nvdimm-backed PMEM remains explicitly amd64 module-only"

	echo "virtio requirements: guest resource fallback loops are bounded"
else
	echo "virtio requirements: source-only resource loop check unavailable"
fi

# TEST-ANCHOR: guest-interrupt-teardown
# The transport owns interrupt resources, but the child owns every callback
# argument and usually the mutex acquired by that callback.  Parent detach
# cannot wait for handlers until child detach returns, which is too late for a
# child that has already destroyed its state.  Require every child that sets
# up bus interrupts to invoke the idempotent teardown boundary, and require
# every in-tree transport to implement that boundary rather than inheriting a
# no-op default.
if [ -n "$source_root" ]; then
	missing_teardown=
	for guest_source in $(grep -El \
	    'virtio_setup_intr[[:space:]]*\(' \
	    "$source_root"/sys/dev/virtio/*/*.c 2>/dev/null || true); do
		if ! grep -Eq 'virtio_teardown_intr[[:space:]]*\(' \
		    "$guest_source"; then
			missing_teardown="$missing_teardown $guest_source"
		fi
	done
	if [ -n "$missing_teardown" ]; then
		echo "virtio requirements: guest interrupt owner lacks teardown:$missing_teardown" >&2
		exit 1
	fi
	for transport_source in \
	    "$source_root/sys/dev/virtio/pci/virtio_pci_modern.c" \
	    "$source_root/sys/dev/virtio/pci/virtio_pci_legacy.c" \
	    "$source_root/sys/dev/virtio/mmio/virtio_mmio.c"; do
		grep -Eq 'DEVMETHOD\(virtio_bus_teardown_intr,' \
		    "$transport_source" || {
			echo "virtio requirements: transport lacks interrupt teardown: $transport_source" >&2
			exit 1
		}
	done
	if grep -Eq '}[[:space:]]+DEFAULT[[:space:]]+.*teardown_intr' \
	    "$source_root/sys/dev/virtio/virtio_bus_if.m"; then
		echo "virtio requirements: interrupt teardown has an unsafe no-op default" >&2
		exit 1
	fi
	for locking_guest in gpu/virtio_gpu.c input/virtio_input.c \
	    rtc/virtio_rtc.c; do
		awk '
		/virtio_teardown_intr[[:space:]]*\(/ { teardown = NR }
		/mtx_destroy[[:space:]]*\(/ {
			if (teardown == 0 || teardown > NR)
				exit 1
		}
		END { if (teardown == 0) exit 1 }
		' "$source_root/sys/dev/virtio/$locking_guest" || {
			echo "virtio requirements: callback mutex is destroyed before interrupt teardown: $locking_guest" >&2
			exit 1
		}
	done
	echo "virtio requirements: guest interrupt callbacks drain before child state destruction"
else
	echo "virtio requirements: source-only guest interrupt teardown check unavailable"
fi

# Request and response ranges have opposite VirtIO descriptor directions.
# sglist_append() coalesces physically adjacent ranges without knowing those
# directions, so the RTC request path must own a padded bounce pair and assert
# that the writable response remains a distinct segment.  Bare caller stack
# objects can otherwise form a read-only chain which the host correctly
# rejects with DEVICE_NEEDS_RESET.
if [ -n "$source_root" ]; then
	rtc_source=$source_root/sys/dev/virtio/rtc/virtio_rtc.c
	for contract in \
	    'struct vtrtc_request_io {' \
	    'uint8_t pad;' \
	    'memcpy(io.request, request, request_len);' \
	    'sglist_append(&sg, io.request, request_len)' \
	    'sglist_append_boundary(&sg, io.response, response_len)' \
	    'KASSERT(sg.sg_nseg > readable,' \
	    'if (sg.sg_nseg <= readable)' \
	    'virtqueue_enqueue(sc->requestq, io.response, &sg, readable,' \
	    'memcpy(response, io.response, used_len);'; do
		rg -q -F "$contract" "$rtc_source" || {
			echo "virtio requirements: RTC direction boundary lacks: $contract" >&2
			exit 1
		}
	done
	echo "virtio requirements: RTC request/response descriptor directions cannot coalesce"
	mem_source=$source_root/sys/dev/virtio/mem/virtio_mem.c
	for contract in \
	    'struct vtmem_request_io {' \
	    'CTASSERT(offsetof(struct vtmem_request_io, response) >=' \
	    'sglist_append(&sg, &io->request, sizeof(io->request))' \
	    'sglist_append_boundary(&sg, &io->response,' \
	    'KASSERT(sg.sg_nseg > readable,' \
	    'if (sg.sg_nseg <= readable)' \
	    'virtqueue_enqueue(sc->vtmem_vq, &io->response, &sg, readable,'; do
		rg -q -F "$contract" "$mem_source" || {
			echo "virtio requirements: memory direction boundary lacks: $contract" >&2
			exit 1
		}
	done
	echo "virtio requirements: memory request/response descriptor directions cannot coalesce"
	for contract in \
	    'sglist_append_boundary(struct sglist *sg, void *buf, size_t len)' \
	    'sglist_append_phys_boundary(struct sglist *sg, vm_paddr_t paddr, size_t len)' \
	    'sglist_append_bio_boundary(struct sglist *sg, struct bio *bp)' \
	    'sglist_append_vmpages_boundary(struct sglist *sg, vm_page_t *m,'; do
		rg -q -F "$contract" "$source_root/sys/kern/subr_sglist.c" || {
			echo "virtio requirements: semantic sglist boundary lacks: $contract" >&2
			exit 1
		}
	done
	for boundary_user in \
	    block/virtio_blk.c \
	    fs/virtio_fs.c \
	    gpu/virtio_gpu.c \
	    iommu/virtio_iommu.c \
	    mem/virtio_mem.c \
	    network/if_vtnet.c \
	    p9fs/virtio_p9fs.c \
	    pmem/virtio_pmem.c \
	    rtc/virtio_rtc.c \
	    scmi/virtio_scmi.c \
	    scsi/virtio_scsi.c \
	    sound/virtio_snd.c; do
		rg -q 'sglist_append_([a-z_]*_)?boundary\(' \
		    "$source_root/sys/dev/virtio/$boundary_user" || {
			echo "virtio requirements: mixed-direction driver lacks semantic sglist boundary: $boundary_user" >&2
			exit 1
		}
	done
	echo "virtio requirements: mixed descriptor directions use non-coalescing sglist boundaries"
	for source_contract in \
	    "$source_root/sys/dev/virtio/gpu/virtio_gpu.c vtgpu:request-and-response-collapsed" \
	    "$source_root/sys/dev/virtio/pmem/virtio_pmem.c vtpmem:request-and-response-collapsed" \
	    "$source_root/sys/dev/virtio/iommu/virtio_iommu.c vtiommu:request-and-response-collapsed"; do
		set -- $source_contract
		case "$2" in
		vtgpu:*) needle='if (sg.sg_nseg <= rcount)' ;;
		vtpmem:*) needle='if (sg.sg_nseg != readable + 1)' ;;
		vtiommu:*) needle='if (writable == 0)' ;;
		esac
		rg -q -F "$needle" "$1" || {
			echo "virtio requirements: $2 lacks a release-kernel direction-boundary check" >&2
			exit 1
		}
	done
	for iommu_contract in \
	    'struct vtiommu_request_io {' \
	    'CTASSERT(offsetof(struct vtiommu_request_io, response) >=' \
	    'sc->vtiommu_req = sc->vtiommu_io->request;' \
	    'sc->vtiommu_resp = sc->vtiommu_io->response;'; do
		rg -q -F "$iommu_contract" \
		    "$source_root/sys/dev/virtio/iommu/virtio_iommu.c" || {
			echo "virtio requirements: IOMMU direction boundary lacks: $iommu_contract" >&2
			exit 1
		}
	done
	echo "virtio requirements: GPU, PMEM, and IOMMU direction failures fail closed in release kernels"
else
	echo "virtio requirements: source-only guest descriptor-direction checks unavailable"
fi

# An internal failed bit is not an ownership fence for writable buffers which
# remain posted to a malformed device.  RTC alarm and input completions cannot
# perform a potentially blocking full reset in interrupt context, so require
# them to close admission, schedule a retained task, and require detach to
# drain that task before mutex destruction.  Both task handlers must converge
# on a helper which stops the complete device and drains every queue.
if [ -n "$source_root" ]; then
	input_source=$source_root/sys/dev/virtio/input/virtio_input.c
	rtc_source=$source_root/sys/dev/virtio/rtc/virtio_rtc.c
	for source_contract in \
	    "$input_source vtinput_fail_task vtinput_fail_locked" \
	    "$rtc_source vtrtc_alarm_task vtrtc_fail_locked"; do
		set -- $source_contract
		grep -Eq "^$2\\(" "$1" &&
		    grep -Eq "^$3\\(" "$1" &&
		    grep -Eq "taskqueue_enqueue\\(taskqueue_thread," "$1" &&
		    grep -Eq "virtio_stop\\(sc->(dev|vtgpu_dev)\\);" "$1" &&
		    grep -Eq "virtqueue_drain\\(sc->(eventq|requestq)" "$1" || {
			echo "virtio requirements: asynchronous guest failure does not revoke queue ownership: $1" >&2
			exit 1
		}
	done
	awk '
/taskqueue_drain\(taskqueue_thread, &sc->fail_task\)/ { drain = NR }
/mtx_destroy\(&sc->mtx\)/ { destroy = NR }
END { exit(drain != 0 && destroy > drain ? 0 : 1) }
' "$input_source" || {
		echo "virtio requirements: input detach does not drain failure task before mutex destruction" >&2
		exit 1
	}
	awk '
/taskqueue_drain\(taskqueue_thread, &sc->alarm_task\)/ { drain = NR }
/mtx_destroy\(&sc->mtx\)/ { destroy = NR }
END { exit(drain != 0 && destroy > drain ? 0 : 1) }
' "$rtc_source" || {
		echo "virtio requirements: RTC detach does not drain alarm/failure task before mutex destruction" >&2
		exit 1
	}
	awk '
/^vtrtc_alarmq_intr\(/ { in_function = 1 }
in_function && /VTRTC_FLAG_DETACH/ && detach == 0 { detach = NR }
in_function && /taskqueue_enqueue\(taskqueue_thread/ && enqueue == 0 {
	enqueue = NR
}
in_function && /^}/ {
	exit(detach != 0 && enqueue > detach ? 0 : 1)
}
END { if (!in_function) exit 1 }
' "$rtc_source" || {
		echo "virtio requirements: RTC interrupt can republish its task after detach drain" >&2
		exit 1
	}
	echo "virtio requirements: asynchronous guest failures revoke posted DMA in task context"
else
	echo "virtio requirements: source-only asynchronous failure ownership check unavailable"
fi

# Control commands in the 5BSD VirtIO-SCSI driver are asynchronous CAM
# operations.  Keep the removed busy-poll mode from returning: it had no
# callers, no deadline, and could pin a CPU forever if a device withheld a
# completion.  The active path must remain callback/interrupt driven.
if [ -n "$source_root" ] && grep -Eq \
    'vtscsi_poll_ctrl_req|VTSCSI_EXECUTE_POLL|VTSCSI_REQ_FLAG_POLLED|VTSCSI_REQ_FLAG_COMPLETE' \
    "$source_root/sys/dev/virtio/scsi/virtio_scsi.c" \
    "$source_root/sys/dev/virtio/scsi/virtio_scsivar.h"; then
	echo "virtio requirements: 5BSD SCSI control path restored an unbounded polling mode" >&2
	exit 1
fi

if [ -n "$source_root" ]; then
	echo "virtio requirements: 5BSD SCSI control requests are interrupt driven"
else
	echo "virtio requirements: source-only SCSI progress check unavailable"
fi

# MMIO exposes QueueNumMax as a 32-bit register, but both split and packed
# virtqueues have a document-defined maximum of 32768 (and split queues add a
# power-of-two rule).  Require both the initial allocation and
# reinitialization paths to select format-correct validation of the full-width
# register value before explicitly narrowing it.
if [ -n "$source_root" ]; then
	mmio_source=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
	for function_name in vtmmio_alloc_virtqueues vtmmio_reinit_virtqueue; do
		if ! awk -v function_name="$function_name" '
$0 ~ ("^" function_name "\\(") {
	in_function = 1
}
in_function && /virtio_queue_size_valid\(/ {
	validated = NR
}
in_function && /\(uint16_t\)size/ {
	narrowed = NR
}
in_function && /^}/ {
	exit(validated != 0 && narrowed > validated ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$mmio_source"; then
			echo "virtio requirements: $function_name narrows QueueNumMax without prior document-limit validation" >&2
			exit 1
		fi
	done
	echo "virtio requirements: MMIO QueueNumMax is validated before narrowing"
else
	echo "virtio requirements: source-only MMIO QueueNumMax check unavailable"
fi

# QueueNotify is an MMIO control register.  Section 4.2.3.1 requires a
# 32-bit aligned transaction even when section 4.2.3.3 says that, without
# NOTIFICATION_DATA, the value itself is only a 16-bit queue index.  Guard
# against accidentally reusing the PCI transport's 16-bit write rule here.
if [ -n "$source_root" ]; then
	mmio_source=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
	if ! awk '
/^vtmmio_notify_virtqueue\(/ {
	in_function = 1
}
in_function && /vtmmio_write_config_4\(sc,[[:space:]]*offset,[[:space:]]*notification\);/ {
	write4 = 1
}
in_function && /vtmmio_write_config_2\(/ {
	write2 = 1
}
in_function && /^}/ {
	exit(write4 && !write2 ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$mmio_source"; then
		echo "virtio requirements: MMIO QueueNotify is not exclusively a 32-bit control-register write" >&2
		exit 1
	fi
	echo "virtio requirements: MMIO QueueNotify uses a 32-bit control-register write"
else
	echo "virtio requirements: source-only MMIO QueueNotify-width check unavailable"
fi

# A device reset returns the transport to its initial state.  An invalid
# device-configuration access marks only the current initialization attempt;
# retaining that software latch after status reaches zero would make a valid
# reinitialization fail even though the device completed reset.
if [ -n "$source_root" ]; then
	for reset_check in \
	    "sys/dev/virtio/pci/virtio_pci_modern.c vtpci_modern_reset vtpci_device_config_failed" \
	    "sys/dev/virtio/mmio/virtio_mmio.c vtmmio_reset vtmmio_device_config_failed"; do
		set -- $reset_check
		reset_source=$source_root/$1
		reset_function=$2
		reset_flag=$3
		if ! awk -v function_name="$reset_function" -v flag="$reset_flag" '
$0 ~ ("^" function_name "\\(") {
	in_function = 1
}
in_function && $0 ~ ("sc->" flag "[[:space:]]*=[[:space:]]*false;") {
	found = 1
}
in_function && /^}/ {
	exit(found ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$reset_source"; then
			echo "virtio requirements: $reset_function retains a failed configuration attempt after reset" >&2
			exit 1
		fi
	done
	echo "virtio requirements: guest reset clears configuration-attempt failures"
else
	echo "virtio requirements: source-only guest reset check unavailable"
fi

# A detached MMIO child can be reprobed without detaching the transport.
# Section 3.1 requires the next initialization to pass through ACKNOWLEDGE
# before DRIVER.  Keep this kernel-only lifecycle property visible to the
# source validator, while the numeric status value remains checked against
# VIRTIO14_STATUS_ACKNOWLEDGE by virtio_guest_contract_test.
if [ -n "$source_root" ]; then
	mmio_source=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
	if ! awk '
/^vtmmio_child_detached\(/ {
	in_function = 1
}
in_function && /vtmmio_set_status\(dev,[[:space:]]*$/ {
	continued = 1
	next
}
in_function &&
    /vtmmio_set_status\(dev,[[:space:]]*VIRTIO_CONFIG_STATUS_ACK\);/ {
	found = 1
}
in_function && continued &&
    /VIRTIO_CONFIG_STATUS_ACK\);/ {
	found = 1
}
in_function && /^}/ {
	exit(found ? 0 : 1)
}
END {
	if (!in_function)
		exit 1
}
' "$mmio_source"; then
		echo "virtio requirements: MMIO child detach does not restore ACKNOWLEDGE" >&2
		exit 1
	fi
	echo "virtio requirements: guest MMIO reattach restarts at ACKNOWLEDGE"
else
	echo "virtio requirements: source-only MMIO reattach check unavailable"
fi

# Split-ring publication is a producer/consumer protocol, not merely a C
# structure layout.  Keep the implementation tied to the ordering language in
# sections 2.7.6 and 2.7.8: acquire the driver's available index before
# consuming descriptors, and release the device's used index after producing
# completion entries.
if [ -n "$source_root" ]; then
	host_core=$source_root/usr.sbin/bhyve/virtio.c
	host_header=$source_root/usr.sbin/bhyve/virtio.h
	guest_virtqueue=$source_root/sys/dev/virtio/virtqueue.c
	if ! awk '
	/^vi16_to_cpu\(/ { in_function = 1 }
	in_function && /VIRTIO_F_VERSION_1/ { saw_version = 1 }
	in_function && /le16toh/ { saw_little = 1 }
	in_function && /^}/ {
		exit(saw_version && saw_little ? 0 : 1)
	}
	END {
		if (!in_function)
			exit 1
	}
	' "$host_header"; then
		echo "virtio requirements: host split-ring decoder is not transport-aware" >&2
		exit 1
	fi
	if ! awk '
	/^vi16_from_cpu\(/ { in_function = 1 }
	in_function && /VIRTIO_F_VERSION_1/ { saw_version = 1 }
	in_function && /htole16/ { saw_little = 1 }
	in_function && /^}/ {
		exit(saw_version && saw_little ? 0 : 1)
	}
	END {
		if (!in_function)
			exit 1
	}
	' "$host_header"; then
		echo "virtio requirements: host split-ring encoder is not transport-aware" >&2
		exit 1
	fi
	if ! awk '
	{
		joined = previous $0
		if (joined ~ /vi16_to_cpu\(.*atomic_load_acq_16\(.*&vq->vq_avail->idx\)/)
			found = 1
		previous = $0
	}
	END { exit(found ? 0 : 1) }
	' "$host_core"; then
		echo "virtio requirements: host ring consumption lacks an acquire index load" >&2
		exit 1
	fi
	if ! awk '
	{
		joined = previous $0
		if (joined ~ /atomic_store_rel_16\(&vq->vq_used->idx,[[:space:]]*vi16_from_cpu\(vq->vq_vs,[[:space:]]*vq->vq_next_used\)\)/)
			found = 1
		previous = $0
	}
	END { exit(found ? 0 : 1) }
	' "$host_core"; then
		echo "virtio requirements: host completion publication lacks a transport-encoded release index store" >&2
		exit 1
	fi
	if ! awk '
	{
		joined = previous $0
		if (joined ~ /vi16_to_cpu\(.*atomic_load_acq_16\(.*&vq->vq_avail->idx\)/)
			found = 1
		previous = $0
	}
	END { exit(found ? 0 : 1) }
	' "$host_core"; then
		echo "virtio requirements: host queue-ready check lacks a transport-decoded acquire index load" >&2
		exit 1
	fi
echo "virtio requirements: host split-ring publication ordering validated"

	# Enabling packed-ring interrupts is a publish-then-recheck protocol.
	# Require the common guest driver to use an architecture-independent
	# barrier between those operations; an x86-only barrier can miss a device
	# completion on a weakly ordered future host architecture.
	if ! awk '
	/^vq_ring_enable_interrupt\(/ { in_function = 1 }
	in_function && /if \(vq_packed\(vq\)\)/ { in_packed = 1 }
	in_packed && /BUS_DMASYNC_PREWRITE/ { saw_sync = 1 }
	in_packed && saw_sync && /^[[:space:]]*mb\(\);/ { saw_barrier = 1 }
	in_packed && /#if.*(__i386__|__amd64__)/ { arch_guard = 1 }
	in_function && /^}/ {
		exit(saw_barrier && !arch_guard ? 0 : 1)
	}
	END {
		if (!in_function)
			exit 1
	}
	' "$guest_virtqueue"; then
		echo "virtio requirements: packed interrupt enable lacks a portable publish/recheck barrier" >&2
		exit 1
	fi
	echo "virtio requirements: guest packed-ring interrupt ordering validated"

# A malformed guest or recoverable host-memory failure must never terminate
# the complete bhyve process.  Device request paths fail closed through
# DEVICE_NEEDS_RESET instead of asserting or aborting on rollback failure.
if [ -n "$source_root" ] &&
    grep -Eq '\babort[[:space:]]*\(' \
    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c; then
	echo "virtio requirements: VirtIO device request path calls abort()" >&2
	grep -En '\babort[[:space:]]*\(' \
	    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c >&2
	exit 1
fi
echo "virtio requirements: device request failures cannot abort bhyve"

# Endpoint devices must not bypass the common DMA/request ownership boundary.
# The IOMMU function is the sole exception: it resolves its own page tables
# before an endpoint domain exists.  Device configuration and balloon PFNs do
# not require a raw guest-address mapper.
raw_dma_uses=$(grep -En \
    '(^|[^[:alnum:]_])(paddr_guest2host|vm_map_gpa|vm_map_gpa_range)[[:space:]]*\(' \
    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c 2>/dev/null |
    grep -v '/pci_virtio_iommu.c:' || true)
if [ -n "$raw_dma_uses" ]; then
	echo "virtio requirements: endpoint bypasses common DMA translation:" >&2
	printf '%s\n' "$raw_dma_uses" >&2
	exit 1
fi
echo "virtio requirements: endpoint DMA paths use the common translator"

# Checkpoint callers share vm_pause_devices(), so a later device refusing
# pause must unwind the already-acquired prefix there rather than depending on
# each caller to remember a separate cleanup path.  pci_checkpoint_resume()
# is ownership-aware and walks the reverse fabric/endpoint order; preserve
# that production contract in addition to the per-device ownership tests.
if ! awk '
/^vm_pause_devices\(void\)/ { in_pause = 1; next }
in_pause && /^vm_resume_devices\(void\)/ { exit }
in_pause && /resume_error = vm_resume_devices\(\)/ { unwind = NR }
in_pause && unwind != 0 && /return \(resume_error\);/ && NR > unwind {
	returned = 1
}
END { exit(in_pause && unwind != 0 && returned ? 0 : 1) }
' "$source_root/usr.sbin/bhyve/snapshot.c"; then
	echo "virtio requirements: partial device-pause failure lacks common unwind" >&2
	exit 1
fi
echo "virtio requirements: partial device-pause failure unwinds ownership"

# Device-model progress must be event or condition driven.  Sleeping in a
# notification, reset, or lifecycle callback stalls a vCPU or checkpoint walk
# and hides missed-wakeup bugs behind timing.  mevent timers and condition
# variables remain permitted.
manual_waits=$(grep -En \
    '(^|[^[:alnum:]_])(sleep|usleep|nanosleep)[[:space:]]*\(' \
    "$source_root"/usr.sbin/bhyve/virtio*.c \
    "$source_root"/usr.sbin/bhyve/pci_virtio_*.c 2>/dev/null || true)
if [ -n "$manual_waits" ]; then
	echo "virtio requirements: device model contains a manual sleep:" >&2
	printf '%s\n' "$manual_waits" >&2
	exit 1
fi
echo "virtio requirements: device progress has no manual sleeps"

# None of the checkpoint and private transport formats added by this work has
# shipped.  Once a current format supersedes an earlier development format,
# retain no fallback decoder or legacy ioctl spelling.  Standards-defined
# VIRTIO_F_VERSION_1 and the established legacy PCI/MMIO transports are not
# private format compatibility and are intentionally outside this gate.
if rg -q 'VIRTIOFSD_SESSION_STATE_VERSION_ACTIVE|VIRTIOFSD_SESSION_STATE_V2_HEADER|VSOCK_IOC_TRANSPORT_SET_FEATURES_LEGACY' \
    "$source_root/usr.sbin/virtiofsd" \
    "$source_root/usr.sbin/bhyve" \
    "$source_root/sys/sys/vsock.h" \
    "$source_root/sys/kern/uipc_vsock_user.c"; then
	echo "virtio requirements: obsolete unreleased format compatibility remains" >&2
	exit 1
fi
if rg -q 'SNAPSHOT_LE64_OR_LEAVE\((saved->vq_generation|generation),' \
    "$source_root/usr.sbin/bhyve/virtio.c" \
    "$source_root/usr.sbin/bhyve/pci_virtio_9p.c"; then
	echo "virtio requirements: obsolete source-generation wire slot remains" >&2
	exit 1
fi
if ! rg -q '#define[[:space:]]+VT9P_SNAPSHOT_VERSION[[:space:]]+2U' \
    "$source_root/usr.sbin/bhyve/pci_virtio_9p.c" ||
    rg -q 'version[[:space:]]*==[[:space:]]*1' \
    "$source_root/usr.sbin/bhyve/pci_virtio_9p.c"; then
	echo "virtio requirements: 9P retains an obsolete version-1 state path" >&2
	exit 1
fi
# The startup management ABIs are also unreleased.  Their public spelling
# names only the current contract; a numbered VERSION_1/SIZE_1 alias would
# imply that callers may deliberately select a superseded generation.
if rg -q 'VMM_STARTUP_(RUN_)?REQUEST_(VERSION|SIZE)_1' \
    "$source_root/sys/dev/vmm" \
    "$source_root/tests/sys/vmm"; then
	echo "virtio requirements: startup ABI retains a version-1 compatibility spelling" >&2
	exit 1
fi
if ! rg -q '#define[[:space:]]+VIRTIOFSD_SESSION_STATE_VERSION[[:space:]]+2U' \
    "$source_root/usr.sbin/virtiofsd/virtiofsd_session.c" ||
    rg -q 'version[[:space:]]*==[[:space:]]*1' \
    "$source_root/usr.sbin/virtiofsd/virtiofsd_session.c"; then
	echo "virtio requirements: virtiofsd retains an obsolete session-state decoder" >&2
	exit 1
fi
# Keep this repository-wide rather than relying on a list of old symbol names:
# every private format that has advanced past its first development encoding
# must remain an exact-current decoder.  A new compatibility branch therefore
# fails the source gate even if it uses a new spelling.
current_only_sources="
$source_root/usr.sbin/bhyve/checkpoint_cpu.c
$source_root/usr.sbin/bhyve/checkpoint_machine.c
$source_root/usr.sbin/bhyve/pci_virtio_console.c
$source_root/usr.sbin/bhyve/pci_virtio_iommu.c
$source_root/usr.sbin/bhyve/pci_virtio_pmem.c
$source_root/usr.sbin/bhyve/pci_virtio_scsi.c
$source_root/usr.sbin/bhyve/pci_virtio_snd.c
$source_root/usr.sbin/bhyve/pci_e82545.c
$source_root/usr.sbin/bhyve/pci_virtio_balloon.c
$source_root/usr.sbin/bhyve/pci_virtio_block.c
$source_root/usr.sbin/bhyve/pci_virtio_gpu.c
$source_root/usr.sbin/bhyve/pci_virtio_input.c
$source_root/usr.sbin/bhyve/pci_virtio_mem.c
$source_root/usr.sbin/bhyve/pci_virtio_net.c
$source_root/usr.sbin/bhyve/pci_virtio_rtc.c
$source_root/usr.sbin/bhyve/pci_virtio_vsock.c
$source_root/usr.sbin/bhyve/virtio.c
$source_root/usr.sbin/bhyve/virtio_admin.c
$source_root/usr.sbin/bhyve/virtio_admin_capability.c
$source_root/usr.sbin/bhyve/virtio_admin_device_parts.c
$source_root/usr.sbin/bhyve/virtio_admin_group.c
$source_root/usr.sbin/bhyve/virtio_admin_queue.c
$source_root/usr.sbin/bhyve/virtio_admin_resource.c
$source_root/usr.sbin/bhyve/virtio_fs_backend.c
$source_root/usr.sbin/bhyve/virtio_fs_state.c
$source_root/usr.sbin/bhyve/virtio_gpu_2d_state.c
$source_root/usr.sbin/bhyve/virtio_iommu_state.c
$source_root/usr.sbin/bhyve/virtio_mem_host.c
$source_root/usr.sbin/bhyve/virtio_pci_modern.c
$source_root/usr.sbin/bhyve/virtio_rtc_alarm.c
$source_root/usr.sbin/bhyve/virtio_snd_host.c
$source_root/usr.sbin/virtiofsd/virtiofsd_export.c
$source_root/usr.sbin/virtiofsd/virtiofsd_handle.c
$source_root/usr.sbin/virtiofsd/virtiofsd_session.c
$source_root/sys/amd64/vmm/intel/vmx_nested_checkpoint.c
$source_root/sys/amd64/vmm/intel/vmx_nested_exposure.c
	$source_root/sys/amd64/vmm/intel/vmx_nested_l2_continuation_state.c
	$source_root/sys/amd64/vmm/intel/vmx_nested_l2_state.c
	$source_root/sys/amd64/vmm/intel/vmx_nested_state.c
	$source_root/sys/amd64/vmm/intel/vmx_nested_vmcs_registry_state.c
	"
if rg -n -i \
    'VERSION_(LEGACY|V1)|decode_v1|restore_v1|load_v1|import_v1|version[[:space:]]*==[[:space:]]*(UINT(16|32|64)_C\()?1(U|ULL)?\)?' \
    $current_only_sources; then
	echo "virtio requirements: a superseded version-1 decoder was reintroduced" >&2
	exit 1
fi
if rg -n -i \
    'retain[^[:cntrl:]]*(reader|decoder)[^[:cntrl:]]*(old|prior|previous|this)[^[:cntrl:]]*(version|format)|retain[^[:cntrl:]]*(old|prior|previous|this)[^[:cntrl:]]*(version|format)[^[:cntrl:]]*(reader|decoder)' \
    $current_only_sources; then
	echo "virtio requirements: source promises an obsolete development decoder" >&2
	exit 1
fi

# Backend identity strings are part of the current private checkpoint
# contract.  They describe the destination object; embedding an obsolete
# development revision in that identity would preserve a second, implicit
# compatibility namespace even after the corresponding decoder disappeared.
if rg -q --glob '!validate-virtio-requirements.sh' \
    'local-v1:|waspnest-[[:alnum:]-]*-v1(["[:space:]]|$)' \
    "$source_root/usr.sbin/bhyve" \
    "$source_root/tests/sys/kern/vsock_e2e" \
    "$source_root/tests/sys/kern/vsock_device_harness"; then
	echo "virtio requirements: obsolete v1 backend identity remains" >&2
	exit 1
fi
echo "virtio requirements: private backend identities have no v1 namespace"

# Checkpoint admission is exact-current.  Do not retain recognizers, fixtures,
# or machine identities for superseded development manifests: none shipped,
# and treating them specially would create a compatibility surface anyway.
if rg -q --glob '!validate-virtio-requirements.sh' \
    'CHECKPOINT_MANIFEST_MAGIC_PREFIX|BHYVE-CHECKPOINT-MANIFEST-[12]|bhyve-virtio-v1' \
    "$source_root/usr.sbin/bhyve" \
    "$source_root/tests/sys/kern/vsock_device_harness" \
    "$source_root/tests/sys/kern/vsock_e2e"; then
	echo "virtio requirements: obsolete checkpoint-v1 recognition remains" >&2
	exit 1
fi
rg -q -F '"BHYVE-CHECKPOINT-MANIFEST-3"' \
    "$source_root/tests/sys/kern/vsock_e2e/run-alpine-auto.sh" || {
	echo "virtio requirements: live checkpoint harness does not require the current manifest" >&2
	exit 1
}
echo "virtio requirements: checkpoint admission has no v1 compatibility path"

# A public host-model entry point owns one lifetime admission until it
# returns.  Calling another public entry point from that scope is unsafe:
# destroy can mark the object as destroying between the two admissions, so
# the nested call can return without producing its output while the outer
# caller continues to consume it.  Keep the virtio-mem configuration encoder
# on the already-admitted internal state path.
if awk '
/^virtio_mem_host_config_encode\(/ { in_function = 1 }
in_function && /virtio_mem_host_get_config\(/ { nested = 1 }
in_function && /^}/ { exit(nested ? 0 : 1) }
END { if (!in_function) exit 1 }
' "$source_root/usr.sbin/bhyve/virtio_mem_host.c"; then
	echo "virtio requirements: memory config encoder nests lifetime admission" >&2
	exit 1
fi
echo "virtio requirements: memory config encoder uses one lifetime admission"

# The private virtio-fs backend protocol has one current encoding.  A
# min/max range would silently recreate compatibility negotiation and can
# publish a session version which no message codec implements.
fs_backend=$source_root/usr.sbin/bhyve/virtio_fs_backend.c
for contract in \
    'hello->minimum_version != VIRTIO_FS_BACKEND_VERSION' \
    'hello->maximum_version != VIRTIO_FS_BACKEND_VERSION' \
    'session->version = VIRTIO_FS_BACKEND_VERSION'; do
	rg -q -F "$contract" "$fs_backend" || {
		echo "virtio requirements: virtio-fs backend retains version-range compatibility: $contract" >&2
		exit 1
	}
done
echo "virtio requirements: virtio-fs backend negotiates exact-current only"

# VIMS is still on its first and sole encoding, but its original reader
# normalized two noncanonical development artifacts instead of rejecting
# them: a source-local generation value and insertion-ordered records.  A
# current-only format must require the exact bytes emitted by its writer.
iommu_state=$source_root/usr.sbin/bhyve/virtio_iommu_state.c
iommu_state_test=$source_root/tests/sys/kern/vsock_device_harness/virtio_iommu_state_test.c
for contract in \
    'le64dec(bytes + 16) != 0' \
    'viommu_endpoint_compare(&endpoints[i - 1],' \
    'viommu_domain_compare(&domains[i - 1],' \
    'viommu_mapping_compare(&mappings[i - 1],'; do
	rg -q -F "$contract" "$iommu_state" || {
		echo "virtio requirements: current VIMS decoder lacks: $contract" >&2
		exit 1
	}
done
if rg -q 'accept older|qsort\(mappings, mapping_count' "$iommu_state"; then
	echo "virtio requirements: VIMS still normalizes an obsolete encoding" >&2
	exit 1
fi
for regression in \
    'le64enc(image_b + 16, 1)' \
    'VIOMMU_STATE_ENDPOINT_SIZE' \
    'VIOMMU_STATE_DOMAIN_SIZE' \
    'VIOMMU_STATE_MAPPING_SIZE'; do
	rg -q -F "$regression" "$iommu_state_test" || {
		echo "virtio requirements: VIMS current-only regression lacks: $regression" >&2
		exit 1
	}
done

# The current checkpoint metadata contract is also the only accepted one.
# Every field emitted by vm_snapshot_basic_metadata() is mandatory at restore;
# silently accepting its absence would preserve the unreleased pre-contract
# format even though the device-private decoders are current-only.
if rg -q 'Historical checkpoint|error != 0 && error != ENOENT' \
    "$source_root/usr.sbin/bhyve/snapshot.c" \
    "$source_root/usr.sbin/bhyve/bhyverun.c"; then
	echo "virtio requirements: obsolete checkpoint metadata fallback remains" >&2
	exit 1
fi

# The original bhyve snapshot layout used the requested path as raw guest RAM
# and discovered adjacent .kern and .meta files.  It was never released by
# this project, and accepting it would bypass the current manifest identity,
# digest, architecture, and machine-contract gates.
if rg -q 'load_(vmmem|kdata|metadata)_file|legacy checkpoint paths' \
    "$source_root/usr.sbin/bhyve/snapshot.c"; then
	echo "virtio requirements: raw three-file checkpoint restore remains" >&2
	exit 1
fi
restore_loader=$(sed -n '/^load_restore_file(/,/^}/p' \
    "$source_root/usr.sbin/bhyve/snapshot.c")
printf '%s\n' "$restore_loader" | rg -q -F \
    'if (!exists || !is_manifest)' || {
	echo "virtio requirements: restore does not require the current manifest" >&2
	exit 1
}
rg -q -F 'raw_three_file_format_rejected' \
    "$source_root/tests/sys/kern/vsock_device_harness/snapshot_manifest_test.c" || {
	echo "virtio requirements: raw checkpoint rejection lacks a regression" >&2
	exit 1
}
echo "virtio requirements: raw three-file checkpoint restore is absent"
for mandatory_lookup in \
    lookup_cpu_topology \
    lookup_cpu_contract \
    lookup_numa_topology \
    lookup_memory_geometry \
    vm_restore_machine_topology_digest \
    vm_restore_device_compatibility; do
	function_body=$(sed -n "/^${mandatory_lookup}(/,/^}/p" \
	    "$source_root/usr.sbin/bhyve/snapshot.c")
	if [ -z "$function_body" ] ||
	    printf '%s\n' "$function_body" | rg -q 'return \(ENOENT\);'; then
		echo "virtio requirements: $mandatory_lookup still accepts absent old metadata" >&2
		exit 1
	fi
done
echo "virtio requirements: obsolete checkpoint metadata fallbacks are absent"

# A malformed restore image is data-plane input, not a process-fatal
# programming invariant.  The kernel-record publisher must report a normal
# error after its topology check even if a subsequent lookup observes a
# missing or empty record; errx() here would bypass transaction cleanup.
kern_restore=$(sed -n '/^vm_restore_kern_structs(/,/^}/p' \
    "$source_root/usr.sbin/bhyve/snapshot.c")
printf '%s\n' "$kern_restore" | rg -q 'errx\(' && {
	echo "virtio requirements: kernel restore still terminates on malformed input" >&2
	exit 1
}
for contract in \
    'data == NULL || size == 0' \
    'return (EINVAL);'; do
	printf '%s\n' "$kern_restore" | rg -q -F "$contract" || {
		echo "virtio requirements: kernel restore lacks ordinary error path: $contract" >&2
		exit 1
	}
done
echo "virtio requirements: malformed kernel records use transaction-safe errors"

# A current global compatibility schema does not imply that every PCI device
# owns a VirtIO compatibility envelope.  Preflight must query the device just
# as commit does and leave envelope-less AHCI, xHCI, framebuffer, and e1000
# records at byte zero.  Otherwise a mixed-device checkpoint is rejected by
# validation even though its commit decoder accepts the same record.
payload_preflight=$(sed -n \
    '/^vm_restore_device_payload_validate_one(/,/^}/p' \
    "$source_root/usr.sbin/bhyve/snapshot.c")
for contract in \
    'pci_snapshot_compat(pdi, &compatibility)' \
    'if (error == 0)' \
    'checkpoint_compat_decode(record, record_size,' \
    'else if (error != ENOENT)'; do
	printf '%s\n' "$payload_preflight" | rg -q -F "$contract" || {
		echo "virtio requirements: device payload preflight lacks: $contract" >&2
		exit 1
	}
done
echo "virtio requirements: envelope-less PCI payload preflight matches commit"

# The compatibility producer is a variadic boundary whose output seals the
# immutable shared-memory topology.  Keep compiler format checking enabled and
# require an independent fixture that distinguishes every region field,
# including a 64-bit offset.
compat_producer=$(sed -n \
    '/^vi_pci_snapshot_compat(/,/^}/p' \
    "$source_root/usr.sbin/bhyve/virtio.c")
for contract in \
    '"%s%u:%u:%ju:%ju"' \
    'region->id, region->bar' \
    '(uintmax_t)region->offset' \
    '(uintmax_t)region->length'; do
	printf '%s\n' "$compat_producer" | rg -q -F "$contract" || {
		echo "virtio requirements: shared-memory compatibility lacks: $contract" >&2
		exit 1
	}
done
rg -q -U 'vi_snapshot_compat_append\(char \*, size_t, size_t \*, const char \*, \.\.\.\)[[:space:]]*\n[[:space:]]*__printflike\(4, 5\);' \
    "$source_root/usr.sbin/bhyve/virtio.c" || {
	echo "virtio requirements: compatibility formatter lacks compile-time checking" >&2
	exit 1
}
for fixture in \
    snapshot_compat_includes_shared_memory_shape \
    '7:4:4096:8192,9:5:4294967296:12288'; do
	rg -q -F "$fixture" \
	    "$source_root/tests/sys/kern/vsock_device_harness/virtio_core_test.c" || {
		echo "virtio requirements: shared-memory compatibility fixture lacks: $fixture" >&2
		exit 1
	}
done
echo "virtio requirements: shared-memory compatibility shape is independently fenced"
echo "virtio requirements: unreleased obsolete format decoders are absent"
else
	echo "virtio requirements: source-only host ring-ordering check unavailable"
fi
