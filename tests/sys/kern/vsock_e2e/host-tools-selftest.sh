#!/bin/sh
# VM-free checks for the host programs used by the VirtIO E2E runner.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
. "$here/virtio-ring-trace.sh"
if [ -z "${TOOLS:-}" ]; then
	if [ -f "$here/Makefile" ]; then
		TOOLS=$(make -C "$here" -V .OBJDIR)
	else
		TOOLS=$here
	fi
fi
work=$(mktemp -d)
server_pid=
cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
	# Evidence-bundle negative tests deliberately leave immutable-looking
	# mode-0444 fixtures behind.  Restore owner permissions before the scoped
	# recursive removal so an interactive release run cannot block on rm's
	# write-protected-file prompt.
	chmod -R u+rwX "$work" 2>/dev/null || true
	rm -rf "$work"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

for tool in unix-pipe vsock-pipe vsh-connect vsh-connect-test-server \
    uinput-inject freebsd-input-check freebsd-tpm2-check \
    freebsd-fwcfg-check wdfire gpu-rfb-check vtcryptocbc; do
	[ -x "$TOOLS/$tool" ] || {
		echo "missing helper: $TOOLS/$tool" >&2
		exit 1
	}
done

"$TOOLS/freebsd-tpm2-check" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  freebsd_tpm2_guest_helper_selftest"
"$TOOLS/freebsd-fwcfg-check" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  freebsd_fwcfg_guest_helper_selftest"

resolver_root="$work/nonvirtio-resolver"
mkdir -p "$resolver_root/bin" "$resolver_root/dev"
for node in ada0 nvme2ns1 dsp7 ums2; do
	ln -s /dev/null "$resolver_root/dev/$node"
done
cat >"$resolver_root/bin/devinfo" <<'EOF'
#!/bin/sh
if [ "$1" = -rv ]; then
	cat <<OUTPUT
ahci0 <AHCI> pnpinfo class=0x010601 at slot=21 function=0 dbsf=pci0:0:21:0
nvme2 <NVMe> pnpinfo class=0x010802 at slot=21 function=0 dbsf=pci0:0:21:0
em1 <e82545> pnpinfo class=0x020000 at slot=21 function=0 dbsf=pci0:0:21:0
hdac3 <HDA> pnpinfo class=0x040300 at slot=21 function=0 dbsf=pci0:0:21:0
xhci4 <xHCI> pnpinfo class=0x0c0330 at slot=21 function=0 dbsf=pci0:0:21:0
uart5 <UART> pnpinfo class=0x070002 at slot=21 function=0 dbsf=pci0:0:21:0
OUTPUT
	[ "${DEVINFO_DUPLICATE_EM:-no}" = no ] ||
	    echo 'em9 <duplicate> pnpinfo dbsf=pci0:0:21:0'
	exit 0
fi
[ "$1" = -p ] || exit 2
case "$2" in
pcm7) echo 'pcm7 hdaa0 hdacc0 hdac3 pci0 pcib0 nexus0' ;;
usbus4) echo 'usbus4 xhci4 pci0 pcib0 nexus0' ;;
ums2) echo 'ums2 uhub0 usbus4 xhci4 pci0 pcib0 nexus0' ;;
*) exit 1 ;;
esac
EOF
cat >"$resolver_root/bin/sysctl" <<'EOF'
#!/bin/sh
if [ "$1" = -n ] && [ "$2" = kern.disks ]; then
	echo 'vtbd0 ada0 nda9'
	exit 0
fi
if [ "$1" = -aN ]; then
	cat <<OUTPUT
dev.pcm.7.%parent
dev.usbus.4.%parent
dev.ums.2.%parent
OUTPUT
	exit 0
fi
exit 2
EOF
cat >"$resolver_root/bin/usbconfig" <<'EOF'
#!/bin/sh
[ "$1" = list ] || exit 2
echo 'ugen4.1: <BHYVE HID Tablet> at usbus4'
EOF
chmod 0555 "$resolver_root/bin/devinfo" "$resolver_root/bin/sysctl" \
    "$resolver_root/bin/usbconfig"
resolver="env PATH=$resolver_root/bin:/bin:/usr/bin DEVICE_ROOT=$resolver_root/dev sh $here/freebsd-nonvirtio.sh"
[ "$(sh -c "$resolver ahci-disk")" = ada0 ]
[ "$(sh -c "$resolver nvme-controller")" = nvme2 ]
[ "$(sh -c "$resolver nvme-disk")" = nvme2ns1 ]
[ "$(sh -c "$resolver e82545-interface")" = em1 ]
[ "$(sh -c "$resolver hda-pcm")" = dsp7 ]
[ "$(sh -c "$resolver xhci-bus")" = 4 ]
[ "$(sh -c "$resolver xhci-ugen")" = ugen4.1 ]
[ "$(sh -c "$resolver xhci-mouse")" = ums2 ]
[ "$(sh -c "$resolver pci-uart")" = uart5 ]
if DEVINFO_DUPLICATE_EM=yes sh -c "$resolver e82545-interface" \
    >"$work/resolver-ambiguous.out" 2>"$work/resolver-ambiguous.err"; then
	echo "5BSD device resolver accepted an ambiguous PCI assignment" >&2
	exit 1
fi
grep -q 'expected one em device.*found 2' "$work/resolver-ambiguous.err"
echo "PASS  freebsd_nonvirtio_device_resolver"

wait_for_socket()
{
	path=$1
	i=0
	while [ ! -S "$path" ] && [ "$i" -lt 50 ]; do
		kill -0 "$server_pid" 2>/dev/null || return 1
		sleep 0.1
		i=$((i + 1))
	done
	[ -S "$path" ]
}

wait_for_file()
{
	path=$1
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 50 ]; do
		kill -0 "$server_pid" 2>/dev/null || return 1
		sleep 0.1
		i=$((i + 1))
	done
	[ -s "$path" ]
}

check_vsh()
{
	type=$1
	flag=$2
	payload="vsh-$type-probe"
	dir="$work/vsh-$type"
	mkdir "$dir"
	"$TOOLS/vsh-connect-test-server" "$dir/sock" "$type" \
	    >"$dir/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$dir/sock" || {
		cat "$dir/server.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsh-connect" "$flag" "$dir" 7001)
	else
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsh-connect" "$dir" 7001)
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$payload" ]
	echo "PASS  vsh_connect_$type"
}

check_unix_pipe()
{
	type=$1
	flag=$2
	payload="unix-$type-probe"
	sock="$work/unix-$type.sock"
	if [ -n "$flag" ]; then
		"$TOOLS/unix-pipe" -l "$flag" -e -n 1 "$sock" \
		    >"$work/unix-$type.log" 2>&1 &
	else
		"$TOOLS/unix-pipe" -l -e -n 1 "$sock" \
		    >"$work/unix-$type.log" 2>&1 &
	fi
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-$type.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/unix-pipe" "$flag" "$sock")
	else
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/unix-pipe" "$sock")
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$payload" ]
	echo "PASS  unix_pipe_$type"
}

check_vsock_pipe()
{
	type=$1
	flag=$2
	port=$3
	payload="vsock-$type-probe"
	if [ -n "$flag" ]; then
		"$TOOLS/vsock-pipe" -l "$flag" -e -n 1 "$port" \
		    >"$work/vsock-$type.log" 2>&1 &
	else
		"$TOOLS/vsock-pipe" -l -e -n 1 "$port" \
		    >"$work/vsock-$type.log" 2>&1 &
	fi
	server_pid=$!
	sleep 0.2
	kill -0 "$server_pid" 2>/dev/null || {
		cat "$work/vsock-$type.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsock-pipe" "$flag" 1 "$port")
	else
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsock-pipe" 1 "$port")
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$payload" ]
	echo "PASS  vsock_pipe_local_$type"
}

check_vsock_seq_bigrecord()
{
	port=$1
	"$TOOLS/vsock-pipe" -l -s -d "$port" >"$work/vsock-seq-big.out" \
	    2>"$work/vsock-seq-big.log" &
	server_pid=$!
	sleep 0.2
	"$TOOLS/vsock-pipe" -s -1 1 "$port" <"$work/record.in" >/dev/null
	wait "$server_pid"
	server_pid=
	cmp "$work/record.in" "$work/vsock-seq-big.out"
	echo "PASS  vsock_pipe_local_seq_200k_record"
}

check_vsh_bulk()
{
	dir="$work/vsh-bulk"
	mkdir "$dir"
	"$TOOLS/vsh-connect-test-server" "$dir/sock" stream \
	    >"$dir/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$dir/sock" || {
		cat "$dir/server.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/vsh-connect" "$dir" 7001 \
	    < "$work/bulk.in" > "$work/vsh-bulk.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/bulk.in" "$work/vsh-bulk.out"
	echo "PASS  vsh_connect_stream_bulk"
}

check_vsh_lifecycle()
{
	type=$1
	flag=$2
	dir="$work/vsh-lifecycle-$type"
	mkdir "$dir"
	"$TOOLS/vsh-connect-test-server" "$dir/sock" "$type" live \
	    >"$dir/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$dir/sock" || {
		cat "$dir/server.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(timeout 10 "$TOOLS/vsh-connect" "$flag" -w "$dir" 7001)
	else
		out=$(timeout 10 "$TOOLS/vsh-connect" -w "$dir" 7001)
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$(printf 'READY\nDISCONNECTED')" ]
	echo "PASS  vsh_connect_lifecycle_$type"
}

check_unix_pipe_bulk()
{
	sock="$work/unix-bulk.sock"
	"$TOOLS/unix-pipe" -l -e -n 1 "$sock" \
	    >"$work/unix-bulk.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-bulk.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/unix-pipe" "$sock" \
	    < "$work/bulk.in" > "$work/unix-bulk.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/bulk.in" "$work/unix-bulk.out"
	echo "PASS  unix_pipe_stream_bulk"
}

check_unix_pipe_seq_record()
{
	sock="$work/unix-seq-record.sock"
	"$TOOLS/unix-pipe" -l -s -e -n 1 "$sock" \
	    >"$work/unix-seq-record.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-seq-record.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/unix-pipe" -s "$sock" \
	    < "$work/record.in" > "$work/unix-seq-record.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/record.in" "$work/unix-seq-record.out"
	echo "PASS  unix_pipe_seq_200k_record"
}

check_payload_chunks()
{
	source=$1
	name=${source##*/}
	encoded="$work/$name.b64"
	decoded="$work/$name.decoded"
	: > "$encoded"
	{ base64 < "$source" | tr -d '\n'; printf '\n'; } | fold -w 1024 |
	while IFS= read -r chunk; do
		printf %s "$chunk" >> "$encoded"
	done
	base64 -d "$encoded" > "$decoded"
	cmp -s "$source" "$decoded"
	echo "PASS  payload_chunks_$name"
}

check_cli_rejection()
{
	if "$TOOLS/vsh-connect" /does/not/exist invalid \
	    >"$work/vsh-invalid.log" 2>&1; then
		echo "vsh-connect accepted an invalid port" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	if "$TOOLS/unix-pipe" -l -n invalid "$work/invalid.sock" \
	    >"$work/unix-invalid.log" 2>&1; then
		echo "unix-pipe accepted an invalid connection count" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	if "$TOOLS/vsock-pipe" -l -e -n invalid 7000 \
	    >"$work/vsock-invalid.log" 2>&1; then
		echo "vsock-pipe accepted an invalid connection count" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	if "$TOOLS/gpu-rfb-check" /does/not/exist 1 1 not-a-pixel \
	    >"$work/gpu-rfb-invalid.log" 2>&1; then
		echo "gpu-rfb-check accepted an invalid checkpoint pixel" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	grep -q 'pixel must contain exactly eight hexadecimal digits' \
	    "$work/gpu-rfb-invalid.log"
	echo "PASS  malformed_helper_arguments_rejected"
}

check_console_status()
{
	expected_status=$1
	log="$work/console-$expected_status.log"
	input="$work/console-$expected_status.in"
	output="$work/console-$expected_status.out"
	error="$work/console-$expected_status.err"
	printf '%s\n' '__VSOCK_BEGIN_stale__' stale \
	    '__VSOCK_END_stale__:0' > "$log"
	: > "$input"
	CONSOLE_LOG="$log" CONSOLE_INPUT="$input" \
	    sh "$here/acmd-console.sh" 'ignored-command' 5 \
	    > "$output" 2> "$error" &
	server_pid=$!
	wait_for_file "$input"
	begin=$(sed -n 's/.*\(__VSOCK_BEGIN_[0-9_]*__\).*/\1/p' "$input")
	end=$(sed -n 's/.*\(__VSOCK_END_[0-9_]*__\).*/\1/p' "$input")
	[ -n "$begin" ] && [ -n "$end" ]
	printf 'echoed guest command\r\n%s:0\r\n%s\r\nguest-payload\r\n%s:%s\r\n' \
	    '__VSOCK_END_unrelated__' "$begin" "$end" "$expected_status" >> "$log"
	if wait "$server_pid"; then
		status=0
	else
		status=$?
	fi
	server_pid=
	[ "$status" -eq "$expected_status" ]
	[ "$(cat "$output")" = guest-payload ]
	[ ! -s "$error" ]
	echo "PASS  console_command_status_$expected_status"
}

check_console_timeout()
{
	log="$work/console-timeout.log"
	input="$work/console-timeout.in"
	: > "$log"
	: > "$input"
	if CONSOLE_LOG="$log" CONSOLE_INPUT="$input" \
	    sh "$here/acmd-console.sh" 'ignored-command' 1 \
	    >"$work/console-timeout.out" 2>"$work/console-timeout.err"; then
		echo "console helper accepted a missing completion marker" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 124 ]
	grep -q 'timed out after 1s' "$work/console-timeout.err"
	echo "PASS  console_command_timeout"
}

check_console_long_command()
{
	log="$work/console-long.log"
	input="$work/console-long.in"
	output="$work/console-long.out"
	error="$work/console-long.err"
	payload=$(dd if=/dev/zero bs=1 count=900 2>/dev/null | tr '\0' L)
	long_command="printf '%s\\n' '$payload'"
	: > "$log"
	: > "$input"
	CONSOLE_LOG="$log" CONSOLE_INPUT="$input" \
	    sh "$here/acmd-console.sh" "$long_command" 10 \
	    > "$output" 2> "$error" &
	server_pid=$!
	processed=0
	completed=no
	i=0
	while [ "$completed" = no ] && [ "$i" -lt 200 ]; do
		lines=$(tr '\r' '\n' < "$input" | awk 'NF { n++ } END { print n + 0 }')
		while [ "$processed" -lt "$lines" ]; do
			processed=$((processed + 1))
			line=$(tr '\r' '\n' < "$input" | awk -v n="$processed" 'NF { i++ } i == n { print; exit }')
			ack=$(printf '%s\n' "$line" | sed -n 's/.*\(__VSOCK_ACK_[0-9_]*__\).*/\1/p')
			[ -z "$ack" ] || printf '%s\r\n' "$ack" >> "$log"
			decode=$(printf '%s\n' "$line" | sed -n 's/.*\(__VSOCK_DECODE_[0-9_]*__\).*/\1/p')
			[ -z "$decode" ] || printf '%s:0\r\n' "$decode" >> "$log"
			begin=$(printf '%s\n' "$line" | sed -n 's/.*\(__VSOCK_BEGIN_[0-9_]*__\).*/\1/p')
			end=$(printf '%s\n' "$line" | sed -n 's/.*\(__VSOCK_END_[0-9_]*__\).*/\1/p')
			if [ -n "$begin" ] && [ -n "$end" ]; then
				printf '%s\r\n%s\r\n%s:0\r\n' "$begin" guest-long-payload "$end" >> "$log"
				completed=yes
			fi
		done
		[ "$completed" = yes ] || sleep 0.1
		i=$((i + 1))
	done
	[ "$completed" = yes ]
	if wait "$server_pid"; then
		status=0
	else
		status=$?
	fi
	server_pid=
	[ "$status" -eq 0 ]
	[ "$(cat "$output")" = guest-long-payload ]
	[ ! -s "$error" ]
	tr '\r' '\n' < "$input" | awk 'length > 240 { exit 1 }'
	encoded=$(tr '\r' '\n' < "$input" |
	    sed -n 's/.*printf %s \([A-Za-z0-9+\/=]*\) >> .*\.b;.*/\1/p' |
	    tr -d '\n')
	[ -n "$encoded" ]
	decoded=$(printf %s "$encoded" | base64 -d)
	[ "$decoded" = "$long_command" ]
	echo "PASS  console_long_command_chunking"
}

check_nested_evidence_validator()
{
	vmmdir="$here/../../vmm"
	validator="$vmmdir/validate-vmx-nested-live-evidence.sh"
	ledger="$vmmdir/vmx-nested-live-qualification.tsv"
	good="$work/nested-evidence-good.tsv"
	bad="$work/nested-evidence-bad.tsv"
	artifacts="$work/nested-evidence-artifacts"
	run_id=0123456789abcdef0123456789abcdef

	[ -r "$validator" ] && [ -r "$ledger" ]
	mkdir -m 0700 "$artifacts"
	printf '%s\n' \
	    'feature_id	linux_l2_evidence	fivebsd_l2_evidence	host_evidence' \
	    > "$good"
	awk -F '	' 'NR > 1 {
		printf "%s\tnested-vmx-live:linux-%d\tnested-vmx-live:fivebsd-%d\tnested-vmx-live:host-%d\n",
		    $1, NR - 1, NR - 1, NR - 1
	}' "$ledger" >> "$good"
	awk -F '	' 'NR > 1 { print $1, NR - 1, $2 }' "$ledger" |
	while read -r feature number requirements; do
		for role in linux-l2 fivebsd-l2 host; do
			case "$role" in
			linux-l2) name=linux-$number; kind=guest-test ;;
			fivebsd-l2) name=fivebsd-$number; kind=guest-test ;;
			host) name=host-$number; kind=host-trace ;;
			esac
			printf '%s\n' \
			    'format	nested-vmx-live-evidence-v3' \
			    "feature_id	$feature" \
			    "role	$role" \
			    "run_id	$run_id" \
			    'started_utc	2026-07-31T12:00:00Z' \
			    'finished_utc	2026-07-31T12:00:01Z' \
			    'result	PASS' \
			    > "$artifacts/$name.evidence"
			printf '%s\n' "$requirements" | tr ';' '\n' |
			while read -r requirement; do
				printf 'assertion\t%s\n' "$requirement"
				printf 'proof\t%s\t%s\t%s\t1\n' \
				    "$requirement" "$kind" "$feature-$role-record"
			done >> "$artifacts/$name.evidence"
			chmod 0444 "$artifacts/$name.evidence"
		done
	done
	chmod 0444 "$good"
	NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" \
	    sh "$validator" "$good" >/dev/null

	sed '$d' "$good" > "$bad"
	chmod 0444 "$bad"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$bad" \
	    >"$work/nested-bad.out" 2>"$work/nested-bad.err"; then
		echo "nested evidence validator accepted a missing group" >&2
		return 1
	fi
	grep -Eq 'does not prove every mandatory live feature group|malformed evidence' \
	    "$work/nested-bad.err"

	chmod 0644 "$bad"
	cp "$good" "$bad"
	chmod 0644 "$bad"
	printf '%s\n' \
	    'EXPOSURE-POLICY	nested-vmx-live:duplicate	nested-vmx-live:duplicate	nested-vmx-live:duplicate' \
	    >> "$bad"
	chmod 0444 "$bad"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$bad" \
	    >"$work/nested-duplicate.out" 2>"$work/nested-duplicate.err"; then
		echo "nested evidence validator accepted a duplicate group" >&2
		return 1
	fi
	grep -q 'malformed evidence' "$work/nested-duplicate.err"

	chmod 0644 "$bad"
	cp "$good" "$bad"
	chmod 0644 "$bad"
	sed -i '' '2s/nested-vmx-live:fivebsd-1/nested-vmx-live:linux-1/' \
	    "$bad"
	chmod 0444 "$bad"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$bad" \
	    >"$work/nested-alias.out" 2>"$work/nested-alias.err"; then
		echo "nested evidence validator accepted aliased assertions" >&2
		return 1
	fi
	grep -q 'malformed evidence' "$work/nested-alias.err"

	mv -f "$artifacts/linux-1.evidence" "$artifacts/linux-1.missing"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-missing.out" 2>"$work/nested-missing.err"; then
		echo "nested evidence validator accepted a missing artifact" >&2
		return 1
	fi
	grep -q 'missing evidence artifact' "$work/nested-missing.err"
	mv -f "$artifacts/linux-1.missing" "$artifacts/linux-1.evidence"

	cp "$artifacts/host-1.evidence" "$work/host-1.saved"
	chmod 0644 "$artifacts/host-1.evidence"
	sed -i '' '/^proof	.*	host-trace	/d' \
	    "$artifacts/host-1.evidence"
	chmod 0444 "$artifacts/host-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-content.out" 2>"$work/nested-content.err"; then
		echo "nested evidence validator accepted a host label without a trace" >&2
		return 1
	fi
	grep -q 'artifact does not prove' "$work/nested-content.err"
	mv -f "$work/host-1.saved" "$artifacts/host-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	chmod 0644 "$artifacts/linux-1.evidence"
	printf '%s\n' 'result	FAIL' >> "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-conflict.out" 2>"$work/nested-conflict.err"; then
		echo "nested evidence validator accepted conflicting results" >&2
		return 1
	fi
	grep -q 'artifact does not prove' "$work/nested-conflict.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	chmod 0644 "$artifacts/linux-1.evidence"
	sed -i '' "s/^run_id	$run_id\$/run_id	ffffffffffffffffffffffffffffffff/" \
	    "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-stale.out" 2>"$work/nested-stale.err"; then
		echo "nested evidence validator accepted a stale run artifact" >&2
		return 1
	fi
	grep -q 'artifact does not prove' "$work/nested-stale.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	chmod 0644 "$artifacts/linux-1.evidence"
	sed -i '' \
	    's/^started_utc\t2026-07-31T12:00:00Z$/started_utc\t2026-07-31T12:00:02Z/' \
	    "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-time.out" 2>"$work/nested-time.err"; then
		echo "nested evidence validator accepted reversed timestamps" >&2
		return 1
	fi
	grep -q 'artifact does not prove' "$work/nested-time.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	chmod 0644 "$artifacts/linux-1.evidence"
	awk 'BEGIN { removed = 0 }
	    /^assertion\t/ && !removed { removed = 1; next }
	    { print }
	' "$artifacts/linux-1.evidence" > "$work/linux-1.missing-requirement"
	mv -f "$work/linux-1.missing-requirement" \
	    "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-requirement.out" \
	    2>"$work/nested-requirement.err"; then
		echo "nested evidence validator accepted missing requirements" >&2
		return 1
	fi
	grep -q 'artifact does not prove' "$work/nested-requirement.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	chmod 0644 "$artifacts/linux-1.evidence"
	awk 'BEGIN { replaced = 0 }
	    /^assertion\t/ && !replaced {
		print "assertion\tUNKNOWN-REQUIREMENT"
		replaced = 1
		next
	    }
	    { print }
	' "$artifacts/linux-1.evidence" > "$work/linux-1.unknown-requirement"
	mv -f "$work/linux-1.unknown-requirement" \
	    "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-unknown-requirement.out" \
	    2>"$work/nested-unknown-requirement.err"; then
		echo "nested evidence validator accepted an unknown requirement" >&2
		return 1
	fi
	grep -q 'artifact does not prove' \
	    "$work/nested-unknown-requirement.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"

	cp "$artifacts/linux-1.evidence" "$work/linux-1.saved"
	requirement=$(awk -F '\t' '$1 == "assertion" { print $2; exit }' \
	    "$artifacts/linux-1.evidence")
	chmod 0644 "$artifacts/linux-1.evidence"
	printf 'assertion\t%s\n' "$requirement" \
	    >> "$artifacts/linux-1.evidence"
	chmod 0444 "$artifacts/linux-1.evidence"
	if NESTED_LIVE_LEDGER="$ledger" \
	    NESTED_LIVE_ARTIFACT_DIR="$artifacts" \
	    NESTED_LIVE_RUN_ID="$run_id" sh "$validator" "$good" \
	    >"$work/nested-duplicate-requirement.out" \
	    2>"$work/nested-duplicate-requirement.err"; then
		echo "nested evidence validator accepted a duplicate requirement" >&2
		return 1
	fi
	grep -q 'artifact does not prove' \
	    "$work/nested-duplicate-requirement.err"
	mv -f "$work/linux-1.saved" "$artifacts/linux-1.evidence"
	echo "PASS  nested_vmx_live_evidence_bundle"
}

check_ring_trace_parser()
{
	trace="$work/ring.trace"

	cat > "$trace" <<-EOF
	chain vtnet 4 0 1 4
	event vtnet 1 split 7 8 0
	event vtnet 3 split 8 9 1
	EOF
	virtio_ring_trace_finish "$trace" split vtnet >/dev/null

	cat > "$trace" <<-EOF
	chain vtnet 4 0 1 4
	event vtnet 1 packed 7 8 0
	event vtnet 3 packed 8 9 1
	EOF
	virtio_ring_trace_finish "$trace" packed vtnet >/dev/null

	cat > "$trace" <<-EOF
	chain vtrnd 0 0 1 4
	event vtrnd 0 split 7 8 0
	event vtrnd 0 split 8 9 1
	chain vtnet 4 0 0 4
	event vtnet 1 split 7 8 1
	EOF
	if virtio_ring_trace_finish "$trace" split vtnet \
	    >"$work/ring-wrong-device.out" 2>"$work/ring-wrong-device.err"; then
		echo "ring trace parser accepted evidence from another device" >&2
		return 1
	fi
	grep -q 'host_indirect_descriptor_data' "$work/ring-wrong-device.err"

	cat > "$trace" <<-EOF
	chain vtnet 4 0 0 4
	event vtnet 1 split 7 8 0
	event vtnet 3 split 8 9 1
	EOF
	if virtio_ring_trace_finish "$trace" split \
	    >"$work/ring-no-indirect.out" 2>"$work/ring-no-indirect.err"; then
		echo "ring trace parser accepted a direct-only trace" >&2
		return 1
	fi
	grep -q 'host_indirect_descriptor_data' "$work/ring-no-indirect.err"

	cat > "$trace" <<-EOF
	chain vtnet 4 0 1 4
	event vtnet 3 split 8 9 1
	EOF
	if virtio_ring_trace_finish "$trace" split \
	    >"$work/ring-no-suppress.out" 2>"$work/ring-no-suppress.err"; then
		echo "ring trace parser accepted a trace without suppression" >&2
		return 1
	fi
	grep -q 'host_event_idx_suppression' "$work/ring-no-suppress.err"

	cat > "$trace" <<-EOF
	chain vtnet 4 0 1 4
	event vtnet 1 split 7 8 0
	EOF
	if virtio_ring_trace_finish "$trace" split \
	    >"$work/ring-no-interrupt.out" 2>"$work/ring-no-interrupt.err"; then
		echo "ring trace parser accepted a trace without an interrupt" >&2
		return 1
	fi
	grep -q 'host_event_idx_interrupt' "$work/ring-no-interrupt.err"

	cat > "$trace" <<-EOF
	chain vtnet 4 0 1 4
	event vtnet 1 packed 7 8 0
	event vtnet 3 packed 8 9 1
	EOF
	if virtio_ring_trace_finish "$trace" split \
	    >"$work/ring-wrong-layout.out" 2>"$work/ring-wrong-layout.err"; then
		echo "ring trace parser accepted the wrong ring layout" >&2
		return 1
	fi
	grep -q 'host_event_idx_suppression' "$work/ring-wrong-layout.err"
	echo "PASS  virtio_ring_trace_parser"
}

check_iommu_trace_parser()
{
	trace="$work/iommu.trace"

	cat > "$trace" <<-EOF
	iommu vtiommu 32 4096 64 1
	iommu vtiommu 32 8192 64 1
	iommu vtiommu 40 12288 128 1
	EOF
	virtio_iommu_trace_finish "$trace" 2 >/dev/null

	if virtio_iommu_trace_finish "$trace" 3 \
	    >"$work/iommu-missing.out" 2>"$work/iommu-missing.err"; then
		echo "IOMMU trace parser accepted a missing endpoint" >&2
		return 1
	fi
	grep -q 'endpoints=2 expected=3' "$work/iommu-missing.err"

	cat >> "$trace" <<-EOF
	iommu vtiommu 48 16384 32 0
	EOF
	if virtio_iommu_trace_finish "$trace" 2 \
	    >"$work/iommu-fault.out" 2>"$work/iommu-fault.err"; then
		echo "IOMMU trace parser accepted a failed translation" >&2
		return 1
	fi
	grep -q 'rejected DMA translation' "$work/iommu-fault.err"
	echo "PASS  virtio_iommu_trace_parser"
}

check_net_hash_trace_parser()
{
	trace="$work/net-hash.trace"

	cat > "$trace" <<-EOF
	nethash vtnet 2 305419896 1 64
	EOF
	virtio_net_hash_trace_finish "$trace" 2 >/dev/null

	sed 's/ 1 64$/ 0 64/' "$trace" > "$work/net-hash-none.trace"
	if virtio_net_hash_trace_finish "$work/net-hash-none.trace" 2 \
	    >"$work/net-hash-none.out" 2>"$work/net-hash-none.err"; then
		echo "net hash parser accepted HASH_REPORT_NONE" >&2
		return 1
	fi
	grep -q 'host_net_hash_report' "$work/net-hash-none.err"

	sed 's/vtnet 2/vtnet 3/' "$trace" > "$work/net-hash-txq.trace"
	if virtio_net_hash_trace_finish "$work/net-hash-txq.trace" 2 \
	    >"$work/net-hash-txq.out" 2>"$work/net-hash-txq.err"; then
		echo "net hash parser accepted a transmit queue" >&2
		return 1
	fi
	grep -q 'host_net_hash_report' "$work/net-hash-txq.err"

	if virtio_net_hash_trace_finish "$trace" 1 \
	    >"$work/net-hash-range.out" 2>"$work/net-hash-range.err"; then
		echo "net hash parser accepted an inactive receive queue" >&2
		return 1
	fi
	grep -q 'host_net_hash_report' "$work/net-hash-range.err"
	echo "PASS  virtio_net_hash_trace_parser"
}

check_gpu_blob_trace_parser()
{
	trace="$work/gpu.trace"

	cat > "$trace" <<-EOF
	gpu vtgpu 0 268 24 0
	gpu vtgpu 0 269 24 0
	EOF
	virtio_gpu_blob_trace_finish "$trace" >/dev/null

	sed '/ 269 /d' "$trace" > "$work/gpu-missing.trace"
	if virtio_gpu_blob_trace_finish "$work/gpu-missing.trace" \
	    >"$work/gpu-missing.out" 2>"$work/gpu-missing.err"; then
		echo "GPU trace parser accepted a missing SET_SCANOUT_BLOB" >&2
		return 1
	fi
	grep -q 'command=269' "$work/gpu-missing.err"

	sed 's/ 268 24 0/ 268 24 22/' "$trace" > "$work/gpu-error.trace"
	if virtio_gpu_blob_trace_finish "$work/gpu-error.trace" \
	    >"$work/gpu-error.out" 2>"$work/gpu-error.err"; then
		echo "GPU trace parser accepted a failed RESOURCE_CREATE_BLOB" >&2
		return 1
	fi
	grep -q 'command=268' "$work/gpu-error.err"
	echo "PASS  virtio_gpu_blob_trace_parser"
}

check_device_ring_trace_parser()
{
	trace="$work/device-ring.trace"

	cat > "$trace" <<-EOF
	chain vtgpu 0 1 0 4
	chain vtnet 1 0 1 3
	EOF
	virtio_device_ring_trace_finish "$trace" packed vtgpu >/dev/null
	virtio_device_ring_trace_finish "$trace" split vtnet >/dev/null
	if virtio_device_ring_trace_finish "$trace" split vtgpu \
	    >"$work/device-ring-layout.out" \
	    2>"$work/device-ring-layout.err"; then
		echo "device ring parser accepted the wrong layout" >&2
		return 1
	fi
	grep -q 'device=vtgpu layout=split' \
	    "$work/device-ring-layout.err"
	if virtio_device_ring_trace_finish "$trace" packed vtrnd \
	    >"$work/device-ring-name.out" \
	    2>"$work/device-ring-name.err"; then
		echo "device ring parser accepted evidence from another device" >&2
		return 1
	fi
	grep -q 'device=vtrnd layout=packed' "$work/device-ring-name.err"
	echo "PASS  virtio_device_ring_trace_parser"
}

check_vsh stream ""
check_vsh seq -s
check_unix_pipe stream ""
check_unix_pipe seq -s
vsock_port=$((45000 + ($$ % 10000)))
check_vsock_pipe stream "" "$vsock_port"
check_vsock_pipe seq -s "$((vsock_port + 1))"
dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\0' B > "$work/bulk.in"
dd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\0' R > "$work/record.in"
check_vsock_seq_bigrecord "$((vsock_port + 2))"
check_vsh_bulk
check_vsh_lifecycle stream ""
check_vsh_lifecycle seq -s
check_unix_pipe_bulk
check_unix_pipe_seq_record
check_cli_rejection
check_console_status 0
check_console_status 7
check_console_timeout
check_console_long_command
check_nested_evidence_validator
check_ring_trace_parser
check_net_hash_trace_parser
check_iommu_trace_parser
check_gpu_blob_trace_parser
check_device_ring_trace_parser
"$TOOLS/uinput-inject" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  uinput_provider_selftest"
"$TOOLS/freebsd-input-check" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  freebsd_input_guest_helper_selftest"
"$TOOLS/gpu-rfb-check" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  gpu_rfb_presentation_helper_selftest"
check_payload_chunks "$here/gvsock.py"
check_payload_chunks "$here/ginput.py"
check_payload_chunks "$here/grng.py"
check_payload_chunks "$here/gballoon.py"
check_payload_chunks "$here/grtc.py"
check_payload_chunks "$here/gblock.py"
check_payload_chunks "$here/gnet.py"
check_payload_chunks "$here/gscsi.py"
check_payload_chunks "$here/gconsole.py"
check_payload_chunks "$here/g9p.py"
check_payload_chunks "$here/ggpu.py"
check_payload_chunks "$here/gmem.py"
check_payload_chunks "$here/gpmem.py"
check_payload_chunks "$here/giommu.py"
check_payload_chunks "$here/gsnd.py"
check_payload_chunks "$here/gcheckpoint.py"
echo "host helper self-tests completed successfully"
