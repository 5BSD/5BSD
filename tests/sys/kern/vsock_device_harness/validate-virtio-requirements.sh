#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
catalog=${1:-"$script_dir/virtio-1.4-requirements.tsv"}
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
	if (errors != 0)
		exit 1
	printf "virtio requirements: %d entries validated\n", rows
}
' "$catalog"

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
	esac

	if [ -r "$source" ]; then
		if ! grep -Eq \
		    "ATF_TC_(WITHOUT_HEAD|WITH_CLEANUP)\\($test_case\\)" \
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
# The guest contract test is the deliberate exception: it compares public
# production constants directly with the oracle.
protocol_names='((VIRTIO_CONFIG|VIRTIO_F|VIRTIO_RING_F|VIRTIO_PCI_CAP|VIRTIO_PCI_COMMON|VIRTIO_PCI_ISR|VIRTIO_MSI|VIRTIO_ID|VIRTIO_DEV|VIRTIO_9P_F|VIRTIO_NET_F|VIRTIO_SCSI|VIRTIO_VSOCK|VRING|VTCON_F|VTCON_DEVICE|VTCON_PORT|VTINPUT_CFG|VTNET_HDR|VTBLK_S|VTBLK_F|VBH_OP|VBH_FLAG)_[A-Z0-9_]+|VIRTIO_PCI_(CONFIG_OFF|HOST_FEATURES|GUEST_FEATURES|QUEUE_PFN|QUEUE_NUM|QUEUE_SEL|QUEUE_NOTIFY|STATUS|ISR)|VTINPUT_(EVENTQ|STATUSQ)|VTNET_(RXQ|TXQ|CTLQ)|VTBLK_(BSIZE|BLK_ID_LEN))'
for source in "$test_dir"/*_test.c; do
	[ -r "$source" ] || continue
	case "${source##*/}" in
	virtio_guest_contract_test.c|virtio_host_contract_test.c)
		continue
		;;
	esac
	grep -q 'virtio_1_4_spec.h' "$source" || continue

	# Oracle aliases must be introduced only after every production .c file
	# has been included.  Otherwise the device under test would compile with
	# the expected values and a wrong production definition could pass.
	if ! awk -v pattern="$protocol_names" '
	/^#include[[:space:]]+".*\.c"/ {
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
	grep '^#undef ' "$source" |
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
	/^ATF_TC_BODY\((virtio_1_4_wire_layout|receive_header_layout),/ {
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
# comes from the transcribed standard, not from another production structure
# or a duplicated implementation expression.  Accumulate multiline ATF calls
# and require the independent oracle on the expected side.
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
		if (statement !~ /VIRTIO14_/) {
			printf "%s:%d: wire-layout assertion lacks VIRTIO14 oracle\n",
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
	echo "virtio requirements: guest resource fallback loops are bounded"
else
	echo "virtio requirements: source-only resource loop check unavailable"
fi

# MMIO exposes QueueNumMax as a 32-bit register, but split virtqueues have a
# document-defined 16-bit parameter with a maximum of 32768.  Require both the
# initial allocation and reinitialization paths to validate the full-width
# register value before explicitly narrowing it.
if [ -n "$source_root" ]; then
	mmio_source=$source_root/sys/dev/virtio/mmio/virtio_mmio.c
	for function_name in vtmmio_alloc_virtqueues vtmmio_reinit_virtqueue; do
		if ! awk -v function_name="$function_name" '
$0 ~ ("^" function_name "\\(") {
	in_function = 1
}
in_function && /virtio_split_queue_size_valid\(size\)/ {
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
	if ! awk '
	{
		joined = previous $0
		if (joined ~ /atomic_load_acq_16\(.*&vq->vq_avail->idx\)/)
			found = 1
		previous = $0
	}
	END { exit(found ? 0 : 1) }
	' "$host_core"; then
		echo "virtio requirements: host ring consumption lacks an acquire index load" >&2
		exit 1
	fi
	if ! grep -Eq \
	    'atomic_store_rel_16\(&vq->vq_used->idx,[[:space:]]*vq->vq_next_used\)' \
	    "$host_core"; then
		echo "virtio requirements: host completion publication lacks a release index store" >&2
		exit 1
	fi
	if ! grep -Eq \
	    'atomic_load_acq_16\(&vq->vq_avail->idx\)' \
	    "$host_header"; then
		echo "virtio requirements: host queue-ready check lacks an acquire index load" >&2
		exit 1
	fi
	echo "virtio requirements: host split-ring publication ordering validated"
else
	echo "virtio requirements: source-only host ring-ordering check unavailable"
fi
