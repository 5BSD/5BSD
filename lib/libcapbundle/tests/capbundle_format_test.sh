#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Clean-break Bundle.ucl/Unit.ucl contract tests.  Each matrix row is an
# independent parser invocation so one rejection cannot mask another.

# Resolve servicectl through the co-located helper, which uses the object-tree
# binary when TEST_OBJTOP is set and otherwise the installed /usr/sbin one.  This
# keeps the test runnable both in-tree and from an installed /usr/tests.
servicetcl()
{
	"$(atf_get_srcdir)/servicectl" "$@"
}

setup_work()
{
	WORK="$(pwd)/work.$$"
	mkdir -p "$WORK"
}

make_bundle()
{
	name=${1:-Good}
	bid=${2:-org.test.good}
	unit=${3:-worker}
	dir="$WORK/$name.cap"
	mkdir -p "$dir/Units/$unit.unit/bin"
	cat > "$dir/Bundle.ucl" <<-EOF
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "$bid";
	version = "1.2.3";
	sequence = 7;
	author = "Test Author";
	publisher = "org.test.publisher";
	units = ["$unit"];
	EOF
	cat > "$dir/Units/$unit.unit/Unit.ucl" <<-EOF
	activation { boot = true; }
	restart = "on-failure";
	EOF
	printf '#!/bin/sh\nexit 0\n' > "$dir/Units/$unit.unit/bin/$unit"
	chmod 0555 "$dir/Units/$unit.unit/bin/$unit"
	printf '%s\n' "$dir"
}

verify_ok()
{
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    servicetcl verify "$1"
}

verify_bad()
{
	pattern=$1
	shift
	atf_check -s exit:1 -o ignore -e match:"$pattern" \
	    servicetcl verify "$1"
}

cleanup_work()
{
	rm -rf "$(pwd)/work.$$"
}

atf_test_case valid_contract cleanup
valid_contract_head() { atf_set descr "Parse metadata, defaults, and explicit activation"; }
valid_contract_body()
{
	setup_work
	dir=$(make_bundle)
	atf_check -s exit:0 \
	    -o match:'ID:      org.test.good' \
	    -o match:'Version: 1.2.3' \
	    -o match:'Publisher: org.test.publisher' \
	    -o match:'Sequence: 7' \
	    -o match:'org.test.good/worker' \
	    -o match:'activation: boot' \
	    servicetcl verify "$dir"
}
valid_contract_cleanup() { cleanup_work; }

atf_test_case protect_policy cleanup
protect_policy_head() { atf_set descr "Parse launcher-applied protection flag policy"; }
protect_policy_body()
{
	setup_work
	dir=$(make_bundle)
	unit="$dir/Units/worker.unit/Unit.ucl"

	# Individual flags: ptrace(0x1)|noprivs(0x200)|nofork(0x400) = 0x601.
	printf '%s\n' 'activation { boot = true; }
protect = ["ptrace", "noprivs", "nofork"];' > "$unit"
	atf_check -s exit:0 -o match:'protect: 0x601' \
	    servicetcl verify "$dir"

	# The "protect" group alias expands to the full outward set (0x1ff).
	printf '%s\n' 'activation { boot = true; }
protect = ["protect"];' > "$unit"
	atf_check -s exit:0 -o match:'protect: 0x1ff' \
	    servicetcl verify "$dir"

	# Unknown flag names are ignored (still verifies), known ones still apply.
	printf '%s\n' 'activation { boot = true; }
protect = ["visible", "bogus"];' > "$unit"
	atf_check -s exit:0 -o match:'protect: 0x4' \
	    servicetcl verify "$dir"

	# No protect stanza: nothing printed.
	printf '%s\n' 'activation { boot = true; }' > "$unit"
	atf_check -s exit:0 -o not-match:'protect:' \
	    servicetcl verify "$dir"
}
protect_policy_cleanup() { cleanup_work; }

atf_test_case activation_matrix cleanup
activation_matrix_head() { atf_set descr "Exercise boot and IPC activation combinations"; }
activation_matrix_body()
{
	setup_work
	dir=$(make_bundle)
	unit="$dir/Units/worker.unit/Unit.ucl"
	for declaration in \
	    'activation { boot = true; }' \
	    'activation { ipc = ["org.test.one"]; }' \
	    'activation { boot = true; ipc = ["org.test.one"]; }' \
	    'activation { boot = false; ipc = "org.test.one"; }'; do
		printf '%s\n' "$declaration" > "$unit"
		verify_ok "$dir"
	done
	for declaration in \
	    'activation {}' \
	    'activation { boot = false; }' \
	    'activation { boot = "yes"; }' \
	    'activation { ipc = []; }' \
	    'activation { ipc = ["bad"]; }' \
	    'activation { ipc = ["org.test.x", "org.test.x"]; }' \
	    'activation { mystery = true; }'; do
		printf '%s\n' "$declaration" > "$unit"
		verify_bad 'activation|duplicate|invalid' "$dir"
	done
	: > "$unit"
	verify_bad 'activation|empty document' "$dir"
}
activation_matrix_cleanup() { cleanup_work; }

atf_test_case bundle_required_matrix cleanup
bundle_required_matrix_head() { atf_set descr "Every bundle identity field is mandatory and typed"; }
bundle_required_matrix_body()
{
	setup_work
	for key in schema schema_version bundle_id version sequence units; do
		dir=$(make_bundle "missing-$key")
		sed -i '' "/^$key =/d" "$dir/Bundle.ucl"
		verify_bad "$key|units|schema" "$dir"
	done
	for replacement in \
	    'schema = 1;' \
	    'schema_version = "1";' \
	    'bundle_id = 4;' \
	    'version = 4;' \
	    'sequence = "7";' \
	    'units = "worker";'; do
		key=${replacement%% *}
		dir=$(make_bundle "type-$key")
		sed -i '' "s/^$key =.*/$replacement/" "$dir/Bundle.ucl"
		verify_bad "$key|units|schema" "$dir"
	done
}
bundle_required_matrix_cleanup() { cleanup_work; }

atf_test_case bundle_value_matrix cleanup
bundle_value_matrix_head() { atf_set descr "Reject malformed bundle identities and versions"; }
bundle_value_matrix_body()
{
	setup_work
	for value in 0 -1 -9223372036854775808; do
		dir=$(make_bundle "sequence-${value#-}")
		sed -i '' "s/^sequence =.*/sequence = $value;/" "$dir/Bundle.ucl"
		verify_bad sequence "$dir"
	done
	i=0
	for value in bad .org.test org..test org.test. 'org/test'; do
		i=$((i + 1))
		dir=$(make_bundle "badid-$i")
		sed -i '' "s|^bundle_id =.*|bundle_id = \"$value\";|" \
		    "$dir/Bundle.ucl"
		verify_bad bundle_id "$dir"
	done
	dir=$(make_bundle emptyversion)
	sed -i '' 's/^version =.*/version = "";/' "$dir/Bundle.ucl"
	verify_bad version "$dir"
	dir=$(make_bundle unknown)
	printf '%s\n' 'typo = true;' >> "$dir/Bundle.ucl"
	verify_bad 'unknown key.*typo' "$dir"
}
bundle_value_matrix_cleanup() { cleanup_work; }

atf_test_case unit_name_matrix cleanup
unit_name_matrix_head() { atf_set descr "Unit directory identities use a narrow portable alphabet"; }
unit_name_matrix_body()
{
	setup_work
	for name in worker worker-2 a 0worker; do
		dir=$(make_bundle "valid-$name" org.test.valid "$name")
		verify_ok "$dir"
	done
	for name in Worker _worker worker_2 worker.2 -worker worker- 'worker x' ..; do
		dir=$(make_bundle invalid org.test.invalid worker)
		sed -i '' "s/units =.*/units = [\"$name\"];/" "$dir/Bundle.ucl"
		verify_bad 'unit name|declared unit' "$dir"
	done
}
unit_name_matrix_cleanup() { cleanup_work; }

atf_test_case exact_inventory cleanup
exact_inventory_head() { atf_set descr "Declared, missing, duplicate, and stray units fail closed"; }
exact_inventory_body()
{
	setup_work
	dir=$(make_bundle missing)
	mv "$dir/Units/worker.unit" "$dir/Units/other.unit"
	verify_bad 'declared unit.*missing' "$dir"
	dir=$(make_bundle duplicate)
	sed -i '' 's/units =.*/units = ["worker", "worker"];/' "$dir/Bundle.ucl"
	verify_bad 'duplicate.*worker' "$dir"
	dir=$(make_bundle stray)
	mkdir "$dir/Units/stray.unit"
	verify_bad 'undeclared entry.*stray.unit' "$dir"
	dir=$(make_bundle strayfile)
	: > "$dir/Units/README"
	verify_bad 'undeclared entry.*README' "$dir"
}
exact_inventory_cleanup() { cleanup_work; }

atf_test_case clean_break_rejections cleanup
clean_break_rejections_head() { atf_set descr "Old schemas and lifecycle inference are not accepted"; }
clean_break_rejections_body()
{
	setup_work
	dir=$(make_bundle oldroot)
	mv "$dir/Bundle.ucl" "$dir/Old.ucl"
	verify_bad 'Bundle.ucl' "$dir"
	dir=$(make_bundle oldunit)
	unit="$dir/Units/worker.unit/Unit.ucl"
	for declaration in \
	    'schema = "org.5bsd.serviced.service";' \
	    'schema_version = "1.0.0";' \
	    'bundle_id = "org.test.old";' \
	    'provides = ["org.test.old"];' \
	    'components = ["network"];' \
	    'on_demand = true;'; do
		printf '%s\n' 'activation { boot = true; }' "$declaration" > "$unit"
		verify_bad 'unknown key' "$dir"
	done
	dir=$(make_bundle oldlayout)
	mkdir "$dir/etc"
	: > "$dir/etc/worker.ucl"
	verify_bad 'root entry|not allowed|etc' "$dir"
}
clean_break_rejections_cleanup() { cleanup_work; }

atf_test_case program_matrix cleanup
program_matrix_head() { atf_set descr "Program defaults safely and cannot escape unit bin"; }
program_matrix_body()
{
	setup_work
	dir=$(make_bundle defaultprog)
	verify_ok "$dir"
	for program in /bin/sh ../worker bin/worker . .. ''; do
		dir=$(make_bundle badprogram)
		unit="$dir/Units/worker.unit/Unit.ucl"
		printf '%s\n' 'activation { boot = true; }' \
		    "program = \"$program\";" > "$unit"
		verify_bad 'program' "$dir"
	done
	dir=$(make_bundle missingbin)
	rm "$dir/Units/worker.unit/bin/worker"
	verify_bad 'binary not found' "$dir"
	dir=$(make_bundle noexec)
	chmod 0444 "$dir/Units/worker.unit/bin/worker"
	verify_bad 'not executable' "$dir"
}
program_matrix_cleanup() { cleanup_work; }

atf_test_case parser_hardening cleanup
parser_hardening_head() { atf_set descr "Duplicate keys, directives, and special files fail closed"; }
parser_hardening_body()
{
	setup_work
	dir=$(make_bundle duplicatekey)
	printf '%s\n' 'sequence = 8;' >> "$dir/Bundle.ucl"
	verify_bad 'duplicate|sequence' "$dir"
	dir=$(make_bundle include)
	printf '%s\n' '.include "/etc/passwd"' >> "$dir/Bundle.ucl"
	verify_bad 'macro|include|parser|unexpected' "$dir"
	dir=$(make_bundle unitsymlink)
	mv "$dir/Units/worker.unit/Unit.ucl" "$dir/real.ucl"
	ln -s "$dir/real.ucl" "$dir/Units/worker.unit/Unit.ucl"
	verify_bad 'regular|symlink' "$dir"
	dir=$(make_bundle binsymlink)
	rm "$dir/Units/worker.unit/bin/worker"
	ln -s /bin/true "$dir/Units/worker.unit/bin/worker"
	verify_bad 'symlink|non-regular' "$dir"
}
parser_hardening_cleanup() { cleanup_work; }

atf_test_case multi_unit_order cleanup
multi_unit_order_head() { atf_set descr "Multiple units retain declared order and independent activation"; }
multi_unit_order_body()
{
	setup_work
	dir=$(make_bundle multi org.test.multi alpha)
	mkdir -p "$dir/Units/beta.unit/bin" "$dir/Units/gamma.unit/bin"
	printf '%s\n' 'activation { ipc = ["org.test.beta"]; }' > \
	    "$dir/Units/beta.unit/Unit.ucl"
	printf '%s\n' 'activation { boot = true; ipc = ["org.test.gamma"]; }' > \
	    "$dir/Units/gamma.unit/Unit.ucl"
	for unit in beta gamma; do
		printf '#!/bin/sh\nexit 0\n' > "$dir/Units/$unit.unit/bin/$unit"
		chmod 0555 "$dir/Units/$unit.unit/bin/$unit"
	done
	sed -i '' 's/units =.*/units = ["gamma", "alpha", "beta"];/' \
	    "$dir/Bundle.ucl"
	atf_check -s exit:0 \
	    -o match:'Services: 3' \
	    -o match:'org.test.multi/gamma' \
	    -o match:'org.test.multi/alpha' \
	    -o match:'org.test.multi/beta' \
	    servicetcl verify "$dir"
}
multi_unit_order_cleanup() { cleanup_work; }

atf_test_case storage_contract cleanup
storage_contract_head() { atf_set descr "Storage scopes, lifetimes, keys, and references are exact"; }
storage_contract_body()
{
	setup_work
	for lifetime in persistent cache boot lease; do
		dir=$(make_bundle "unit-$lifetime")
		printf '%s\n' 'activation { boot = true; }' \
		    "storage = [{ name = \"data\"; scope = \"unit\"; rights = [\"mount\", \"props_read\"]; lifetime = \"$lifetime\"; }];" > \
		    "$dir/Units/worker.unit/Unit.ucl"
		atf_check -s exit:0 -o match:"lifetime=$lifetime scope=unit dataset=u-[0-9a-f]{48}" \
		    servicetcl verify "$dir"
	done
	for lifetime in persistent cache boot lease; do
		dir=$(make_bundle "shared-$lifetime")
		printf '%s\n' \
		    "shared { storage = [{ name = \"data\"; flavor = \"native\"; lifetime = \"$lifetime\"; }]; }" >> "$dir/Bundle.ucl"
		printf '%s\n' 'activation { boot = true; }' \
		    'storage = [{ name = "data"; scope = "shared"; rights = "mount"; }];' > \
		    "$dir/Units/worker.unit/Unit.ucl"
		atf_check -s exit:0 -o match:"flavor=native.*lifetime=$lifetime scope=shared dataset=s-[0-9a-f]{48}" \
		    servicetcl verify "$dir"
	done
}
storage_contract_cleanup() { cleanup_work; }

atf_test_case storage_negative_matrix cleanup
storage_negative_matrix_head() { atf_set descr "Malformed and ambiguous storage declarations fail closed"; }
storage_negative_matrix_body()
{
	setup_work
	i=0
	for declaration in \
	    'storage = "data";' \
	    'storage = [{}];' \
	    'storage = [{ name = "Data"; scope = "unit"; rights = "mount"; }];' \
	    'storage = [{ name = "data"; rights = "mount"; }];' \
	    'storage = [{ name = "data"; scope = "global"; rights = "mount"; }];' \
	    'storage = [{ name = "data"; scope = "unit"; rights = "unknown"; }];' \
	    'storage = [{ name = "data"; scope = "unit"; rights = []; }];' \
	    'storage = [{ name = "data"; scope = "unit"; rights = "mount"; lifetime = "ephemeral"; }];' \
	    'storage = [{ name = "data"; scope = "shared"; rights = "mount"; lifetime = "lease"; }];' \
	    'storage = [{ name = "data"; scope = "shared"; rights = "mount"; flavor = "native"; }];' \
	    'storage = [{ name = "data"; scope = "shared"; rights = "mount"; }];' \
	    'storage = [{ name = "data"; scope = "unit"; rights = "mount"; }, { name = "data"; scope = "unit"; rights = "mount"; }];'; do
		i=$((i + 1))
		dir=$(make_bundle "bad-storage-$i")
		printf '%s\n' 'activation { boot = true; }' "$declaration" > \
		    "$dir/Units/worker.unit/Unit.ucl"
		verify_bad 'storage|scope|rights|lifetime|duplicate|undeclared' "$dir"
	done
	dir=$(make_bundle old-storage)
	printf '%s\n' 'activation { boot = true; }' \
	    'capabilities { storage = [{ name = "data"; rights = "mount"; }]; }' > \
	    "$dir/Units/worker.unit/Unit.ucl"
	verify_bad 'unknown key.*storage' "$dir"
	for declaration in \
	    'shared = [];' \
	    'shared { unknown = []; }' \
	    'shared { storage = "data"; }' \
	    'shared { storage = [{}]; }' \
	    'shared { storage = [{ name = "Data"; }]; }' \
	    'shared { storage = [{ name = "data"; lifetime = "ephemeral"; }]; }' \
	    'shared { storage = [{ name = "data"; }, { name = "data"; }]; }'; do
		i=$((i + 1))
		dir=$(make_bundle "bad-shared-$i")
		printf '%s\n' "$declaration" >> "$dir/Bundle.ucl"
		verify_bad 'shared|storage|lifetime|duplicate|object|array' "$dir"
	done
}
storage_negative_matrix_cleanup() { cleanup_work; }

atf_test_case process_policy_matrix cleanup
process_policy_matrix_head() { atf_set descr "Process policy fields accept bounded explicit values"; }
process_policy_matrix_body()
{
	setup_work
	dir=$(make_bundle process)
	cat > "$dir/Units/worker.unit/Unit.ucl" <<-'EOF'
	program = "worker";
	arguments = ["--foreground", "literal argument with spaces"];
	environment { MODE = "test"; PATH = "/bin"; }
	activation { boot = true; ipc = ["org.test.process.worker"]; }
	restart = "always";
	stop_timeout = 300;
	max_failures = 100;
	kmod_requires = ["zfs", "if_bridge"];
	user = "capability";
	group = "capability";
	jail { name = "process-jail"; path = "/jails/process";
	    hostname = "process"; ip4_addr = "192.0.2.4"; }
	EOF
	verify_ok "$dir"

	i=0
	for declaration in \
	    'restart = "sometimes";' \
	    'stop_timeout = 0;' 'stop_timeout = 301;' 'stop_timeout = "5";' \
	    'max_failures = 0;' 'max_failures = 101;' \
	    'arguments = "--shell split";' 'arguments = [4];' \
	    'environment = [];' 'environment { 2BAD = "x"; }' \
	    'environment { AUTHORITYD_CHANNEL_FD = "9"; }' \
	    'environment { SERVICE_BOOTSTRAP_FD = "9"; }' \
	    'environment { CAPABILITY_UNIT_DIR = "/tmp/override"; }' \
	    'kmod_requires = ["bad/name"];' \
	    'jail = "named";' \
	    'jail { name = "bad/name"; path = "/j"; }' \
	    'jail { name = "good"; path = "relative"; }' \
	    'jail { name = "good"; path = "/j"; ip4_addr = "999.1.1.1"; }'; do
		i=$((i + 1))
		dir=$(make_bundle "bad-process-$i")
		printf '%s\n' 'activation { boot = true; }' "$declaration" > \
		    "$dir/Units/worker.unit/Unit.ucl"
		verify_bad 'restart|timeout|failures|arguments|environment|module|jail|invalid' "$dir"
	done
}
process_policy_matrix_cleanup() { cleanup_work; }

atf_test_case capability_contract cleanup
capability_contract_head() { atf_set descr "Every direct capability family survives parsing"; }
capability_contract_body()
{
	setup_work
	dir=$(make_bundle capabilities)
	cat > "$dir/Units/worker.unit/Unit.ucl" <<-'EOF'
	activation { boot = true; }
	capabilities {
	    paths = ["/var/empty", "/dev/null"];
	    files = [
	        { path = "/etc/ssl/cert.pem"; actions = ["read", "stat"]; },
	        { path = "/tmp/output"; actions = "write"; }
	    ];
	    network = [
	        { domain = "inet"; protocol = "tcp"; port = 443;
	          direction = "connect"; address = "192.0.2.0/24"; },
	        { domain = "inet6"; protocol = "udp"; ports = "53-54";
	          direction = "connect"; address = "2001:db8::"; prefix = 32; },
	        { domain = "bluetooth"; protocol = "l2cap";
	          direction = "connect"; address = "00:11:22:33:44:55"; }
	    ];
	    jails = [7, "named", { name = "managed"; actions = ["get", "attach"]; }];
	    vsock = [{ cid = 3; ports = "1024-2048"; direction = "connect"; }];
	    services = ["mount", "node", "accounting", "identity"];
	    system = ["kldload", "kldunload", "kldstat", "reboot",
	        "swapon", "swapoff", "sysctl", "kenv", "acct", "audit",
	        "kenv_read"];
	}
	EOF
	atf_check -s exit:0 \
	    -o match:'paths=2 files=2 network=3 jails=3 vsock=1 services=4' \
	    -o match:'network: domain=bluetooth protocol=l2cap' \
	    -o match:'vsock: cid=3 ports=1024-2048 direction=connect' \
	    servicetcl verify "$dir"
}
capability_contract_cleanup() { cleanup_work; }

atf_test_case capability_negative_matrix cleanup
capability_negative_matrix_head() { atf_set descr "Malformed capability entries fail independently"; }
capability_negative_matrix_body()
{
	setup_work
	i=0
	for declaration in \
	    'capabilities = [];' \
	    'capabilities { typo = []; }' \
	    'capabilities { paths = "/tmp"; }' \
	    'capabilities { paths = ["relative"]; }' \
	    'capabilities { paths = ["/x", "/x"]; }' \
	    'capabilities { files = [{ actions = "read"; }]; }' \
	    'capabilities { files = [{ path = "relative"; actions = "read"; }]; }' \
	    'capabilities { files = [{ path = "/x"; actions = []; }]; }' \
	    'capabilities { files = [{ path = "/x"; actions = "invent"; }]; }' \
	    'capabilities { services = ["unknown"]; }' \
	    'capabilities { services = ["mount", "mount"]; }' \
	    'capabilities { system = ["root"]; }' \
	    'capabilities { system = ["audit", "audit"]; }' \
	    'capabilities { jails = [0]; }' \
	    'capabilities { jails = [{}]; }' \
	    'capabilities { jails = [{ name = "x"; actions = "invent"; }]; }' \
	    'capabilities { vsock = [{ port = 4; ports = 5; }]; }' \
	    'capabilities { vsock = [{ cid = -1; }]; }' \
	    'capabilities { vsock = [{ direction = "listen"; }]; }'; do
		i=$((i + 1))
		dir=$(make_bundle "bad-capability-$i")
		printf '%s\n' 'activation { boot = true; }' "$declaration" > \
		    "$dir/Units/worker.unit/Unit.ucl"
		verify_bad 'capabilities|unknown|invalid|duplicate|array|jail|vsock' "$dir"
	done
}
capability_negative_matrix_cleanup() { cleanup_work; }

atf_test_case network_negative_matrix cleanup
network_negative_matrix_head() { atf_set descr "Network claim domain/address/protocol combinations fail closed"; }
network_negative_matrix_body()
{
	setup_work
	i=0
	for entry in \
	    '{ domain = "packet"; }' \
	    '{ protocol = "sctp"; }' \
	    '{ domain = "inet"; protocol = "l2cap"; }' \
	    '{ domain = "bluetooth"; protocol = "tcp"; }' \
	    '{ port = -1; }' '{ ports = "80-20"; }' \
	    '{ port = 80; ports = 80; }' \
	    '{ direction = "listen"; }' \
	    '{ domain = "inet"; address = "2001:db8::1"; }' \
	    '{ domain = "inet6"; address = "192.0.2.1"; }' \
	    '{ domain = "any"; address = "192.0.2.1"; }' \
	    '{ domain = "inet"; prefix = 24; }' \
	    '{ domain = "inet"; address = "192.0.2.1"; prefix = 64; }' \
	    '{ domain = "bluetooth"; address = "bad"; }' \
	    '{ domain = "bluetooth"; address = "00:11:22:33:44:55"; prefix = 24; }'; do
		i=$((i + 1))
		dir=$(make_bundle "bad-network-$i")
		printf '%s\n' 'activation { boot = true; }' \
		    "capabilities { network = [$entry]; }" > \
		    "$dir/Units/worker.unit/Unit.ucl"
		verify_bad 'network|domain|protocol|port|direction|address|prefix|malformed' "$dir"
	done
}
network_negative_matrix_cleanup() { cleanup_work; }

atf_test_case tree_limits cleanup
tree_limits_head() { atf_set descr "Bundle resource trees have bounded size and entry counts"; }
tree_limits_body()
{
	setup_work
	dir=$(make_bundle oversized)
	mkdir -p "$dir/Shared"
	truncate -s 536870913 "$dir/Shared/oversized"
	verify_bad 'size exceeds limit' "$dir"
	rm "$dir/Shared/oversized"
	i=0
	while [ "$i" -lt 4100 ]; do
		: > "$dir/Shared/entry-$i"
		i=$((i + 1))
	done
	verify_bad 'exceeds.*tree entries' "$dir"
}
tree_limits_cleanup() { cleanup_work; }

atf_init_test_cases()
{
	atf_add_test_case valid_contract
	atf_add_test_case protect_policy
	atf_add_test_case activation_matrix
	atf_add_test_case bundle_required_matrix
	atf_add_test_case bundle_value_matrix
	atf_add_test_case unit_name_matrix
	atf_add_test_case exact_inventory
	atf_add_test_case clean_break_rejections
	atf_add_test_case program_matrix
	atf_add_test_case parser_hardening
	atf_add_test_case multi_unit_order
	atf_add_test_case storage_contract
	atf_add_test_case storage_negative_matrix
	atf_add_test_case process_policy_matrix
	atf_add_test_case capability_contract
	atf_add_test_case capability_negative_matrix
	atf_add_test_case network_negative_matrix
	atf_add_test_case tree_limits
}
