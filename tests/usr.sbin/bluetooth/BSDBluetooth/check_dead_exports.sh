#!/bin/sh
#
# Dead-export gate for the Bluetooth stack.
#
# A census of the mesh stack found hundreds of exported symbols that no
# production translation unit references, including mandatory procedures that
# were implemented, unit-tested, passing, and never executed by the daemon.
# A green test suite cannot detect that by construction: the tests call the
# functions directly, which is exactly why they passed.  This gate closes that
# hole mechanically.
#
# Method.  nm(1) and readelf(1) are run over the built objects of the
# production daemons and libraries.  Object relocations are used, not a source
# grep: function-pointer and dispatch-table references are invisible to grep,
# and the model opcode tables hold static handlers, so a grep-based answer
# would be different and wrong.  An export counts as referenced when a
# production translation unit OTHER than its definer names it.  Nothing under
# tests/ is scanned, because a test calling a function directly is precisely
# what hides the problem.
#
# Every export is placed in one of three classes:
#
#	referenced	named by another production unit		(fine)
#	file-local	named only inside its own defining unit		(should
#			be static, not exported)
#	unreferenced	named by no production unit at all		(dead)
#
# The last two classes are seeded into spec_dead_exports.tsv, a SHRINKING
# allowlist.  The gate fails when a symbol falls into them and is not listed,
# and fails when a listed symbol has become referenced and the list was not
# updated -- so the list cannot silently rot upward.
#
# Usage: check_dead_exports.sh [-q] [--generate] [objroot]
#
# The objroot defaults to the build objdir for this source tree.  When the
# built objects, nm(1) or readelf(1) are absent the script exits 66
# (EX_NOINPUT) without an opinion, exactly like the other conformance gates in
# this directory, so a source-less or unbuilt checkout still gets an honest
# run instead of a spurious failure.
#
# --generate rewrites the allowlist on stdout, preserving the review category
# of every symbol already listed:
#
#	./check_dead_exports.sh --generate > spec_dead_exports.tsv

set -eu

quiet=false
generate=false
while [ "$#" -gt 0 ]; do
	case "$1" in
	-q)		quiet=true; shift ;;
	--generate)	generate=true; shift ;;
	-*)		echo "usage: $0 [-q] [--generate] [objroot]" >&2
			exit 64 ;;
	*)		break ;;
	esac
done
if [ "$#" -gt 1 ]; then
	echo "usage: $0 [-q] [--generate] [objroot]" >&2
	exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
allowlist="$script_dir/spec_dead_exports.tsv"

# Production units only.  tests/ is deliberately absent from this list.
UNIT_DIRS="lib/libmesh lib/libble usr.sbin/bluetooth/BSDBluetooth \
    usr.sbin/bluetooth/meshd usr.sbin/bluetooth/bluedctl \
    usr.sbin/bluetooth/meshctl"

# Locate the build objects.  In an installed tests package none of this
# resolves, and the gate skips.
srctop=$(CDPATH= cd -- "$script_dir/../../../.." 2>/dev/null && pwd || echo "")
if [ "$#" -eq 1 ]; then
	objroot=$1
elif [ -n "${BLUED_DEAD_EXPORT_OBJROOT-}" ]; then
	objroot=$BLUED_DEAD_EXPORT_OBJROOT
elif [ -n "$srctop" ]; then
	machine=$(uname -m)
	arch=$(sysctl -n hw.machine_arch 2>/dev/null || uname -p)
	if [ -n "${MAKEOBJDIRPREFIX-}" ]; then
		objroot="${MAKEOBJDIRPREFIX}${srctop}/${machine}.${arch}"
	else
		objroot="/usr/obj${srctop}/${machine}.${arch}"
	fi
else
	objroot=""
fi

skip() {
	$quiet || echo "dead-exports: $1; gate skipped"
	exit 66
}

command -v nm >/dev/null 2>&1 || skip "nm(1) unavailable"
command -v readelf >/dev/null 2>&1 || skip "readelf(1) unavailable"
[ -n "$objroot" ] && [ -d "$objroot" ] || skip "build objects absent ($objroot)"

# One object per translation unit.  Libraries build both .o and .pico from the
# same source; either carries the same symbol and relocation information, so
# take exactly one and never double-count a unit.
objs=""
units=0
for d in $UNIT_DIRS; do
	dir="$objroot/$d"
	[ -d "$dir" ] || continue
	stems=$(ls "$dir" 2>/dev/null | grep -E '\.(pieo|pico|o)$' |
	    sed -e 's/\.pieo$//' -e 's/\.pico$//' -e 's/\.o$//' | sort -u)
	for stem in $stems; do
		for ext in pieo pico o; do
			if [ -f "$dir/$stem.$ext" ]; then
				objs="$objs $dir/$stem.$ext"
				units=$((units + 1))
				break
			fi
		done
	done
done
[ "$units" -gt 0 ] || skip "no built objects under $objroot"

records=$(mktemp -t dead-exports.XXXXXX)
rows=$(mktemp -t dead-exports-rows.XXXXXX)
report=$(mktemp -t dead-exports-report.XXXXXX)
trap 'rm -f "$records" "$rows" "$report"' EXIT HUP INT TERM

for o in $objs; do
	unit=${o#$objroot/}
	unit=$(echo "$unit" | sed -e 's/\.pieo$/.c/' -e 's/\.pico$/.c/' \
	    -e 's/\.o$/.c/')
	# Exported definitions: text and data, global only.
	nm -g --defined-only "$o" 2>/dev/null |
	    awk -v u="$unit" '$2=="T"||$2=="D"||$2=="B"||$2=="R" \
		{print "DEF\t"$3"\t"u"\t"$2}'
	# Cross-unit references.
	nm -u "$o" 2>/dev/null | awk -v u="$unit" '{print "REF\t"$2"\t"u}'
	# Same-unit references, including function-pointer and dispatch-table
	# entries that a source grep cannot see.
	readelf -r "$o" 2>/dev/null |
	    awk -v u="$unit" 'NF>=5 && $1 ~ /^[0-9a-f]+$/ {
		if ($5 ~ /^[A-Za-z_][A-Za-z0-9_]*$/) print "REF\t"$5"\t"u }'
done >"$records"

# A missing allowlist is a first-run condition, not an error: every export is
# then reported as new.
seed=$allowlist
[ -f "$seed" ] || seed=/dev/null

set +e
awk -F'\t' \
    -v allowlist="$seed" -v generate="$generate" -v quiet="$quiet" \
    -v units="$units" -v rows="$rows" -v report="$report" '
# Fixed category vocabulary, in report order.  Categories say whether a row is
# a problem; see the generated allowlist header for what each one means.
BEGIN {
	ncats = split("dead-mandatory operator-surface-gap superseded " \
	    "over-exported client-role-api public-library-api " \
	    "simulator-api dead-by-design deliberately-dead unreviewed", \
	    cats, " ")
	# Categories that mean "something is wrong here", in report order.
	nprob = split("dead-mandatory operator-surface-gap superseded " \
	    "unreviewed", probs, " ")
	for (i = 1; i <= nprob; i++)
		is_problem[probs[i]] = 1
}
# A reviewer-recorded category always wins, so manual triage survives every
# regeneration.  Otherwise classify mechanically, defaulting to a problem.
function category(sym, unit,   base, dir, n, a) {
	if (sym in cat && cat[sym] != "")
		return cat[sym]
	n = split(unit, a, "/")
	base = a[n]
	dir = a[n - 1]
	if (base == "ble.c")
		return "public-library-api"
	if (base == "mesh_sim.c")
		return "simulator-api"
	if (sym ~ /_cli_/ || sym ~ /_cli$/)
		return "client-role-api"
	if (sym ~ /^mesh_mgr_cfg_.*_(parse|apply)$/)
		return "client-role-api"
	if (sym ~ /(_status_decode|_status_parse|_set_encode|_get_build)$/)
		return "client-role-api"
	if (dir == "libmesh" || dir == "meshd" || dir == "meshctl")
		return "dead-mandatory"
	# A file-local symbol has a caller; the only question is its linkage.
	# That is read straight off the census, so it is not a judgement call
	# and defaulting to it hides nothing.
	if (class[sym] == "file-local")
		return "over-exported"
	# Anything still dead and untriaged stays a presumed problem.
	return "unreviewed"
}
FILENAME == allowlist {
	if ($0 ~ /^#/ || NF == 0)
		next
	listed[$1] = 1
	lclass[$1] = $2
	cat[$1] = $4
	note[$1] = $5
	next
}
$1 == "DEF" {
	# main() is named by crt and every daemon defines one; leading
	# underscores belong to the runtime and the compiler.
	if ($2 == "main" || $2 ~ /^_/)
		next
	def[$2] = $3
	next
}
$1 == "REF" {
	# Distinct (symbol, referencing unit) pairs, counted once each, so the
	# classification below stays linear in the number of exports.
	if (!(($2 SUBSEP $3) in ref_unit)) {
		ref_unit[$2 SUBSEP $3] = 1
		nrefunits[$2]++
	}
	next
}
END {
	for (s in def) {
		self = ((s SUBSEP def[s]) in ref_unit)
		other = (nrefunits[s] - (self ? 1 : 0)) > 0
		if (other)
			cls = "referenced"
		else if (self)
			cls = "file-local"
		else
			cls = "unreferenced"
		class[s] = cls
		n_class[cls]++
		total++
	}

	if (generate == "true") {
		for (s in class) {
			if (class[s] == "referenced")
				continue
			c = category(s, def[s])
			gen_cat[c]++
			ngen++
			printf("%s\t%s\t%s\t%s\t%s\n", s, class[s], def[s], c,
			    (s in note && note[s] != "") ? note[s] : "-") \
			    >> rows
		}
		print "# Bluetooth stack dead-export allowlist."
		print "#"
		print "# Generated by check_dead_exports.sh, which also gates it.  Every row is"
		print "# an exported symbol that no OTHER production translation unit"
		print "# references.  References from anything under tests/ do not count: a"
		print "# test calling a function directly is exactly what hid this class of"
		print "# defect, so counting tests would defeat the gate."
		print "#"
		print "# THIS LIST IS EXPECTED TO SHRINK AND MUST NEVER GROW.  Wiring a dead"
		print "# procedure into the daemon makes its row fail as \"allowlisted symbol is"
		print "# now referenced\"; that failure is the intended signal, not an obstacle."
		print "# Resolve it by deleting the row, or regenerate the whole file:"
		print "#"
		print "#\tcd tests/usr.sbin/bluetooth/BSDBluetooth"
		print "#\t./check_dead_exports.sh --generate > spec_dead_exports.tsv"
		print "#"
		print "# Regeneration preserves the category and note of every symbol already"
		print "# listed, so review work is never lost."
		print "#"
		print "# Columns: symbol<TAB>class<TAB>unit<TAB>category<TAB>note"
		print "#"
		print "# class -- how the census sees the symbol"
		print "#   unreferenced  no production unit names it: dead code."
		print "#   file-local    named only inside its own defining unit; it is"
		print "#                 exported but should be static."
		print "#"
		print "# category -- whether the row is a PROBLEM, and if so which kind."
		print "# The distinction that matters is between a procedure that OUGHT to run"
		print "# and cannot, and surface that is dead because nothing in this product"
		print "# is supposed to call it.  The first four categories are problems."
		print "#"
		print "#   dead-mandatory       A PROBLEM, and the worst kind.  An implemented,"
		print "#                        unit-tested procedure that the specification"
		print "#                        -- or this daemon own documentation -- says"
		print "#                        shall run,"
		print "#                        with no production caller: it executes in no"
		print "#                        shipped code path however green its tests are."
		print "#                        Fix it by wiring it to a real caller -- never by"
		print "#                        inventing a caller no code path reaches, which"
		print "#                        converts a dead export into a lie and silences"
		print "#                        the only instrument that can see it."
		print "#   operator-surface-gap A PROBLEM, but not one a wiring change can fix."
		print "#                        The procedure is implemented and correct and"
		print "#                        there is no code path to it because no operator"
		print "#                        verb, config key or protocol field can ask for"
		print "#                        it.  The note must size the missing surface."
		print "#                        Often paired with a parser for a response we can"
		print "#                        never provoke -- look for that when triaging."
		print "#   superseded           A PROBLEM only in that it still exists.  A"
		print "#                        duplicate of a newer entry point that the daemon"
		print "#                        uses instead.  Delete it; the note names the"
		print "#                        replacement.  Several are also strictly weaker"
		print "#                        than what replaced them (missing locking or"
		print "#                        missing guards), so keeping them is a trap."
		print "#   unreviewed           PRESUMED A PROBLEM.  Seeded by the census and"
		print "#                        not yet triaged.  Reclassify, with a note, as"
		print "#                        review reaches it."
		print "#"
		print "#   over-exported        Not a problem, just wrong linkage.  The symbol"
		print "#                        HAS callers, all inside its own translation"
		print "#                        unit, so it should be static.  Derived from the"
		print "#                        file-local class, not from judgement.  Note that"
		print "#                        the unreferenced class OVER-REPORTS the reverse"
		print "#                        way: these daemons link as PIE, the assembler"
		print "#                        resolves an intra-unit call to a global function"
		print "#                        without emitting a relocation, and the readelf"
		print "#                        pass cannot see it.  So an unreferenced row may"
		print "#                        still have same-unit callers; check by grep"
		print "#                        before calling one dead."
		print "#   client-role-api      Not a problem.  Client-model entry point for a"
		print "#                        role this product does not implement; meshd"
		print "#                        only serves these models.  Kept as API."
		print "#   public-library-api   Not a problem.  Exported through the installed"
		print "#                        ble.h and libble.3; consumers are out of tree."
		print "#   simulator-api        Not a problem.  mesh_sim harness surface,"
		print "#                        driven by tests and tools, not by meshd."
		print "#   dead-by-design       Not a problem, but it must be argued per symbol"
		print "#                        in the note: \"it is an API\" is not a reason."
		print "#                        Unreachable because of what this product IS --"
		print "#                        a transport it does not carry, a spec procedure"
		print "#                        that does not exist, a controller test-mode"
		print "#                        command, an accessor whose contract is unsafe"
		print "#                        for every live caller."
		print "#   deliberately-dead    Not a problem: REMOVED ON PURPOSE, and wiring it"
		print "#                        back would reintroduce a defect.  The note must"
		print "#                        say which defect.  Annotate or delete; never"
		print "#                        wire."
		print "#"
		line = ""
		for (i = 1; i <= ncats; i++)
			if (gen_cat[cats[i]] > 0)
				line = line sprintf("%s%s %d",
				    line == "" ? "" : ", ", cats[i],
				    gen_cat[cats[i]])
		printf("# %d rows: %s\n", ngen, line)
		print "#"
		exit 0
	}

	fail = 0
	nnew = 0
	nfixed = 0
	ngone = 0
	nmoved = 0

	# 1. A dead export that nobody signed off on: the regression this gate
	#    exists to catch.
	for (s in class) {
		if (class[s] == "referenced" || (s in listed))
			continue
		printf("dead-exports: NEW dead export: %s (%s, %s)\n", s,
		    class[s], def[s]) >> report
		nnew++
		fail = 1
	}
	# 2. An allowlisted symbol that has been wired up.  Failing here is
	#    what keeps the list shrinking instead of rotting upward.
	for (s in listed) {
		if (!(s in class) || class[s] != "referenced")
			continue
		printf("dead-exports: allowlisted symbol is now referenced: " \
		    "%s\n", s) >> report
		nfixed++
		fail = 1
	}
	# 3. Housekeeping.  Reported, never fatal: the symbol is no longer
	#    dead in the way its row claims.
	for (s in listed) {
		if (!(s in class)) {
			ngone++
			continue
		}
		if (class[s] != "referenced" && class[s] != lclass[s])
			nmoved++
		if (class[s] != "referenced")
			live_cat[cat[s]]++
	}

	if (quiet != "true") {
		printf("dead-exports: %d production translation units, " \
		    "%d exported symbols\n", units, total)
		printf("dead-exports:   referenced by another unit:   %5d\n",
		    n_class["referenced"] + 0)
		printf("dead-exports:   file-local (should be static):%5d\n",
		    n_class["file-local"] + 0)
		printf("dead-exports:   no production reference:      %5d\n",
		    n_class["unreferenced"] + 0)
	}
	line = ""
	for (i = 1; i <= ncats; i++)
		if (live_cat[cats[i]] > 0)
			line = line sprintf("%s%s %d",
			    line == "" ? "" : ", ", cats[i],
			    live_cat[cats[i]])
	printf("dead-exports: allowlist: %d of %d entries still dead (%s)%s%s\n",
	    n_class["file-local"] + n_class["unreferenced"] - nnew,
	    n_listed(), line,
	    ngone ? sprintf("; %d gone, prune them", ngone) : "",
	    nmoved ? sprintf("; %d changed class", nmoved) : "")
	# The headline number: how much of the allowlist is still something
	# someone has to fix, as opposed to surface that is dead on purpose.
	if (quiet != "true") {
		nproblem = 0
		nbenign = 0
		for (i = 1; i <= ncats; i++) {
			if (live_cat[cats[i]] == 0)
				continue
			if (is_problem[cats[i]])
				nproblem += live_cat[cats[i]]
			else
				nbenign += live_cat[cats[i]]
		}
		printf("dead-exports:   still to fix:                 %5d\n",
		    nproblem)
		printf("dead-exports:   dead on purpose:              %5d\n",
		    nbenign)
	}

	if (nnew)
		printf("dead-exports: %d export(s) are dead and not " \
		    "allowlisted.  Wire them into the daemon, make them " \
		    "static, or -- only with a recorded reason -- add them " \
		    "to spec_dead_exports.tsv.\n", nnew) >> report
	if (nfixed)
		printf("dead-exports: %d allowlisted export(s) are now " \
		    "referenced.  Regenerate the allowlist so it shrinks: " \
		    "./check_dead_exports.sh --generate > " \
		    "spec_dead_exports.tsv\n", nfixed) >> report
	exit (fail ? 1 : 0)
}
function n_listed(   s, n) {
	n = 0
	for (s in listed)
		n++
	return (n)
}
' "$seed" "$records"
status=$?
set -e

if [ -s "$rows" ]; then
	sort "$rows"
fi
if [ -s "$report" ]; then
	cat "$report" >&2
fi
exit $status
