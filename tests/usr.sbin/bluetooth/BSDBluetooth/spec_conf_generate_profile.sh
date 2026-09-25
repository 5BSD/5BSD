#!/bin/sh
#
# Regenerate the profile/supplement conformance catalogues from the Bluetooth
# SIG profile specification texts.  This is the companion of
# spec_conf_generate.sh, which covers the Core Specification only.
#
# The output is a pure function of:
#
#   * bluetooth-specs/MshPRT_v1.1.1.txt     (Mesh Protocol 1.1.1)
#   * bluetooth-specs/MshMDL_v1.1.1.txt     (Mesh Model 1.1.1)
#   * bluetooth-specs/CSS_v15.txt           (Core Specification Supplement v15)
#   * bluetooth-specs/HOGP_v1.1.txt         (HID Over GATT Profile 1.1)
#   * bluetooth-specs/HIDS_v1.1.txt         (HID Service 1.1)
#   * spec_conf_extract_profile_requirements.awk  (scope + sentence rules)
#   * spec_conf_coverage_profile.awk              (attribution rules)
#   * spec_conf_css_adscope.awk                   (CSS Part A scope derived
#                                                  from blued's AD types)
#   * bluetooth-specs/Assigned_Numbers.html       (AD type -> CSS section)
#   * the AD_TYPE_* values defined by blued, libble and libmesh
#   * spec_conf_rank_profile.awk                  (risk weighting)
#   * the traceability matrix (spec_requirements.tsv)
#
# so drift in any of them is visible as a diff, exactly like
# spec_conf_generate.sh and check_generated_oracles.sh.
#
# Usage:
#   spec_conf_generate_profile.sh              regenerate in place
#   spec_conf_generate_profile.sh --check      fail if checked-in files are stale

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src_root=$(CDPATH= cd -- "$script_dir/../../../.." && pwd)
specs="$src_root/bluetooth-specs"

mode=generate
while [ "$#" -gt 0 ]; do
	case "$1" in
	--check) mode=check; shift ;;
	-h|--help) sed -n '2,25p' "$0"; exit 0 ;;
	*) echo "usage: $0 [--check]" >&2; exit 64 ;;
	esac
done

req_out="$script_dir/spec_conf_profile_requirements_generated.tsv"
cov_out="$script_dir/spec_conf_profile_coverage_generated.tsv"
rank_out="$script_dir/spec_conf_profile_gaps_ranked.tsv"

# Scope statements.  Each is a reviewable claim about which chapters of a
# document this stack is responsible for; chapters are excluded only where the
# document describes a role the stack does not implement.
#
#   Mesh Protocol 1.1.1  3-7  networking, foundation models, provisioning,
#                             proxy, mesh GATT services.  1-2 are introduction
#                             and architecture, 8 is sample data (consumed as
#                             oracles, not as requirements), 9-10 are the
#                             acronym list and the bibliography.
#   Mesh Model 1.1.1     2-6  device properties, generics, sensors, time and
#                             scenes, lighting - every model family present in
#                             lib/libmesh.  1 is introduction, 7-9 are summary,
#                             acronyms and bibliography.
#   CSS v15         Parts A,B data types (advertising data) and the common
#                             profile/service error codes.  Part C is the
#                             BR/EDR Security Mode 4 Level 0 service list, and
#                             blued exposes no BR/EDR service-access layer.
#                             Part A is narrowed further, to the sections
#                             reached from the AD types blued emits and parses;
#                             see spec_conf_css_adscope.awk.
#   HOGP 1.1             2-7  configuration, HID Device requirements, HID Host
#                             requirements, HID ISO, HID ISO Service, security.
#                             HID Device and HID ISO requirements are retained
#                             in scope and classified NOT-APPLICABLE by
#                             spec_conf_coverage_profile.awk, so the roles this
#                             stack declines stay visible instead of vanishing.
#   HIDS 1.1             2-3  service requirements and the SCI feature.
#
# Fields: tag | text file | document name | page-header regex | parted |
#         section scope | part scope
docs='
MSHPRT111|MshPRT_v1.1.1.txt|Mesh Protocol 1.1.1|Mesh Protocol / Specification|0|3,4,5,6,7|
MSHMDL111|MshMDL_v1.1.1.txt|Mesh Model 1.1.1|Mesh Model / Specification|0|2,3,4,5,6|
CSS15|CSS_v15.txt|Supplement to the Bluetooth Core Specification v15|SUPPLEMENT TO THE BLUETOOTH CORE SPECIFICATION|1||V1PA,V1PB
HOGP11|HOGP_v1.1.txt|HID Over GATT Profile 1.1|HID Over GATT Profile / Profile Specification|0|2,3,4,5,6,7|
HIDS11|HIDS_v1.1.txt|HID Service 1.1|HID Service Specification / Service Specification|0|2,3|
'

missing=$(printf '%s\n' "$docs" | while IFS='|' read -r tag f rest; do
	[ -n "$f" ] || continue
	[ -f "$specs/$f" ] || printf ' %s' "$f"
done)
if [ -n "$missing" ]; then
	echo "spec_conf_profile: specification text absent:$missing" >&2
	echo 'spec_conf_profile: SIG source documents are local review inputs' >&2
	echo 'spec_conf_profile: and are not redistributed; regeneration skipped.' >&2
	exit 66
fi

tmpdir=$(mktemp -d -t bluetooth-specconf-profile.XXXXXX)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

# 0. Narrow CSS Part A to the advertising data types this stack actually uses.
#    The AD type values come from the sources, the value-to-section mapping
#    from Assigned Numbers, so neither end of it is hand-maintained.
grep -rhoE '#define[[:space:]]+AD_TYPE_[A-Z0-9_]+[[:space:]]+0x[0-9A-Fa-f]+' \
    "$src_root/usr.sbin/bluetooth/BSDBluetooth" "$src_root/lib/libble" \
    "$src_root/lib/libmesh" "$src_root/usr.sbin/bluetooth/meshd" 2>/dev/null |
    grep -oE '0x[0-9A-Fa-f]+$' | tr 'abcdef' 'ABCDEF' | sed 's/^0X/0x/' |
    LC_ALL=C sort -u >"$tmpdir/adtypes"
if [ ! -s "$tmpdir/adtypes" ]; then
	echo 'spec_conf_profile: no AD_TYPE_* values found in the sources' >&2
	exit 1
fi
adscope=$(awk -v ADTYPES="$tmpdir/adtypes" \
    -f "$script_dir/spec_conf_css_adscope.awk" \
    "$specs/Assigned_Numbers.html" 2>"$tmpdir/adscope.err")
if [ -z "$adscope" ]; then
	echo 'spec_conf_profile: CSS Part A scope derivation produced nothing' >&2
	cat "$tmpdir/adscope.err" >&2
	exit 1
fi

# 1. Extract the normative sentences of every in-scope document.
{
	printf '# Generated by spec_conf_generate_profile.sh; do not edit.\n'
	printf '# Sources: Mesh Protocol 1.1.1, Mesh Model 1.1.1, Core\n'
	printf '# Specification Supplement v15, HID Over GATT Profile 1.1,\n'
	printf '# HID Service 1.1 (see bluetooth-specs/README.md).\n'
	printf 'requirement_id\tvolume_part\tsection\tkeyword\ttext\n'
	printf '%s\n' "$docs" |
	while IFS='|' read -r tag f name head parted secs parts; do
		[ -n "$tag" ] || continue
		awk -v DOC="$tag" -v DOCNAME="$name" -v HEADRE="$head" \
		    -v PARTED="$parted" -v SECTIONS="$secs" -v PARTS="$parts" \
		    -f "$script_dir/spec_conf_extract_profile_requirements.awk" \
		    "$specs/$f"
	done
} >"$tmpdir/out"

# 2. Classify coverage against the existing traceability matrix.
matrix="$script_dir/spec_requirements.tsv"
[ -f "$script_dir/spec_conf_requirements_proposed.tsv" ] &&
    matrix="$script_dir/spec_conf_requirements_proposed.tsv"
awk -v MATRIX="$matrix" -v ADSCOPE="$adscope" \
    -f "$script_dir/spec_conf_coverage_profile.awk" \
    "$tmpdir/out" >"$tmpdir/cov"

# 3. Rank what is left.
awk -v REQS="$tmpdir/out" -f "$script_dir/spec_conf_rank_profile.awk" \
    "$tmpdir/cov" |
    { read -r hdr; printf '%s\n' "$hdr"; sort -t "$(printf '\t')" -k1,1nr \
	-k2,2; } >"$tmpdir/rank"

# 4. Emit or compare.
if [ "$mode" = check ]; then
	rc=0
	for pair in "$tmpdir/out:$req_out" "$tmpdir/cov:$cov_out" \
	    "$tmpdir/rank:$rank_out"; do
		cand=${pair%%:*}
		have=${pair#*:}
		if [ ! -f "$have" ]; then
			echo "spec_conf_profile: $have is missing; run $0" >&2
			rc=1
			continue
		fi
		if ! cmp -s "$cand" "$have"; then
			echo "spec_conf_profile: $have is stale; regenerate it" >&2
			diff -u "$have" "$cand" >&2 || true
			rc=1
		fi
	done
	[ "$rc" -eq 0 ] &&
	    echo 'spec_conf_profile: generated catalogues are current'
	exit "$rc"
fi

cat "$tmpdir/out" >"$req_out"
cat "$tmpdir/cov" >"$cov_out"
cat "$tmpdir/rank" >"$rank_out"

printf 'spec_conf_profile: wrote %s normative requirements to %s\n' \
    "$(grep -vc '^#\|^requirement_id' "$req_out")" "$req_out"
awk -F'\t' 'NR > 1 { n[$4]++ } END { for (s in n) printf \
    "spec_conf_profile: %-15s %d\n", s, n[s] }' "$cov_out"
awk -F'\t' 'NR > 1 { doc = $1; sub(/-.*$/, "", doc); n[doc "\t" $4]++ }
    END { for (k in n) printf "spec_conf_profile: %-30s %d\n", k, n[k] }' \
    "$cov_out" | sort

# The Supplement is cited in the matrix by a version older than the in-tree
# normative text.  Coverage matches by document family, so those citations are
# still attributed; report the skew rather than hiding it.
cat "$tmpdir/adscope.err" >&2
skew=$(grep -c 'CSS v12' "$matrix" || :)
[ "$skew" -gt 0 ] && printf \
    'spec_conf_profile: %s matrix rows cite "CSS v12"; in-tree text is v15\n' \
    "$skew"
exit 0
