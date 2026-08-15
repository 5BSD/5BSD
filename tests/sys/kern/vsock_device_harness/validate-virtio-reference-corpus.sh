#!/bin/sh
#
# Validate the immutable reference metadata without downloading or importing
# external source code.  If an artifact directory is supplied, require one
# authenticated regular file for every catalog row and no extra artifacts.
#

set -eu

catalog=${1:?usage: validate-virtio-reference-corpus.sh catalog [--waspnest] [artifact-dir]}
shift
require_waspnest=0
if [ "${1-}" = "--waspnest" ]; then
	require_waspnest=1
	shift
fi
artifact_dir=${1-}
[ "$#" -le 1 ] || {
	echo "usage: validate-virtio-reference-corpus.sh catalog [--waspnest] [artifact-dir]" >&2
	exit 2
}

awk -F '	' -v require_waspnest="$require_waspnest" '
NR == 1 {
	if ($0 != "reference_id	authority	title	revision	publication_date	url	sha256	applicable_sections	classification") {
		print "invalid reference corpus header" >"/dev/stderr"
		exit 1
	}
	next
}
NF != 9 {
	printf "line %d: expected 9 fields, found %d\n", NR, NF >"/dev/stderr"
	bad = 1
	next
}
$1 !~ /^[A-Z0-9][A-Z0-9.-]*$/ {
	printf "line %d: invalid reference id\n", NR >"/dev/stderr"
	bad = 1
}
seen[$1]++ {
	printf "line %d: duplicate reference id %s\n", NR, $1 >"/dev/stderr"
	bad = 1
}
seen_digest[$7]++ {
	printf "line %d: duplicate SHA-256 %s\n", NR, $7 >"/dev/stderr"
	bad = 1
}
$5 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ {
	printf "line %d: invalid publication date\n", NR >"/dev/stderr"
	bad = 1
}
$6 !~ /^https:\/\// {
	printf "line %d: reference URL is not HTTPS\n", NR >"/dev/stderr"
	bad = 1
}
$1 == "VIRTIO-1.4-CS01" && $6 !~ /\/virtio-v1[.]4-cs01[.]pdf$/ {
	printf "line %d: VirtIO CS01 must pin the reproducible official PDF\n",
	    NR >"/dev/stderr"
	bad = 1
}
$7 !~ /^[0-9a-f]{64}$/ {
	printf "line %d: invalid SHA-256\n", NR >"/dev/stderr"
	bad = 1
}
$9 != "normative" && $9 != "explanatory" {
	printf "line %d: invalid classification\n", NR >"/dev/stderr"
	bad = 1
}
{
	classification[$1] = $9
}
END {
	if (NR < 2) {
		print "empty reference corpus" >"/dev/stderr"
		bad = 1
	}
	if (require_waspnest &&
	    (classification["VIRTIO-1.4-CS01"] != "normative" ||
	    classification["INTEL-SDM-3-092"] != "normative" ||
	    classification["INTEL-SDM-4-092"] != "normative" ||
	    classification["LINUX-7.2-RC4"] != "explanatory" ||
	    classification["QEMU-300438"] != "explanatory")) {
		print "WASPNest corpus is missing a required pinned reference or classification" >"/dev/stderr"
		bad = 1
	}
	exit bad
}
' "$catalog"

if [ -n "$artifact_dir" ]; then
	[ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] || {
		echo "reference artifact directory is invalid: $artifact_dir" >&2
		exit 1
	}
	manifest=$(mktemp /tmp/virtio-reference-manifest.XXXXXX)
	entries=$(mktemp /tmp/virtio-reference-entries.XXXXXX)
	trap 'rm -f "$manifest" "$entries"' EXIT HUP INT TERM
	# Do not silently ignore anything in an operator-supplied corpus.  A
	# directory, symbolic link, or special file would otherwise make the
	# advertised "no extra artifacts" contract inaccurate.  The explicit
	# listing also preserves find(1)'s failure status instead of losing it in a
	# producer/consumer pipeline.
	find "$artifact_dir" -maxdepth 1 -mindepth 1 -print >"$entries"
	tab=$(printf '\t')
	while IFS= read -r artifact; do
		case "$artifact" in
		*"$tab"*)
			echo "reference artifact path contains a tab: $artifact" >&2
			exit 1
			;;
		esac
		if [ -L "$artifact" ] || [ ! -f "$artifact" ]; then
			echo "reference artifact is not a regular non-symbolic file: $artifact" >&2
			exit 1
		fi
		# Do not let a failed command substitution become a successful printf.
		# The manifest is an authentication boundary, so both digest production
		# and its expected fixed-width representation must succeed explicitly.
		digest=$(sha256 -q "$artifact") || {
			echo "cannot hash reference artifact: $artifact" >&2
			exit 1
		}
		case "$digest" in
		????????????????????????????????????????????????????????????????)
			case "$digest" in
			*[!0-9a-f]*)
				echo "invalid reference artifact digest: $artifact" >&2
				exit 1
				;;
			esac
			;;
		*)
			echo "invalid reference artifact digest: $artifact" >&2
			exit 1
			;;
		esac
		printf '%s\t%s\n' "$digest" "$artifact"
	done <"$entries" >"$manifest"
	awk -F '	' '
	NR == FNR {
		if (FNR > 1)
			wanted[$7] = $1
		next
	}
	{
		seen[$1]++
		if (!($1 in wanted)) {
			printf "unrecognized reference artifact: %s\n", $2 \
			    >"/dev/stderr"
			bad = 1
		}
	}
	END {
		for (digest in wanted) {
			if (seen[digest] == 0) {
				printf "missing reference artifact: %s\n", \
				    wanted[digest] >"/dev/stderr"
				bad = 1
			} else if (seen[digest] != 1) {
				printf "duplicate reference artifact: %s\n", \
				    wanted[digest] >"/dev/stderr"
				bad = 1
			}
		}
		exit bad
	}
	' "$catalog" "$manifest"
fi

echo "reference corpus entries validated"
