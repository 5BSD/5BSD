#!/bin/sh

set -eu
if [ "$#" -ne 2 ]; then
	echo "usage: $0 Core_Specification_6_3.txt Assigned_Numbers.html" >&2
	exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
generated="$script_dir/spec_core63_generated.h"
candidate=$(mktemp -t core63-oracles.XXXXXX)
assigned_candidate=$(mktemp -t assigned-oracles.XXXXXX)
trap 'rm -f "$candidate" "$assigned_candidate"' EXIT HUP INT TERM

awk -f "$script_dir/generate_core63_oracles.awk" "$1" >"$candidate"
if ! cmp -s "$candidate" "$generated"; then
	echo 'generated Core 6.3 oracle header is stale; regenerate it' >&2
	diff -u "$generated" "$candidate" >&2 || true
	exit 1
fi

awk -f "$script_dir/generate_assigned_oracles.awk" "$2" >"$assigned_candidate"
if ! cmp -s "$assigned_candidate" "$script_dir/spec_assigned_generated.h"; then
	echo 'generated Assigned Numbers oracle header is stale; regenerate it' >&2
	diff -u "$script_dir/spec_assigned_generated.h" "$assigned_candidate" >&2 || true
	exit 1
fi
