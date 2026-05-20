#!/bin/sh
# Custom merge driver: keep our version, but warn when upstream changed the file.
# Args from git: %O (ancestor) %A (ours) %B (theirs)
ANCESTOR="$1"
OURS="$2"
THEIRS="$3"

if ! cmp -s "$ANCESTOR" "$THEIRS"; then
    echo "MACF: upstream changed $(basename "$4" 2>/dev/null || echo "file") — review with: git diff MERGE_HEAD -- <path>" >&2
fi

# Keep ours
exit 0
