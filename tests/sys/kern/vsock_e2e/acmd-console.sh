#!/bin/sh
# Run one command through an Alpine serial console and return its exit status.
set -u

command=${1:?guest command required}
limit=${2:-30}
log=${CONSOLE_LOG:?set CONSOLE_LOG}
input=${CONSOLE_INPUT:?set CONSOLE_INPUT}

size=$(wc -c < "$log" 2>/dev/null) || size=0
# FreeBSD wc right-aligns the count.  Normalize it before using it in an
# unquoted shell token sent to the guest console.
size=$((size + 0))
nonce="${size}_$$_$(date +%s)"
begin="__VSOCK_BEGIN_${nonce}__"
end="__VSOCK_END_${nonce}__"
offset=$((size + 1))

printf 'printf "\\n%%s\\n" %s; ( %s ); r=$?; printf "\\n%%s:%%s\\n" %s "$r"\r' \
    "$begin" "$command" "$end" >> "$input"

i=0
while [ "$i" -lt "$limit" ]; do
	chunk=$(tail -c +"$offset" "$log" 2>/dev/null | tr -d '\r')
	status=$(printf '%s\n' "$chunk" | sed -n "s/^${end}:\([0-9][0-9]*\)$/\1/p" | tail -1)
	[ -n "$status" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "${status:-}" ]; then
	echo "guest console command timed out after ${limit}s" >&2
	return 124 2>/dev/null || exit 124
fi

printf '%s\n' "$chunk" | awk -v b="$begin" -v e="$end" '
	$0 == b { capture = 1; next }
	index($0, e ":") == 1 { capture = 0; exit }
	capture { print }
'
exit "$status"
