#!/bin/sh
# Run one command through a guest serial console and return its exit status.
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

started=$(date +%s)
status=
chunk=

wait_for_marker()
{
	marker=$1
	while :; do
		chunk=$(tail -c +"$offset" "$log" 2>/dev/null | tr -d '\r')
		printf '%s\n' "$chunk" | grep -F -x -q "$marker" && return 0
		now=$(date +%s)
		[ $((now - started)) -lt "$limit" ] || return 1
		sleep 0.1
	done
}

# 5BSD advertises MAX_CANON and MAX_INPUT as 255 bytes.  Keep short commands
# on the fast path only when the complete wrapped line is safely below that
# boundary.  Stage longer commands in acknowledged base64 chunks.  Waiting
# for every acknowledgement also prevents the serial input queue from being
# overrun when a large command is transferred.
direct=$(printf 'printf "\\n%%s\\n" %s; ( %s ); r=$?; printf "\\n%%s:%%s\\n" %s "$r"\r' \
    "$begin" "$command" "$end")
direct_size=$(printf %s "$direct" | wc -c)
direct_size=$((direct_size + 0))
if [ "$direct_size" -le 240 ]; then
	printf %s "$direct" >> "$input"
else
	guest_base="/tmp/.vc$$"
	encoded=$(printf %s "$command" | base64 | tr -d '\n')
	chunks=$(mktemp "${TMPDIR:-/tmp}/acmd-console.XXXXXX") || exit 1
	trap 'rm -f "$chunks"' EXIT HUP INT TERM
	printf '%s\n' "$encoded" | fold -w 96 > "$chunks"
	sequence=0
	while IFS= read -r encoded_chunk; do
		sequence=$((sequence + 1))
		ack="__VSOCK_ACK_${nonce}_${sequence}__"
		if [ "$sequence" -eq 1 ]; then
			printf ': > %s.b; printf %%s %s >> %s.b; printf "\\n%%s\\n" %s\r' \
			    "$guest_base" "$encoded_chunk" "$guest_base" "$ack" >> "$input"
		else
			printf 'printf %%s %s >> %s.b; printf "\\n%%s\\n" %s\r' \
			    "$encoded_chunk" "$guest_base" "$ack" >> "$input"
		fi
		if ! wait_for_marker "$ack"; then
			echo "guest console command timed out after ${limit}s" >&2
			exit 124
		fi
	done < "$chunks"
	rm -f "$chunks"
	trap - EXIT HUP INT TERM
	decode="__VSOCK_DECODE_${nonce}__"
	printf 'base64 -d %s.b > %s; d=$?; rm -f %s.b; printf "\\n%%s:%%s\\n" %s "$d"\r' \
	    "$guest_base" "$guest_base" "$guest_base" "$decode" >> "$input"
	if ! wait_for_marker "$decode:0"; then
		echo "guest console command timed out after ${limit}s" >&2
		exit 124
	fi
	printf 'printf "\\n%%s\\n" %s; ( sh %s ); r=$?; rm -f %s; printf "\\n%%s:%%s\\n" %s "$r"\r' \
	    "$begin" "$guest_base" "$guest_base" "$end" >> "$input"
fi

while :; do
	chunk=$(tail -c +"$offset" "$log" 2>/dev/null | tr -d '\r')
	status=$(printf '%s\n' "$chunk" | sed -n "s/^${end}:\([0-9][0-9]*\)$/\1/p" | tail -1)
	[ -n "$status" ] && break
	now=$(date +%s)
	[ $((now - started)) -lt "$limit" ] || break
	sleep 0.1
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
