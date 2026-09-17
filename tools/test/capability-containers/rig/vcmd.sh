#!/bin/sh
# vcmd.sh "<command>" [timeout_s] — run a command on the guest serial
# console and print exactly its stdout.
#
# Robust framing: the command is wrapped so the guest emits unique
# BEGIN/END sentinels around the real output.  We extract strictly
# between them, so a cluttered console (job-control notices, races with
# a previous background command, partial prompts) cannot corrupt the
# result the way prompt-sniffing did.  A per-call nonce keeps concurrent
# or back-to-back calls from matching each other's markers.
#
# Long-command safety.  The guest console tty is canonical (line-edited)
# and imposes TWO independent limits that both silently drop input and
# strand the shell at a "> " continuation prompt (a false "hang"):
#
#   1. Per line: a single line longer than MAX_CANON (~255 bytes) loses
#      its overflow characters.
#   2. Per burst: feeding many lines back-to-back faster than the
#      interactive shell drains them overflows the tty input queue, so
#      later lines are truncated even when each is individually short.
#
# Neither is a bhyve bug — the fork's uart backend back-pressures the
# 16-byte RX FIFO correctly (excess bytes wait in the socket); this is
# standard Unix serial-console behavior.  So a long command is (a)
# streamed base64-encoded in short chunks to beat limit 1, and (b) PACED
# with a short delay between lines so the shell drains each before the
# next arrives, beating limit 2.  Callers never hand-stage a script.
FEED_PACE=${VCMD_PACE:-0.4}
LOG=$HOME/vm/console.log
BUF=$HOME/vm/console.in.buf
TMO=${2:-20}
CMD=$1

nonce=$(( $(wc -c < "$LOG" 2>/dev/null || echo 0) ))
nonce="${nonce}_$$"
B="__VB_${nonce}_B__"
E="__VB_${nonce}_E__"

off=$(wc -c < "$LOG" 2>/dev/null || echo 0)

# Budget: the wrapped single line is 'printf "\n%s\n"; { CMD; }; printf
# "\n%s\n"\r' — CMD plus ~40 chars of framing plus two markers.  Keep the
# whole line comfortably under MAX_CANON.
wrapped_len=$(( ${#CMD} + ${#B} + ${#E} + 40 ))
if [ "$wrapped_len" -lt 200 ]; then
	printf 'printf "\\n%s\\n"; { %s; }; printf "\\n%s\\n"\r' \
	    "$B" "$CMD" "$E" >> "$BUF"
else
	f="/tmp/.vcmd_${nonce}"
	# Clear the guest staging file (short line), paced.
	printf ': > %s\r' "$f" >> "$BUF"
	sleep "$FEED_PACE"
	# Append the base64 of CMD in <=100-char chunks.  base64 output is
	# [A-Za-z0-9+/=] only, so single-quoting each chunk is always safe;
	# each emitted printf line stays well under MAX_CANON, and a pause
	# after each lets the shell consume it before the next is sent.
	printf '%s' "$CMD" | base64 -w0 2>/dev/null | fold -w 100 | \
	while IFS= read -r chunk || [ -n "$chunk" ]; do
		printf "printf '%%s' '%s' >> %s\r" "$chunk" "$f" >> "$BUF"
		sleep "$FEED_PACE"
	done
	# Decode, run, and clean up in a single line wrapped by the
	# sentinels.  Folding the rm into this line (rather than a trailing
	# line) matters: a separate cleanup line would be tty-echoed WHILE
	# the decoded command is still running, landing inside the captured
	# B..E window.  rm is silent, so it never pollutes the output here.
	printf 'printf "\\n%s\\n"; { b64decode -r %s | sh; }; rm -f %s; printf "\\n%s\\n"\r' \
	    "$B" "$f" "$f" "$E" >> "$BUF"
fi

i=0
while [ "$i" -lt "$TMO" ]; do
	sleep 1
	if tail -c +$((off + 1)) "$LOG" 2>/dev/null | tr -d '\r' | \
	    grep -q "^$E\$"; then
		break
	fi
	i=$((i + 1))
done

# Emit strictly the lines between the LAST BEGIN and the following END.
tail -c +$((off + 1)) "$LOG" 2>/dev/null | tr -d '\r' | \
	awk -v b="$B" -v e="$E" '
		$0 == b { buf = ""; cap = 1; next }
		$0 == e { if (cap) { printf "%s", buf; cap = 0 } next }
		cap { buf = buf $0 "\n" }
	'
