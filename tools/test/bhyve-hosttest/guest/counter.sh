#!/bin/sh
# Monotonic counter that must keep counting across checkpoint/restore and
# migration. Writes "<n> <uptime-ish>" to /var/tmp/ht-counter every 0.2 s.
# usage: counter.sh start|read|stop
f=/var/tmp/ht-counter p=/var/tmp/ht-counter.pid
case "$1" in
start)
	rm -f $f
	( n=0; while :; do n=$((n + 1)); echo "$n" > $f.new && mv $f.new $f; sleep 0.2; done ) >/dev/null 2>&1 &
	echo $! > $p; sleep 0.5; echo "COUNTER-STARTED pid=$(cat $p) value=$(cat $f)" ;;
read)
	kill -0 "$(cat $p)" 2>/dev/null && alive=yes || alive=no
	echo "COUNTER value=$(cat $f 2>/dev/null) alive=$alive pid=$(cat $p 2>/dev/null)" ;;
stop)
	kill "$(cat $p)" 2>/dev/null; rm -f $p ;;
esac
