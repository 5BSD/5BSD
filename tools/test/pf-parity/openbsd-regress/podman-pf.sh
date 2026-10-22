#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# podman container networking through 5BSD's OpenBSD PF, end to end.
# The DUT runs podman with the 5BSD containernetworking-plugins (portmap
# patched for OpenBSD PF) and the port's pf.conf.sample; the OpenBSD helper
# (vio1, 10.188.210.10) is the outside host and the DUT's default router.
#
# Prerequisite on the DUT: podman-suite installed, the patched CNI plugins
# in /usr/local/libexec/cni (PODMAN_CNI_DIR with the FreeBSD originals in
# PODMAN_CNI_ORIG for the contrast case), and the image built here.
# Prints PASS/FAIL lines; exit status 1 if anything failed.
set -u
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config -o ConnectTimeout=300"
HELPER=10.188.210.10
DUT=10.188.210.50
rc=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; rc=1; }

# DUT: default route via the helper, the CNI sample ruleset, vfs storage on
# UFS, and a minimal image: a static sh plus nc(1) with its libraries.
$S dut 'sh -es' <<'EOF'
ifconfig vtnet1 | grep -q 'inet 10.188.210.50 ' ||
    ifconfig vtnet1 inet 10.188.210.50/24 up
# Keep the image's own default route (defaultrouter) to restore after.
[ -e /var/tmp/podman-pf.defaultrouter ] ||
    route -n get default 2>/dev/null |
    awk '$1 == "gateway:" { print $2 }' > /var/tmp/podman-pf.defaultrouter
route -q delete default >/dev/null 2>&1 || true
route -q add default 10.188.210.10
sysctl -q net.inet.ip.forwarding=1
# Images built from package payloads have only the .sample configs.
for f in /usr/local/etc/containers/*.sample; do
	[ -e "${f%.sample}" ] || cp "$f" "${f%.sample}"
done
if ! zfs list >/dev/null 2>&1 || [ -z "$(zfs list -H 2>/dev/null)" ]; then
	sed -i '' -e 's/^driver = "zfs"/driver = "vfs"/' \
	    /usr/local/etc/containers/storage.conf
fi
cp /usr/local/etc/containers/pf.conf.sample /etc/pf.conf
# Kernels without the egress group (before land/pf 55b7aff751a) name the
# uplink instead.
if [ -z "$(ifconfig -g egress 2>/dev/null)" ]; then
	sed -i '' -e 's/egress:0/vtnet1:0/; s/on egress/on vtnet1/' /etc/pf.conf
fi
pfctl -f /etc/pf.conf
pfctl -e >/dev/null 2>&1 || true
if ! podman image exists localhost/pftest:latest; then
	r=/var/tmp/pftest-root; rm -rf $r; mkdir -p $r/bin $r/usr/bin $r/lib $r/libexec $r/etc $r/tmp $r/dev
	# /rescue/sh is static.  Copy only it: an image's /rescue may be
	# separate copies of one large binary rather than hard links.
	cp /rescue/sh $r/bin/sh
	cp /usr/bin/nc $r/usr/bin/nc
	cp /libexec/ld-elf.so.1 $r/libexec/
	for l in $(ldd -f "%p\n" /usr/bin/nc); do [ -f "$l" ] && cp $l $r/lib/; done
	tar -cf /var/tmp/pftest.tar -C $r .
	podman import /var/tmp/pftest.tar localhost/pftest:latest >/dev/null
fi
podman rm -f -a >/dev/null 2>&1 || true
EOF
[ $? -eq 0 ] || { echo "FAIL setup"; exit 1; }
$S helper 'printf "pass\n" | pfctl -f -; route -q delete -net 10.88.0.0/16 >/dev/null 2>&1; true'

# A: outbound NAT.  The helper has no route to 10.88/16, so a reply only
# arrives through <cni-nat> masquerading.
out=$($S dut 'podman run --rm localhost/pftest /usr/bin/nc -z -w 5 10.188.210.10 22 && echo OK' 2>&1)
case "$out" in *OK*) pass "masquerade: container reached the helper" ;;
*) fail "masquerade: $out" ;; esac

# B: a published port from outside.
$S dut "podman run -d --name web -p 8080:80 localhost/pftest /bin/sh -c 'while :; do echo hello | /usr/bin/nc -N -l 80; done' >/dev/null"
sleep 3
id=$($S dut 'podman inspect -f "{{.Id}}" web' | cut -c1-32)
r=$($S helper "nc -w 5 $DUT 8080 </dev/null")
[ "$r" = hello ] && pass "portmap: helper -> $DUT:8080" || fail "portmap: helper got '$r'"

# C: the anchor holds the OpenBSD rules the plugin generated.
a=$($S dut "pfctl -a cni-rdr/$id -sr")
case "$a" in *"rdr-to 10.88."*"port 80"*) pass "anchor: $(echo "$a" | head -1)" ;;
*) fail "anchor cni-rdr/$id: $a" ;; esac

# D: the published port from the container host itself.
for dst in 127.0.0.1 $DUT; do
	r=$($S dut "nc -w 5 $dst 8080 </dev/null")
	[ "$r" = hello ] && pass "portmap local: $dst:8080" ||
	    fail "portmap local: $dst:8080 got '$r'"
done

# E: reloading the main ruleset keeps the container's anchor.
$S dut 'pfctl -f /etc/pf.conf'
r=$($S helper "nc -w 5 $DUT 8080 </dev/null")
[ "$r" = hello ] && pass "reload: published port survives pfctl -f" ||
    fail "reload: helper got '$r' after pfctl -f /etc/pf.conf"

# F: removing the container removes its rules and its masquerade entry.
ip=$($S dut 'podman inspect -f "{{.NetworkSettings.IPAddress}}" web')
$S dut 'podman rm -f web >/dev/null'
a=$($S dut "pfctl -a cni-rdr/$id -sr")
[ -z "$a" ] && pass "teardown: anchor cni-rdr/$id empty" ||
    fail "teardown: anchor still has: $a"
$S dut "pfctl -t cni-nat -T show" | grep -qw "$ip" &&
    fail "teardown: $ip still in <cni-nat>" ||
    pass "teardown: $ip removed from <cni-nat>"
$S dut 'pfctl -Fs >/dev/null 2>&1'
r=$($S helper "nc -w 3 $DUT 8080 </dev/null 2>&1")
[ "$r" != hello ] && pass "teardown: port 8080 closed" ||
    fail "teardown: port 8080 still answers"

# G: contrast, the FreeBSD plugin: its rules do not load, so podman
# refuses to publish the port rather than running it unreachable.
if $S dut 'test -x ${PODMAN_CNI_ORIG:-/var/tmp/podman/cni-orig}/portmap'; then
	$S dut 'd=${PODMAN_CNI_ORIG:-/var/tmp/podman/cni-orig}; cp /usr/local/libexec/cni/portmap /var/tmp/portmap.5bsd; cp $d/portmap /usr/local/libexec/cni/portmap'
	out=$($S dut "podman run -d --name web2 -p 8081:80 localhost/pftest /bin/sh -c 'sleep 30'" 2>&1)
	case "$out" in *"syntax error"*|*"error loading rules"*) pass "freebsd plugin: refused ($(echo "$out" | grep -o 'syntax error' | head -1))" ;;
	*) fail "freebsd plugin: $out" ;; esac
	$S dut 'podman rm -f web2 >/dev/null 2>&1; cp /var/tmp/portmap.5bsd /usr/local/libexec/cni/portmap'
fi

# H: no panics, lock-order reversals or pf warnings from all of the above.
d=$($S dut 'dmesg | grep -E "lock order reversal|panic|state key linking mismatch|pf: " | tail -5')
[ -z "$d" ] && pass "dmesg: clean" || fail "dmesg: $d"

# Restore the default route the DUT had: the ATF suites that follow expect
# one (udp_bindings connects to an address only a default route reaches).
$S dut 'route -q delete default >/dev/null 2>&1; gw=$(cat /var/tmp/podman-pf.defaultrouter 2>/dev/null); rm -f /var/tmp/podman-pf.defaultrouter; [ -z "$gw" ] || route -q add default "$gw"; true'
exit $rc
