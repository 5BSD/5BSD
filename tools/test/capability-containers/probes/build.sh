#!/bin/sh
# Build the probe units against the world in /usr/obj (run from a buildenv:
#   make buildenv BUILDENV_SHELL="sh tools/test/capability-containers/probes/build.sh"
# ).  They link against the sysroot's libservice/liblogcmp/libcryptocmp.
set -e
D=$(cd "$(dirname "$0")" && pwd); W=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}/tmp; mkdir -p "$D/bin"
LS=$(ls "$W"/usr/lib/libservice.so.[0-9]* | sort -V | tail -1)
cd "$D"
cc -O2 -pipe -I/usr/src/lib/libservice reclaimprobe.c -o bin/reclaimprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice enospcprobe.c -o bin/enospcprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice boottimeprobe.c -o bin/boottimeprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice envprobe.c -o bin/envprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice jailprobe.c -o bin/jailprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice stressprobe.c -o bin/stressprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice txnstressprobe.c -o bin/txnstressprobe "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice modprobe.c -o bin/modprobe "$LS"
LB=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}/lib/libble/libble.so.1; [ -f "$LB" ] || LB=$(ls "$W"/usr/lib/libble.so.[0-9]* | sort -V | tail -1)
cc -O2 -pipe -I/usr/src/lib/libble -I/usr/src/lib/libservice gattprobe.c -o bin/gattprobe "$LB" "$LS"
cc -O2 -pipe -I/usr/src/usr.sbin/bluetooth/blued gattowners.c /usr/src/usr.sbin/bluetooth/BSDBluetooth/blued_persist.c -o bin/gattowners
cc -O2 -pipe -I/usr/src/lib/liblogcmp logprobe.c -o bin/logprobe "$W/usr/lib/liblogcmp.so.1" "$LS"
cc -O2 -pipe -I/usr/src/lib/libcryptocmp -I/usr/src/lib/liblogcmp -I/usr/src/sys cryptoprobe.c -o bin/cryptoprobe "$W/usr/lib/libcryptocmp.so.1" "$W/usr/lib/liblogcmp.so.1" "$LS"
cc -O2 -pipe -I/usr/src/lib/libservice -I/usr/src/lib/liblogcmp groupprobe.c -o bin/groupprobe "$W/usr/lib/liblogcmp.so.1" "$LS"
cc -O2 -pipe -I/usr/src/lib/libcryptodesc -I/usr/src/sys keyowners.c -o bin/keyowners "$W/usr/lib/libcryptodesc.so.1" 2>/dev/null || cc -O2 -pipe -I/usr/src/lib/libcryptodesc -I/usr/src/sys keyowners.c -o bin/keyowners
for p in reclaimprobe envprobe jailprobe stressprobe modprobe gattprobe logprobe cryptoprobe groupprobe; do echo "$p: $(readelf -d bin/$p | grep -o 'libservice.so.[0-9]*')"; done
