#!/bin/sh
# Build the probe units against the world in /usr/obj (run from a buildenv:
#   make buildenv BUILDENV_SHELL="sh tools/test/capability-containers/probes/build.sh"
# ).  They link against the sysroot's libservice/liblogcmp/libcryptocmp.
set -e
D=$(cd "$(dirname "$0")" && pwd); W=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}/tmp; mkdir -p "$D/bin"
LS=$(ls "$W"/usr/lib/libservice.so.[0-9]* | sort -V | tail -1)
# The provider clients moved out of libservice into their own libraries.
FS="$W/usr/lib/libfilesystemcmp.so.1"; EXT="$W/usr/lib/libextensioncmp.so.1"
NS="$W/usr/lib/libnamespacecmp.so.1"
CI="-I/usr/src/lib/libservice -I/usr/src/lib/libfilesystemcmp -I/usr/src/lib/libextensioncmp -I/usr/src/lib/libnamespacecmp"
cd "$D"
cc -O2 -pipe $CI reclaimprobe.c -o bin/reclaimprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI enospcprobe.c -o bin/enospcprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI boottimeprobe.c -o bin/boottimeprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI envprobe.c -o bin/envprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI jailprobe.c -o bin/jailprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI stressprobe.c -o bin/stressprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI txnstressprobe.c -o bin/txnstressprobe "$FS" "$EXT" "$NS" "$LS"
cc -O2 -pipe $CI modprobe.c -o bin/modprobe "$FS" "$EXT" "$NS" "$LS"
LB=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}/lib/libble/libble.so.1; [ -f "$LB" ] || LB=$(ls "$W"/usr/lib/libble.so.[0-9]* | sort -V | tail -1)
cc -O2 -pipe -I/usr/src/lib/libble $CI gattprobe.c -o bin/gattprobe "$LB" "$FS" "$EXT" "$LS"
cc -O2 -pipe -I/usr/src/usr.sbin/bluetooth/blued gattowners.c /usr/src/usr.sbin/bluetooth/BSDBluetooth/blued_persist.c -o bin/gattowners
cc -O2 -pipe -I/usr/src/lib/liblogcmp logprobe.c -o bin/logprobe "$W/usr/lib/liblogcmp.so.1" "$LS"
cc -O2 -pipe -I/usr/src/lib/libcryptocmp -I/usr/src/lib/liblogcmp -I/usr/src/sys cryptoprobe.c -o bin/cryptoprobe "$W/usr/lib/libcryptocmp.so.1" "$W/usr/lib/liblogcmp.so.1" "$LS"
cc -O2 -pipe $CI -I/usr/src/lib/liblogcmp groupprobe.c -o bin/groupprobe "$W/usr/lib/liblogcmp.so.1" "$FS" "$LS"
cc -O2 -pipe -I/usr/src/lib/libcryptodesc -I/usr/src/sys keyowners.c -o bin/keyowners "$W/usr/lib/libcryptodesc.so.1" 2>/dev/null || cc -O2 -pipe -I/usr/src/lib/libcryptodesc -I/usr/src/sys keyowners.c -o bin/keyowners
for p in reclaimprobe envprobe jailprobe stressprobe modprobe gattprobe logprobe cryptoprobe groupprobe; do echo "$p: $(readelf -d bin/$p | grep -o 'libservice.so.[0-9]*')"; done
