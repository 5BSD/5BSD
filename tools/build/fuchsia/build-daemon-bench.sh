#!/bin/sh
# build-daemon-bench.sh -- build the pre-migration ("legacy") latency_bench
# for a capability daemon, for comparison with the in-tree FIDL bench in the
# same VM (tools/build/fuchsia/DAEMONS.md, "Latency").
#
# usage: build-daemon-bench.sh SRC BASE_REV DAEMON OUT_DIR
#
#   SRC       a source tree whose world is built (its objdir supplies the
#             buildenv toolchain and libraries)
#   BASE_REV  the commit before the daemon's FIDL migration
#   DAEMON    power | device | ...
#   OUT_DIR   receives latency_bench.<daemon>.legacy
#
# The bench driver (the daemon's tests/latency_bench.c and daemon_bench.h)
# comes from SRC; the provider and client sources come from BASE_REV, so the
# two binaries differ only in the protocol implementation.  Runs the compile
# inside "make buildenv" so it links against the built world, not the host.
set -eu
[ $# = 4 ] || { sed -n '2,/^set -eu/p' "$0" | sed -e '/^set -eu/d' -e 's/^# \{0,1\}//' >&2; exit 64; }
src=$(cd "$1" && pwd) rev=$2 daemon=$3 out=$4
mkdir -p "$out"
out=$(cd "$out" && pwd)
old=$out/legacy-src-$daemon
rm -rf "$old"
mkdir -p "$old"
case $daemon in
power)
	paths="usr.sbin/BSDPower lib/libpowercmp"
	defs="-DBSDPOWER_TESTING"
	incs="usr.sbin/BSDPower lib/libpowercmp"
	srcs="usr.sbin/BSDPower/BSDPower.c usr.sbin/BSDPower/config.c"
	bench=usr.sbin/BSDPower/tests/latency_bench.c
	libs="-lservice -lchannel -lprivateucl"
	;;
device)
	paths="usr.sbin/BSDDevice lib/libdevicecmp"
	defs="-DBSDDEVICE_TESTING"
	incs="usr.sbin/BSDDevice lib/libdevicecmp"
	srcs="usr.sbin/BSDDevice/bsddevice.c usr.sbin/BSDDevice/policy.c"
	bench=usr.sbin/BSDDevice/tests/latency_bench.c
	libs="-lservice -lchannel -lprivateucl -lpthread"
	;;
trace)
	paths="usr.sbin/BSDTrace lib/libtracecmp"
	defs="-DTRACECMP_TESTING -DTRACECMP_CLIENT_SOURCE=\\\"$old/lib/libtracecmp/tracecmp.c\\\""
	incs="usr.sbin/BSDTrace lib/libtracecmp"
	srcs="usr.sbin/BSDTrace/tracecmp.c usr.sbin/BSDTrace/tracecmp_policy.c"
	bench=usr.sbin/BSDTrace/tests/latency_bench.c
	libs="-lbsm -ldtrace -lservice -lchannel -llogcmp"
	extra="-I$src/lib/liblogcmp -I$src/cddl/contrib/opensolaris/lib/libdtrace/common"
	;;
sysctl)
	paths="usr.sbin/BSDSysctl lib/libsysctlcmp"
	defs="-DSYSCTLCMP_TESTING"
	incs="usr.sbin/BSDSysctl lib/libsysctlcmp"
	srcs="usr.sbin/BSDSysctl/bsdsysctl.c usr.sbin/BSDSysctl/config.c usr.sbin/BSDSysctl/interfaces.c"
	bench=usr.sbin/BSDSysctl/tests/latency_bench.c
	libs="-lservice -lchannel -lprivateucl"
	;;
crypto)
	paths="usr.sbin/BSDCrypto lib/libcryptocmp"
	defs="-DBSDCRYPTO_TESTING"
	incs="usr.sbin/BSDCrypto lib/libcryptocmp"
	srcs="usr.sbin/BSDCrypto/bsdcrypto.c usr.sbin/BSDCrypto/policy.c"
	bench=usr.sbin/BSDCrypto/tests/latency_bench.c
	libs="-lauditcmp -lcryptodesc -lservice -lchannel -lpthread"
	extra="-I$src/lib/libauditcmp -I$src/lib/libcryptodesc -I$src/lib/liblogcmp -I$src/lib/libcapreclaim"
	;;
audit)
	paths="usr.sbin/BSDAudit lib/libauditcmp"
	defs="-DAUDITCMP_TESTING -DAUDITCMP_CLIENT_SOURCE=\\\"$old/lib/libauditcmp/auditcmp.c\\\""
	incs="usr.sbin/BSDAudit lib/libauditcmp"
	srcs="usr.sbin/BSDAudit/auditcmp.c usr.sbin/BSDAudit/auditcmp_rate.c usr.sbin/BSDAudit/auditcmp_submit.c"
	bench=usr.sbin/BSDAudit/tests/latency_bench.c
	libs="-lbsm -lservice -lchannel"
	extra="-I$src/lib/liblogcmp"
	;;
network)
	paths="usr.sbin/BSDNetwork lib/libnetworkcmp"
	defs="-DNETWORKCMP_TESTING -DNETWORKCMP_CLIENT_SOURCE=\\\"$old/lib/libnetworkcmp/networkcmp.c\\\""
	incs="usr.sbin/BSDNetwork lib/libnetworkcmp"
	srcs="usr.sbin/BSDNetwork/networkcmp.c usr.sbin/BSDNetwork/config.c usr.sbin/BSDNetwork/policy.c usr.sbin/BSDNetwork/resolver.c"
	bench=usr.sbin/BSDNetwork/tests/latency_bench.c
	libs="-lauditcmp -lprivateucl -lservice -lchannel -lpthread"
	extra="-I$src/lib/libauditcmp -I$src/lib/liblogcmp -I$src/lib/libnotify -I$src/lib/libsysctlcmp"
	;;
notify)
	paths="usr.sbin/BSDNotify lib/libnotify"
	defs="-DNOTIFY_BENCH_LEGACY -DNOTIFY_CLIENT_SOURCE=\\\"$old/lib/libnotify/notify.c\\\" -DNOTIFY_SERVER_SOURCE=\\\"$old/usr.sbin/BSDNotify/bsdnotify.c\\\""
	incs="usr.sbin/BSDNotify lib/libnotify"
	srcs="usr.sbin/BSDNotify/broker.c usr.sbin/BSDNotify/policy.c usr.sbin/BSDNotify/transport.c"
	bench="usr.sbin/BSDNotify/tests/latency_bench.c usr.sbin/BSDNotify/tests/latency_bench_server.c"
	libs="-lauditcmp -llogcmp -lnotify -lprivateucl -lservice -lchannel -lpthread"
	extra="-I$src/lib/libauditcmp -I$src/lib/liblogcmp"
	;;
*)
	echo "build-daemon-bench: unknown daemon $daemon" >&2; exit 64;;
esac
git -C "$src" archive "$rev" $paths | tar -xf - -C "$old"
flags="-O2 -pipe -std=gnu17 $defs -DDAEMON_BENCH_VARIANT=\\\"legacy\\\""
for i in $incs; do flags="$flags -I$old/$i"; done
flags="$flags -I$src/tools/build/fuchsia -I$src/lib/libservice -I$src/lib/libchannel"
flags="$flags -I$src/sys -I$src/contrib/libucl/include ${extra:-}"
files=""
for b in $bench; do files="$files $src/$b"; done
for s in $srcs; do files="$files $old/$s"; done
cat > "$out/build-$daemon.sh" <<EOS
#!/bin/sh
set -eux
cc $flags $files $libs -o $out/latency_bench.$daemon.legacy
EOS
make -C "$src" buildenv BUILDENV_SHELL="/bin/sh $out/build-$daemon.sh"
ls -l "$out/latency_bench.$daemon.legacy"
