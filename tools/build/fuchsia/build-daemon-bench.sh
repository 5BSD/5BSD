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
