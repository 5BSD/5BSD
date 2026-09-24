#!/bin/sh
# Cross-build a real Linux64 libfuse daemon; never execute it on the host.
set -eu
out=${1:?usage: build-fuse-client.sh output-directory}
mkdir -p "$out"
out=$(realpath "$out")
root="$out/sysroot"
mkdir -p "$root"
fetch_checked()
{
 name=$1
 digest=$2
 url=$3
 if [ ! -f "$out/$name" ]; then
  curl --fail --location --max-time 120 -o "$out/$name" "$url"
 fi
 [ "$(sha256 -q "$out/$name")" = "$digest" ] || {
  echo "checksum mismatch: $name" >&2
  exit 1
 }
}
fetch_checked hello.c 30c36c4c57547bc4253d438b63f0ac89602e508870b73918646f3d840532a188 \
 https://raw.githubusercontent.com/libfuse/libfuse/fuse-3.18.3/example/hello.c
while read -r name digest; do
 fetch_checked "$name" "$digest" \
  "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$name"
 tar -xf "$out/$name" -C "$root"
done <<'PACKAGES'
musl-1.2.6-r2.apk 573712e2f49c15bfc20a2699f204acdfc74c772722b15e7353d768057fae0e71
musl-dev-1.2.6-r2.apk 6831e8b9e4821dae2c9121f0641f81e543f4ac27c03144c4876980ee84e6988f
fuse3-dev-3.18.3-r0.apk c077da4132070a073dc4c708fc9155272b6615cac0cfae387b74ab11da0f56ac
fuse3-static-3.18.3-r0.apk 55d26a2fb0ea15534e9b956c3bffc1eb2968bfd1730a4e9302ffd4b138b1c44f
fuse3-libs-3.18.3-r0.apk 5455c41da8abb45ece2c7bf74cb9a9f5758d9ba17118cb85a2bc5ebef159bcfa
PACKAGES
clang --target=x86_64-linux-musl --sysroot="$root" -fuse-ld=lld \
 -static -nostdlib -O2 -I"$root/usr/include/fuse3" \
 "$root/usr/lib/crt1.o" "$root/usr/lib/crti.o" "$out/hello.c" \
 -L"$root/usr/lib" -lfuse3 -lc "$root/usr/lib/crtn.o" \
 -o "$out/fuse-hello"
echo "Built $out/fuse-hello; run only in a disposable Linux64 guest."
