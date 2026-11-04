# Optional native Hesiod consumer (2026-11-04)

The AMD64 hesinfo target now uses the maintained source program/manual and
native utility installation/debug/archive rules. The source hesiod.h provider
adds only this consumer to its existing restricted visibility. Hesiod functions
are optional libc exports, so the program links the existing configured native
libc/shared interface and libsys instead of assuming the prepared SDK enables
Hesiod. The target is explicitly incompatible when the hesiod option is false.
The usr.bin production parent selects its archive only when the option is true;
other unconverted optional families remain incompatible.

The normal 16-job build-bsd format-5 request passes in
/usr/obj/usr/src/bazel-hesinfo-native-r1-20261104. Its safe usage case executes
against declared native libc/libsys and checks stdout, exact stderr and exit 2;
source_settings_test also passes. No DNS or host configuration is changed.
The archive review in bazel-hesinfo-review-r2-20261104 binds actual native link
and archive actions, three captured products, exact payload hashes, modes and
numeric ownership. It contains the binary, split debug file, manual and two
explicit debug directories. This is serialization and safe CLI qualification,
not a complete DNS/Hesiod service test or independent Make binary parity.

The maintained original reference in bazel-hesinfo-make-r1-20261104 failed:
its unchanged SDK lacks the optional hesiod.h header; its libc also has no
Hesiod dynamic exports. WITH_HESIOD on a leaf cannot retroactively configure
that SDK. This failure is retained. No replacement header/library was silently
injected and no passing Make parity is claimed. A coherent original HESIOD
world/SDK profile remains required for independent comparison. ARM64/RISC-V,
full installed world/pkgbase, runtime DNS and resource/cache gates remain open.

The new parent query also exposed an earlier file2c package-boundary regression
from adding its TAP tests BUILD file: parent native cases still used tests/...
file labels. Those labels now explicitly name the test package and that package
exports only the eleven consumed fixture files to its parent. No fixture bytes,
case arguments or installed manifests change. Complete production rebuild and
all nine existing native cases pass in
bazel-usrbin-file2c-boundary-native-r1-20261104. Its review in
bazel-usrbin-file2c-boundary-review-r1-20261104 verifies all 801 captured
production archive/request/directory outputs remain byte-identical to the
previous passing production run.
The initial failed query and initial audit's incorrect all-records-are-files
assumption remain in r1 evidence directories; the corrected audit checks actual
file and directory types separately.

Existing generic build-bsd format-5 inputs/settings carry this work; frontend C,
signing, staging policy and publication behavior are unchanged. The maintained
manual and completion roadmap are updated. Make remains default; BIP excluded.
No host installation, module loading, upgrade, reboot or publication occurs.

The corrected explicit-JDK ownership query passes both profiles in
bazel-hesinfo-selection-r3-20261104: disabled has the unchanged 267 archives;
enabled adds exactly hesinfo for 268, and both parents are compatible. The first
query caught the file2c labels; the second failed because the audit caller omitted
the explicit JAVA_HOME used by build-bsd and discovered an unrelated host JDK
layout. Those caller failures remain retained; the maintained frontend's explicit
Java selection was not changed. Queries materialize no production compilation.
