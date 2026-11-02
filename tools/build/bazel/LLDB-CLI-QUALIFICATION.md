# LLDB command line programs: native qualification (2026-11-02)

## Qualified scope

The native amd64 shared-library configuration now builds the original `lldb`
(one C++ source) and `lldb-server` (five C++ sources), their two original
TableGen option headers, runtime/debug programs, manuals and installation
archives. Original C++ and TableGen source bodies are unchanged. The source-owned
rules retain Make's PIE, warning, assertion, target-registration, language,
optimization, stack-protector and shared-library policies. Static LLVM linking,
other architectures, the upstream debugger suite and a complete selected-world
aggregate remain separate gates.

All paths below are under `/usr/obj/usr/src`. The final ordinary maintained
frontend profile is `bazel-lldb-cli-native-qualification-r3-20261102`, using
`bazel-lldb-cli-native-inputs-r3-20261102.json`, jobs16 and the standard disk guard
(18 GiB required start, 16 GiB reserve). It passed with two native Python test
wrappers; the reserve was not reached. Its SDK is the independently prepared
`bazel-posttar-sdk-20261102`, receipt SHA-256
`879ee79f4d33b1b2e1e6dfc28e1fe48d6fb47c24e90c9e07920a75d403397a4b`.
Historical library captures retain their original SDK bindings.

## Original Make references and controlled comparison

`bazel-lldb-make-reference-r1-20261102` and
`bazel-lldb-server-make-reference-r1-20261102` are unchanged original Make builds
and disposable installation stages, made through the maintained reference
helper with supported nofilemon metadata. Their original recipes explicitly
link the three configured world private DSOs; those are recorded existing
inputs, not claimed to be freshly built dependencies of these leaf references.

`bazel-lldb-cli-make-metadata-review-r1-20261102` binds all six real compiler
recipes and 5,162 consumed source/header occurrences. The actual native
compilers pass the exact effective macro and ordered warning vectors, PIE,
C++17, O2, line-table debug, SSP and original section policies. Every consumed
Make file hash maps to the corresponding declared native source, generated
header or selected SDK input. See `bazel-lldb-cli-action-review-r1-20261102`.

The ordinary filename baseline is retained in
`bazel-lldb-cli-object-review-r1-20261102`: four code sections sets and one
complete allocated section set match. All differing strings have exactly the
`/usr/src/` prefix difference. Two server objects also fold that nine-byte
filename length into LLVM error/log calls. Their original disassembly is
retained in `bazel-lldb-cli-filename-diagnosis-r1-20261102`; this diagnosis did
not substitute normalized object contents for comparison.

The independent `bazel-lldb-cli-filename-control-r1-20261102` includes each
unchanged original Makefile, appends only `-fmacro-prefix-map=/usr/src/=`, and
replaces only the LLDB library path in expanded DPADD/LDADD with the freshly
built independent Make private library from
`bazel-lldb-library-filename-control-full-r1-20261102`. All other dependency
paths and library order remain original. Its wrapper preserves recursive
DEPEND_CFLAGS; actual six compiler recipes retain `-MD`, `-MF` and `-MT`.
Fresh local object-directory include paths and the compiler map carried into
the link driver are recorded explicitly. All six objects and both final native
installed programs match this independent control in **every allocated section**:
bytes, section type, flags, size and alignment, including code, read-only data,
relocations and dynamic tables. See `bazel-lldb-cli-control-review-r3-20261102`.
No whole-file or debug-information byte identity is claimed.

## Actual producer and linker contracts

- `bazel-lldb-cli-generator-review-r1-20261102` verifies the two actual native
  TableGen actions, original Options.td/LLGSOptions.td and OptParser.td inputs,
  native tool hash, C locale and exact generated header bytes against both
  original Make and independent control outputs.
- The first successful native candidate (r2) linked its own C++ objects through
  a lazy archive. The server consequently extracted `main` first, unlike Make's
  direct original object sequence; even the one-object driver had different
  dynamic string/symbol table layout. Those rejected outputs and hash-bound
  original parameter files/archives remain in
  `bazel-lldb-cli-link-review-r3-20261102` and the earlier control reports.
  The correction uses the existing declared compiler-output files directly in
  ordinary `cc_binary.srcs`; real dependency libraries remain in `deps`.
- `bazel-lldb-cli-link-review-r4-20261102` verifies all four final actual uncached
  links, exact one/five direct object order, actual earlier compiler-output
  digests and explicit solib search directories selecting the captured native
  LLDB/Clang/LLVM DSOs. SDK sysroot DSO copies are distinct toolchain inputs.
  Final r3 reuses the six r2 compiler outputs and two generated headers; final
  captures and link inputs bind those exact payloads, not mutable bazel-bin.
- `bazel-lldb-cli-elf-review-r2-20261102` passes the unchanged maintained ELF
  program checker against ordinary Make: PIE/interpreter, **ordered** 17 NEEDED
  entries for lldb and 16 for lldb-server, imported/exported names and versions,
  RELRO/NOW, and absence of RPATH, text relocations and writable executable
  segments. Original filename-policy payload differences remain reported there;
  complete allocated-payload parity is established by the explicit control.
- `bazel-lldb-cli-install-review-r2-20261102` matches all ten original Make
  destination/type/root:wheel/mode/package records, checks each archive's eight
  structural directories separately, verifies literal decompressed manuals and
  both actual debuglink CRCs. Runtime allocated payloads match the independent
  control. Package tags stay `lldb` and `lldb,dbg`; final package creation and
  family directory composition are not claimed.

## Runtime tests and instrumentation

The two normal Bazel Python wrappers each test three source-reviewed paths
before debugger initialization: driver help, unknown option and missing file
argument; server usage, version and unknown command. Both final retained test
logs pass. Each wrapper also uses loader tracing to verify that the program
resolves the declared native LLDB, Clang and LLVM files. DOF initialization is
disabled in the process environment before program startup. No attach, launch,
listen or tracing activation is performed. These are two XML wrapper cases,
not six upstream test cases or a fully hermetic-loader qualification.

The earlier API wrapper remains separately qualified with the private library.
No host files were installed or changed, and no upgrade or reboot was performed.

## Cache evidence, failures and frontend integration

The current private LLDB/Clang/LLVM capture hashes equal the previously accepted
library captures. The broad old/current profile build-setting vectors also
match. Four actual uncached old/current compiler pairs (LLVM TextAPI Utils,
Clang NoReturnFunctionChecker, LLDB Version and ValueObjectVariable) have
identical argv, environment, output paths and output hashes, but three changed
input digests: execution-runtime libc, libthr and rtld. Thus these four actions
have legitimate changed compiler-runtime inputs; no whole-closure cause or
performance comparison is inferred. Evidence is retained in
`bazel-lldb-cli-compiler-cache-review-r1-20261102`. The inherited historical
`closure-actions.json` was empty and is explicitly not evidence; actual records
were recovered from the fully drained, tool-bound immutable compact logs.

The initial OptParser visibility rejection, r2 lazy-link rejection and ordinary
filename baseline remain preserved. Observer attempts that guessed a manual
path, required a unique DSO basename across SDK and selected solib inputs, or
omitted compiler CXXFLAGS from link comparison were rejected before acceptance;
corrected observers use actual source labels, explicit link directories and
complete original recipes. No production checker relaxation was made.

Existing format-5 targets, typed LLVM settings, tests, runtime inputs and
installation producers represent the entire cohort. No new frontend C/backend,
security, staging or manual API is required. Next work is actual LLDB-family
composition and inherited MK_LLDB world selection/package ownership, followed
by the remaining selected userland components. Full debugger runtime and full
system completion remain open.
