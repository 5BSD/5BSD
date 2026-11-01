# Native NTP documentation and family installation aggregation

2026-11-01. All seven NTP programs, four private libraries and the maintained
documentation installation tree now have native candidates. Make remains the
production/default backend. This closes the directory's installation aggregation;
complete pkgbase dependency/manifests/package creation, publication and full
service/protocol/cross-architecture/performance qualification remain separate
gates. No host installation or daemon/clock operation was performed.

## Maintained inputs and normal frontend route

The native inventory declares all 235 HTML/data payloads across eight directory
components, plus nine manuals. Four pages are actually owned beside their
programs (util/ntp-keygen.html, ntpd/ntp.conf.html, ntpd/ntp.keys.html and
ntpsnmpd/ntpsnmpd.html); the source-to-destination map preserves those real inputs
and their normal installed names. There is no source probing, copying, resource
fallback or production Make interpretation. All metadata is maintained native
Bazel source, including actual logical ownership, modes and package tags.

Seven manuals retain Make's original .Dt sed expressions using the existing
declared filter rule and native sed, with explicit runtime inputs; two are
maintained local manuals. All nine retain declared gzip compression. The existing
split_manpages setting selects ntp versus ntp-man tags. The new typed html bool
(default true, matching MK_HTML) selects both HTML payloads and their directories.
HTML disabled leaves all nine manuals, matching Make. Qualification retains
the current fixed SDK/manual-compression profile; generic MK_MAN/MANCOMPRESS
overrides and all Make option combinations are not newly modeled or qualified.

The normal format-5 build-settings object accepts
//tools/build/bazel/config:html = false and the existing split_manpages bool.
No frontend C, SDK or Python API change is needed: source_graph already passes
typed source labels through to Bazel. Actual build-bsd plan invocations confirm
--with-option/--without-option are unsupported CLI options and reject exit 64;
they are not silently ignored. Those switches do exist on install-reference.py
for independent Make references. Make src-conf is explicitly rejected by the
native test action. Exact profile files, their receipt input bindings and CLI
observations are preserved in bazel-ntp-documentation-evidence-20261101 under
/usr/obj/usr/src. The normal frontend was used, not a replacement build entry.

## Build and artifact evidence

All paths below are under /usr/obj/usr/src. The two final maintained frontend
runs each pass both the doc archive and combined family archive targets:

- bazel-ntp-doc-qualification-r3-20261101
- bazel-ntp-doc-nohtml-split-qualification-r3-20261101

Fresh independent Make subtree references are bazel-ntp-doc-make-r1-20261101 and
bazel-ntp-doc-nohtml-split-make-r1-20261101. The latter explicitly selects
WITHOUT_HTML and WITH_MANSPLITPKG. Both use the maintained reference helper,
baseline SDK/profile checks, 16 jobs and NO_ROOT staging. No package was created
or published, and no test target/runtime success is inferred from these two
build-only target lists.

bazel-ntp-doc-family-{default,nohtml-split}-parity-r1-20261101 contains passing
commands and hash-bound capture comparisons. Documentation matches all Make
metadata and exact payload bytes: default 252 records (244 files/eight dirs),
reduced nine manual records. The combined family archive matches the union of
fresh independently qualified Make component inventories: default 273 records
(260 files/13 dirs), reduced 30 records (25 files/five dirs). Only repeated
identical directory metadata is deduplicated; files cannot collide.

Every combined-archive program/config/debug payload is byte-identical to its
previous completed native component archive, selected through the maintained
receipt/manifest/hash/containment resolver. Thus existing ELF, version, debug-CRC
and bounded option-test evidence applies to those exact bytes. Every doc payload
matches its fresh Make staging bytes, including compressed/transformed manuals.
This is installation payload identity, not a claim of complete binary equivalence
with Make. The family target merges native component manifest providers and
builds their payloads; it does not maintain a second selected-binary fixture.

Additional installed ntpd checks in the default parity directory verify that
actual native and Make stripped binaries retain the four time-discipline schemas
and five ordinary/nine is-enabled patched sites, using their validated separate
debug files. The default installed binary hash is also bound to the combined
family payload. Both enabled NTP profiles pass; live registration/firing remains
unqualified.

## Retained failures and remaining work

Initial r1 analysis rejected Python-style whitespace split; the inventory is now
explicit Starlark lists. Default r2 rejected four incorrectly assumed html/
source labels; the corrected map owns the real program-adjacent inputs. Reduced
r2 passed; both final r3 profiles pass after the source-map correction. All prior
runs are retained. No file was omitted to make an archive pass.

The combined target is an installation archive, not a completed native pkg
repository. Package dependency closure, subpackage manifest/creation parity and
publication still need qualification in the wider pkgbase aggregation. Upstream
contrib/ntp tests outside the maintained Make graph, isolated live NTP/auth/refclock
and probe tests, full-system startup, and controlled rebuild/runtime performance
remain open. The earlier observed large exec-config rebuilds are not a cache
performance claim.
