# Native wpa_cli — 2026-11-02

## Source, link and install ownership

The maintained wpa_cli program now uses native cc_binary source ownership with
its actual WPA header context, ordinary PIE policy and Make's ordered macro/
warning flags. The explicit twelve private-library dependency edges preserve
the maintained LIBADD sequence; OpenSSL selects ssl/crypto, followed by the
original pcap/util shared libraries. The actual Make CONFIG_TLS=openssl macro
is retained even in internal-crypto configurations. No production source,
service policy or test body is changed to accommodate the build.

The native install manifest retains /usr/sbin/wpa_cli, its debug companion and
wpa_cli.8 under package=wpa. Private libraries retain their own INTERNALLIB
ownership. The new child package does not leave stale ancestor raw-file labels.

## Performed checks

Evidence is under /usr/obj/usr/src:

- bazel-wpa-cli-reference-matrix-20261102.json records four fresh independent
  Make program builds, crossing OpenSSL and EAPOL. Each explicitly selects all
  twelve private archives in DPADD, LDADD and the actual recorded link recipe.
  Archive hashes remain bound; EAP peer uses the corrected r2 references from
  WPA-EAP-PEER-DUPLICATE.md. The production helper's Make-variable gates were
  not widened to manufacture these reference builds.
- Four normal build-bsd format-5 profiles
  pass program/install construction and safe_cli_test with sixteen jobs and the
  existing 18 GiB start / 16 GiB stop reserve. No disk guard fired. Each actual
  retained unittest log reports four methods, sixteen total; the Bazel XML
  reports one wrapper case per profile. These counts are not interchangeable.
- bazel-wpa-cli-elf-audit-r1-20261102/report.json passes four immutable-capture
  ELF contract comparisons, including exact ordered NEEDED entries, PIE,
  RELRO/NOW, symbol/version contracts and absence of text relocations, executable
  stack and search paths. With OpenSSL the ordered libraries are ssl, crypto,
  pcap, util, libc; internal configurations retain pcap, util, libc.
- bazel-wpa-cli-object-audit-r1-20261102/report.json binds each program object
  and linker parameter snapshot to actual execution input/output hashes. All
  four text sections, eight raw constant sections and ordered decoded macro/
  warning vectors match Make. All 324 prerequisite hash checks, 81 unique
  source/sysroot inputs, match native action inputs. All four compiler records
  report processwrapper-sandbox with cache_hit=false. Snapshots were provisional
  until those checks passed; mutable bazel-bin is not the comparison oracle.
- bazel-wpa-cli-link-audit-20261102.json verifies all four actual private archive
  orders, 48 archive selections, from those digest-bound parameter files.
- bazel-wpa-cli-relocation-audit-20261102.json compares all 9,718 raw non-debug
  relocation records across four program objects, including numeric symbol
  indices and addends, without rewriting objects.
- bazel-wpa-cli-install-audit-20261102/report.json matches all five default
  installation records, owner/group/mode/package tags and decompressed manual
  payload. Both native and Make installed debug-link CRCs validate. This is
  component installation qualification, not final pkgbase dependency/package
  archive construction.

The safe tests run as a non-root user and exercise help, version, illegal-option
handling and loader closure. The first three return before opening a control
connection. The loader check requires every loaded DSO to come from declared
runfiles directories; native pcap/OFED/crypto/thread dependencies are included.
No host WLAN interface, account, network configuration or service is modified.

## Reproducibility and remaining gates

Full linked/debug byte identity is not claimed. The ELF reports retain actual
physical differences in code/data, relocation and debug sections. The linked
rodata printable-string audit identifies exactly the inherited relative
contrib/wpa/src/utils/eloop.c versus Make's /usr/src-prefixed filename in each
configuration. That observation does not establish equivalence of every linked
section, relocation or full ABI. Original diagnostic semantics remain intact;
no absolute source-tree constant or artifact rewrite forces a match.

The default and internal-EAPOL builds compile additional execution-tool closure;
their retained logs report 1,274 and 1,284 sandbox spawns and 6,486 and 5,413
cache hits respectively. These observations do not establish cache causes or
controlled performance. The existing compact-execution-evidence and configured
execution-action cache investigation gates remain open.

Existing explicit format-5 targets and typed openssl/wpa_supplicant_eapol
settings cover the maintained build-bsd path. No frontend C/backend option,
SDK/staging/signing/publication policy or new manual API is introduced. The
existing manual documents this route; Make remains production/default.

The source has no recognized direct SDT/DTrace/audit/FIDL call markers. Shared
instrumentation and event delivery still require runtime qualification. Native
WPA output coverage now includes all sixteen private library directories and
three of five programs within their documented safe runtime scope. Remaining
programs are hostapd and wpa_supplicant. Real control-socket operations, wireless
and authentication behavior, cross-userland, full system/pkgbase/boot and
controlled performance remain open.
