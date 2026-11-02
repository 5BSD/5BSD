# Native hostapd — 2026-11-02

## Maintained ownership

The native cc_binary owns the original five program translation units in their
Make order: config_file.c, ctrl_iface.c, driver_bsd.c, eap_register.c and main.c.
Its physical header provider owns the 70 observed WPA headers with their
original include contexts. Thirteen explicit private-library dependencies retain
Make's actual archive order. OpenSSL selects ssl/crypto before pcap/util.

Program flags preserve Make's PIE policy, HOSTAPD, CONFIG_L2_FREEBSD,
CONFIG_DNET_PCAP, optional CONFIG_IPV6 and the real second Makefile.inc macro/
warning group. No program source, service behavior, backend or privilege check
is changed for native construction.

The source-owned installation retains package=hostapd for /usr/sbin/hostapd,
its debug companion, hostapd.8, hostapd.conf.5 and the three original example
files under /usr/share/examples/hostapd. The existing examples bool controls
the example payload and directory. Private libraries remain INTERNALLIB.

## Checks performed

Evidence is under /usr/obj/usr/src, using the validated November 2 execution SDK
and normal build-bsd format-5 inputs with sixteen jobs. The 18 GiB start / 16 GiB
stop guard never fired. No host interface, WLAN configuration, service, tracing,
installation or clock state was changed.

- Fresh independent Make default and OpenSSL/no-EAPOL consumers select all
  thirteen recorded private archives through DPADD, LDADD and the actual link
  recipe. The [AES-CTR correction](WPA-AES-CTR-QUALIFICATION.md) resolves the real
  no-EAPOL link failure; earlier failure logs are retained.
- Two immutable ELF comparisons pass the shared strict program metadata check,
  including ordered DT_NEEDED vectors: libssl.so.35, libcrypto.so.35,
  libpcap.so.8, libutil.so.10, libc.so.7. PIE, RELRO/NOW, imports/version contracts,
  and absence of text relocations, search paths, executable stack and writable/
  executable loads match Make. Full linked/debug byte identity and full ABI
  equivalence remain unqualified.
- Ten actual program objects match raw text, fifteen raw constant sections and
  ordered macro/warning vectors. All 1,014 observed physical source/sysroot
  prerequisite hash checks match the native action inputs (162 unique inputs).
  Both five-object and thirteen-private-archive link orders match the original
  recorded Make recipes. All 7,070 raw nondebug relocation records match,
  including numeric symbol indices and addends.
- The default native program and both crypto archives are byte-identical to
  earlier immutable captures. Its six provisional object/parameter snapshots
  match the earlier actual execution inputs/outputs exactly; the old receipt
  and full execution log hashes are retained. The current default execution log
  is empty. An initial audit requiring fresh action rows correctly rejected it;
  no cached result is presented as a fresh compilation. No-EAPOL actions are
  bound to their current execution log.
- Both native install archives match ten independent Make installation records
  each: type, owner/group, mode, package/debug tags, tar metadata, both manual
  payloads and all three example payloads. Native and Make debug-link CRCs both
  validate for each configuration (four CRC checks total). This is component
  install qualification, not final pkg archive/dependency composition.
- Hashed retained test logs report four safe unittest methods per configuration,
  eight total. Bazel XML has one wrapper case per configuration. Default reused
  the earlier successful test report. Help, version and illegal-option branches
  return before interface/driver setup. The loader check requires every DSO to
  come from declared native runfiles, including pcap/OFED/thread dependencies.
  Tests run without root and do not activate an access point.

Primary reports: bazel-wpa-aes-ctr-hostapd-elf-audit-20261102/report.json;
bazel-wpa-aes-ctr-hostapd-openssl-eapol-object-audit-r2-20261102/report.json;
bazel-wpa-aes-ctr-hostapd-openssl-noeapol-object-audit-r1-20261102/report.json;
the corresponding install/relocation audit reports; and
bazel-wpa-aes-ctr-hostapd-test-log-audit-20261102.json. Earlier default r1 analysis
rejected an unused include root; r2 passed after removing only that unused root,
retaining all observed headers. Earlier successful evidence stays separate.

## Open gates

Independent internal-backend Make consumers still fail on enabled SAE/EHT and
other crypto APIs missing from that backend. No feature has been disabled to
force success. Internal archive construction is not consumer qualification.
IPv6-disabled, examples-disabled and other packaging/configuration profiles need
separate hostapd qualification. Cross-userland, live control sockets, root driver
initialization, WLAN association/authentication/EAP behavior, full pkgbase/system
composition/boot and controlled performance remain open. wpa_supplicant remains
the fifth program to convert; four programs have bounded native qualification.

The five program sources have no recognized direct SDT/DTrace/audit/FIDL calls
in the recorded call-shaped scan. Shared instrumentation, daemon security-event
delivery and audit policy require runtime review; no invented probes were added.

Existing typed openssl/wpa_supplicant_eapol/inet6/examples settings and explicit
targets cover the maintained build-bsd workflow. No frontend C, backend,
staging/signing/verification/publication or manual API changes are introduced.
Make remains production/default. Compact execution evidence and configured
execution-tool cache analysis remain tracked system-scale gates.
