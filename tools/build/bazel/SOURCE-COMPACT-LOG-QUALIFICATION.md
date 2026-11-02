# Source graph compact execution-log qualification

## Maintained interface (2026-11-02)

Format 5 now accepts the existing format-3/4 execution-log-format choice: json
(the unchanged default) or compact. Invalid values are rejected. The normal
build-bsd bazel-test backend passes exactly the corresponding Bazel log flag;
configured test-inventory cquery removes both log flags. Test selection, SDK
validation, source input hashes, artifact capture, sandbox configuration and
Bazel caching policies are preserved.

The receipt retains execution_log_sha256 and adds execution_log with explicit
format, absolute pathname, byte size and the same SHA256. The file is hashed
once. There is no format sniffing, implicit JSON fallback or partial compact
parser. Bazel's upstream converter reconstructs JSON; execution_log.stream_objects
accepts its caller-owned text stream through the same bounded incremental parser
used by objects(path). The caller checks converter exit status and owns process/
stream cleanup. Malformed/truncated JSON remains an error.

The frontend C program needs no new option: its maintained JSON input/backend
interface already carries this configuration. Backend, manual, test declarations
and documentation are updated together. Make remains production/default; BIP
remains excluded. Compact mode is opt-in until wider qualification is complete.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-source-compact-log-test-r1-20261102 is a normal format-5 frontend run
  with 16 workers and an actual compact log. source_settings_test,
  source_test_inventory_test and execution_log_test all pass. Retained logs
  contain 10, nine and six unittest methods respectively: 25 methods total,
  distinguished from the three XML wrapper cases.
- bazel-source-compact-log-review-r1-20261102/audit.json binds the successful
  receipt, 145,491-byte compact log, actual upstream converter invocation,
  six source input hash bindings and all three spawned XML output digests to
  immutable retained reports. The configured inventory query contains neither
  execution-log flag and retains the requested test selection/settings.
- converter-current-bindings.json verifies all 189 recorded upstream converter
  inputs before and after use. Two historical bazel-bin alias paths were
  absent; their actual preserved execroot artifacts have exactly the recorded
  launcher/manifest bytes. The missing-alias revalidation result remains
  recorded; no old receipt is rewritten or missing path silently accepted.

The decoded spawn stream contains three uncached test-setup executions and
three separate XML-generation executions, all successful. Six TestRunner
records do not mean six test suites. Python launcher files are built-in
FileWrite products: they have immutable BEP captures but no SpawnExec producer
record. This test run does not establish new compiler object output parity.

The converter streamed 2,988,966 UTF-8 JSON bytes through the shared reader;
no expanded JSON file was materialized. The converter's command-scoped CPU,
maximum RSS and block I/O observations are retained in converter.stderr.
This is an integration/resource observation, not a matched Make/Bazel or
JSON/compact performance comparison and not whole-build memory accounting.
The prior upstream converter/libc experiment remains historical evidence;
its component coverage is not promoted to full-system qualification here.

## Remaining gates

Apply the option to subsequent component profiles and bind actual compiler,
linker, generated-source and artifact records with the upstream converter.
Retain correct cache provenance when an action is absent from a later log;
neither a cache hit nor a missing spawn proves a fresh compilation. Qualify
compact evidence/resource scaling and controlled CPU/memory/disk I/O/disk-use/
cache comparisons before full-system scale. Complete world/kernel/pkgbase,
hardware repository publication and VM/runtime gates remain open.

Upstream documents the compact format and converter at
https://bazel.build/remote/cache-remote (Comparing the execution logs).
