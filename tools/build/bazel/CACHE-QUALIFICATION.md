# Bazel cache qualification gates

The candidate graph is not cache-qualified until the actual supported Bazel
version executes these checks. A generator byte comparison, a parsed BUILD
file, a repository download cache, and a successful build do not individually
prove action-cache correctness or useful incremental behavior.

## Required evidence

Retain the configured target/action graph (cquery/aquery structured output),
execution records, command lines, tool/config/source hashes, output hashes,
selected cache locations and measured resource use for each run. Separate
repository downloads from cached build actions. Distinguish local up-to-date
results, local disk cache hits and remote cache hits; do not label one another.
Do not infer cache hits solely from elapsed time or identical output bytes.

## Run matrix

| Change or run | Required result |
| --- | --- |
| Fresh output base and empty action cache | All required outputs built and independently checked against Make. |
| Repeat without changes | No compiler, generator, archiver or linker execution; outputs unchanged. |
| Delete outputs/use a fresh output base with a populated disk cache | Outputs restored from cached actions, without recompilation. |
| Same source/config at another workspace location | Check cache reuse and byte reproducibility; identify absolute path/debug-directory leakage. |
| Edit one C source | Its affected compilation actions and dependent archive/link actions update; unrelated compilation stays reusable. |
| Edit an included header | Every actual consumer rebuilds; outputs/behavior demonstrate the new input took effect. |
| Edit an unused header or unrelated file | No unrelated compilation executes; document any conservative dependency invalidation. |
| Edit generator template/script/parameters | Affected generation and downstream compilation update. |
| Change cat only | Manual generation changes its action key; high-level C generators do not depend on cat. |
| Edit symbol map/version definitions | Version generation and dependent links update. |
| Change compiler/linker/archiver or relevant SDK input | Every affected action invalidates; no silent host-tool fallback. |
| Change maintained flags, assembly selection, target or ABI | Action graph reflects supported semantics, or explicitly rejects unsupported settings. |
| Change ambient PATH, HOME or locale | Declared tool selection and output behavior remain controlled. |
| Edit original source and refresh exported workspace | New source bytes reach Bazel; a stale snapshot is never reported as a current build. |
| Corrupt an output/cache object | Never accept incorrect installed artifacts; record recovery/failure behavior. |

Run mutations only in private source/workspace copies and restore them with
hash checks. Include both positive invalidation and negative controls. Compare
installed inventory, modes, ownership, debug splits, links and package metadata;
cached raw library outputs do not establish installation/package parity.

## Boundaries still requiring proof

The current exporter creates a source snapshot. Developer edits outside that
snapshot cannot invalidate Bazel actions automatically. Maintained frontend
integration must refresh and validate inputs before each requested build, while
preserving stable action identities and useful cache reuse. Qualification-only
fresh-directory helpers are not an incremental developer build interface.

Declared dynamic-runtime copies do not redirect the host ELF loader. Prefer
verified static execution tools or qualify and bind the actual execution
platform. FreeBSD execution isolation and remote execution must be qualified
separately; do not assume Linux sandbox behavior. Source/SDK file lists must
cover real dependencies without feeding the whole source tree to every action.

Measure cold build, unchanged rebuild, representative edit and cache restore:
wall time, CPU, peak process/guest/host memory, bytes read/written, disk growth,
and action counts. Use the same CPU/RAM budgets and comparable Make baselines.
Record regression limits before evaluating results. Retain Make as the
production backend until complete world/kernel/package parity is established.
