# Libuv application compatibility — September 26, 2026

**The tested libuv filesystem and epoll paths work. Synchronous cancellation
still has an application-visible race when enabled.** This qualification adds
a reproducible application check; it makes no kernel change and does not claim
general Node, Bun, database, or io_uring compatibility.

The same static Linux executable links unmodified libuv 1.53.0 on Linux
6.18.35-0-virt and the previously qualified hard-link-only candidate kernel.
The candidate normally advertises Linux 5.15.0. A second profile temporarily
sets `compat.linux.osrelease=6.18.35` **inside the disposable VM** to exercise
paths that libuv otherwise excludes by version. The installed host's identity
and kernel were not changed.

## Results

| Profile | Filesystem, epoll, and cancellation checks in default/SQPOLL modes | Additional SQPOLL cancellation repetitions |
|---|---|---|
| Linux 6.18.35 | 6/6 pass | 20/20 pass |
| Candidate, advertised 5.15.0 | 6/6 pass | Not repeated: libuv excludes synchronous ring cancellation at this version |
| Candidate, diagnostic 6.18.35 | 6/6 pass in final run | **8 pass, 12 fail out of 20** |

An earlier run also failed the diagnostic profile's single cancellation check.
It is preserved separately. Passing a later single run does not resolve the
reproducible race.

Each repetition submits 32 asynchronous, 64-byte regular-file reads and attempts
to cancel each before running the event loop. The candidate failures report
`cancel=0 completion=64`: `uv_cancel()` reports success, but the request completes
with a successful read. All 12 failed repetitions have this mismatch. Libuv's
[documented filesystem cancellation contract](https://github.com/libuv/libuv/blob/v1.53.0/docs/src/request.rst)
requires a successfully cancelled filesystem request to report `UV_ECANCELED`.
The test accepts `UV_EBUSY` when a read has already executed, and checks its data.
The exception documented for `uv_write_t` does not apply to these `uv_fs_t` reads.

All five candidate resource counters returned to zero after each profile:
live requests, registered files, issuer references, issuer tokens, and wired
pages. There was no panic, ZFS reported healthy pools, and shutdown completed
cleanly. A failed cancellation assertion exits its process; successful cases
also explicitly verify `uv_loop_close()`.

## Verified application behavior

The filesystem case verifies create/open, write, fsync, read with byte-for-byte
comparison, stat/fstat/lstat metadata, truncate, close, rename, hard link,
symbolic link, unlink, missing-path errno, and directory removal. Default mode
uses the thread pool for all 18 filesystem operations, as a control.

With SQPOLL enabled, the candidate's advertised identity uses the ring for 15
operations. Close and truncate use libuv's version-selected thread-pool paths;
directory removal always uses the pool. With the diagnostic identity, 17
operations use the ring, matching Linux. **No submitted filesystem operation
retries through the pool in these runs.** The observer checks the actual CQE's
request identity and result against the callback, including detection of
`EOPNOTSUPP` fallback, without changing libuv source.

The epoll case repeatedly creates socket pairs, receives readiness callbacks,
closes the descriptors, and reuses descriptor numbers. Each case receives 32
callbacks and records 34 actual io_uring epoll submissions. These checks cover
libuv's normal epoll batching as well as its explicitly enabled SQPOLL mode.

## Next compatibility work

The concrete next target is cancellation of requests that race with execution.
Current source inspection suggests a relevant boundary: `sq_cancel_req()` can
accept cancellation of an issuing request, while the issuing path preserves a
successful I/O result. That is a hypothesis consistent with the observed
failure, not a verified kernel fix. Return values, completion ordering, partial
I/O, synchronous waiting, and request ownership need to be handled together.
Overwriting a completed transfer's result with `ECANCELED` would not establish
correct semantics.

The [previous stream/cancellation teardown failure](fixes-20260926.md) also
remains unresolved. This harness does not exercise blocked stream reads or
prove that blocked-I/O cancellation is safe. No optional device backend is
required to investigate either issue. Application qualification should continue
with named workloads once these shared behaviors are reliable.

## Evidence and reproduction

The candidate kernel SHA-256 is
`e5f5b7d4ec2dfde4cd2a8d41a0523912c0e42b9f4aaadda7b503ca138a7be8e6`.
It is the same kernel used for the final hard-link verification, not a build of
the concurrently edited working tree. Candidate files reside on ZFS; Linux uses
tmpfs. Both VMs use four emulated CPUs under QEMU TCG; candidate RAM is 1.5 GiB
and Linux RAM is 1 GiB. These are correctness checks, not performance results.

- [Build and invocation instructions](README.md#libuv-application-compatibility)
- [Pinned build commands and hashes](libuv-build-manifest-20260926.json)
- [Individual results, run scripts, and evidence hashes](libuv-results-20260926.json)
- [Final candidate console](evidence-20260926/libuv-candidate.log.gz)
- [Final Linux console](evidence-20260926/libuv-oracle.log.gz)
- [First cancellation failure](evidence-20260926/libuv-cancellation-first-failure.log.gz)

After the six-case harness, the diagnostic candidate and Linux each run
`libuv-compat sqpoll cancel` in 20 fresh processes, with a 45-second timeout per
process. The per-request diagnostics record cancellation return values and
completion results. The JSON preserves the exact commands and the earlier
failure's executable/source hashes. No failure or timeout is converted to a
pass by the VM's completion marker.
