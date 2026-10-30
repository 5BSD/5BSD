# NLM file identity regression

Status: syntax checked with host headers; not linked or executed yet. Run only in an
isolated disposable guest after normal NFS qualification setup is available.
This does not start a server, alter exports, mount storage, or relax BIP.

Build with the matching world headers and librpcsvc using this directory's
Makefile and the normal object tree. The fixture uses the installed NLMv4
protocol definitions/XDR routines, rather than a copied matching algorithm.

Inputs:

```
nlm-file-identity SERVER UNIQUE-CALLER-NAME FILE-A FILE-B [HARD-LINK-TO-A]
```

SERVER must name the NLM server in the same guest: the files are local server
paths, and the test obtains their handles with getfh. rpcbind, statd and lockd
must already be running, the grace period must have elapsed, and the files must
be in storage exported to the RPC peer. Loopback RPC must be allowed and the
server's callback NLM endpoint must be reachable. Run with getfh permission.
BIP currently blocks ordinary lockd admission; do not bypass that restriction
just to run this test. First use the ordinary-system qualification guest, then
repeat in hardened mode after its full NFS admission work is qualified.

For hard-link qualification, supply the optional fifth argument as an existing
hard link to FILE-A. The fixture requires the same device/inode, at least two
links and distinct canonical pathnames; it never creates the alias. All file
identities and ancestors must remain stable throughout this test. Without that
argument, only the original two-file case runs; it must not count as alias coverage.

Use two disposable regular files in an exclusively controlled test directory.
Their paths and ancestors must remain stable for the test; getfh resolves a
pathname independently from open. They must be different objects, writable under
the export's mapped RPC credentials, and free of other test activity. The tool
does not write file contents or unlink them. Use a fresh caller name to avoid
colliding with an existing NLM host entry. The guest must have no unrelated NLM
clients; this is not a production-host test.

The fixture holds a local POSIX byte-range lock on A and sends a blocking,
non-monitored NLMv4 request with a distinct remote lock owner. That request must
be queued. It then checks:

- A separate NLM owner initially observes B as unlocked.
- The identical client/PID/range/type tuple on unlocked B is granted.
- The separate owner then observes B as locked.
- CANCEL for B does not match the pending request on A.
- A duplicate request for A remains blocked.
- UNLOCK B and CANCEL A succeed; the separate owner observes B as unlocked
  after release.

With the hard-link input, the fixture additionally requires a request through
the alias to match A's queued lock. CANCEL through that alias must cancel A, and
CANCEL through A's original name must then report no queued request. The local
blocker remains held until remote cleanup finishes. Opening the alias before
acquiring the blocker and closing it only after cleanup avoids releasing POSIX
locks early through a second descriptor to the same file.

Client creation receives an explicit five-second RPC timeout, as does each
request. This is not a whole-process deadline; name resolution and multiple
transport attempts still require an outer guest-runner timeout. RPC errors and unexpected statuses fail the
test, including an unestablished initial blocked request. Cleanup cancels and
unlocks both requests before releasing the local blocker; unconfirmed cleanup
prevents success. An external kill or lost RPC reply can leave server state
uncertain, so retain diagnostics and discard the guest after a failed run.

Required qualification is a run against the pre-fix kernel demonstrating the
cross-file failure and against the corrected kernel demonstrating success,
with source/kernel hashes, complete output and clean guest shutdown. The optional hard-link case also needs actual guest execution. Additional
two-blocked-file, cancellation-race, protected-handle and reclaim cases remain
necessary. This fixture alone cannot establish working
NFS mounts, ordinary file I/O, cleanup authentication or root-resistant BIP.
