# ELF code signing: format revision and authority boundaries

This document describes the ELF-native revision under development. It is not a
claim of completed kernel/VM acceptance. See the workstream validation receipt
for the exact tested source and outstanding gates.

## What Apple implements

Mach-O's `LC_CODE_SIGNATURE` is a structured locator containing a file offset
and length. It locates an embedded SuperBlob, whose indexed components include
CodeDirectory, entitlement/requirement data, and a CMS signature. CodeDirectory
contains ordinary page-hash slots and special slots that bind related metadata.
The identity signer signs the CodeDirectory through CMS and includes the
certificate chain. Those certificates carry public keys; the private key is
never embedded. Ad-hoc signing emits no CMS identity signature. Validating a
signature is distinct from accepting its signer under a subsystem's policy.

Primary implementation references:

- [Mach-O locator](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h): `linkedit_data_command`, `LC_CODE_SIGNATURE`.
- [Signature discovery](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/machorep.cpp): `MachORep::signingData`.
- [CMS signer](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/signer.cpp): `signCodeDirectoryWithIdentity`.
- [CodeDirectory and SuperBlob](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h).
- [Kernel code-page validation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c): `cs_validate_page`.
- [Trust, self-signing, and nested code](https://developer.apple.com/library/archive/technotes/tn2206/_index.html): TN2206.

## Translation to ELF

ELF defines notes and section metadata, but not a universal executable code-signing
ABI. 5BSD therefore defines a versioned descriptor in `.note.5bsd.signature`, an
`SHT_NOTE` section with `SHF_ALLOC` clear. It is outside every program-header file
range. No load segment or program-header entry is added. Adding `PT_NOTE` to an
arbitrary linked image would require a spare program-header slot or relocation
of loader-visible metadata; the nonallocated section avoids that change.

A redundant EOF locator supports bounded discovery. The note and ELF section
table describe the signature, and both locators must agree. Recognizable partial, duplicate, contradictory, or malformed signing
metadata is an error, not a reason to try an external policy or unsigned fallback.
The signer completes all ELF metadata edits before calculating the signature.

Version 1 uses the fixed signing header and immediate policy bytes, adds an
authenticated original-header/length record, and describes the note through a
copied string table and section table. Only ELF section-table locator fields may
change in the original file prefix. Removal restores the authenticated original
ELF header and truncates to its recorded original length. Unchanged code/data
segment offsets remain valid. ELF32/ELF64 and both byte orders need coverage.

## Cryptography and trust

The format uses an Ed25519 signature over a domain-separated
SHA-256 hash of every file byte, treating only the signature field as zero. It
is not Apple's CMS or page-hash CodeDirectory format and does not claim their
certificate-chain or demand-paged verification features. A public Ed25519 key
inside the descriptor permits integrity checking without an enrollment lookup.
That key cannot enroll itself or grant platform/global capabilities.

`capimage_verify_integrity` checks consistency. Trusted verification additionally
matches a separately enrolled key. Switchboard's capability policy continues to
apply after those checks. A personally signed program may be valid without being
eligible for system privileges. Unsigned classic programs and personal bundles
remain supported. Self-signing is not the same as Apple's identity-free ad-hoc
signature: our personal signature still uses a key pair.

If every signing locator is deliberately removed, an in-file scheme cannot
distinguish that result from intentionally unsigned software. Trusted identities
that require a signature must enforce that requirement externally. This revision
does not implement the deferred immutable base or SIP-like process protections.

## Cache and tooling

The cache builder verifies a private snapshot of each signed source, restores
its exact pre-signing ELF header, and excludes appended signing metadata. It
records the original signed source size separately. The cache index authenticates separate SHA-256 digests of the complete
signed source and the extracted payload. The loader compares the source digest
returned by a kernel-verified handle with the index, keeping the handle until
mapping completes. It performs no ELF-header reconstruction. Unsigned sources
retain exact byte comparison. Each cache entry grows by 32 bytes; this is an
explicit cost, not a RAM-saving claim. Extraction yields an unsigned ELF with no pointers
into discarded signature metadata. The cache has its own integrity seal.

Ordinary ELF loading tolerated the previous trailer; the limitation was that
standard rewriting tools did not understand it. The note makes the metadata
inspectable with `readelf -S` and `readelf -n`. It does not make post-signing
`strip`, `objcopy`, debuglink changes, or arbitrary relinking signature-preserving.
Perform those transformations before signing. Removal and re-signing use
`capsign`, including recursive bundle operations and updated outer seals.

The ELF signature and cache formats are unreleased version 1. There is one
supported layout for each; no development-format readers or migration paths
are retained. Build readers, writers and signed artifacts as one coordinated
system generation. Unsupported format versions are rejected.

## Acceptance gates

- Shared bounded locator parser in libcapimage, kernel verification/PREPARE,
  and explicit-descriptor rtld verification; same malformed-input corpus.
- Native inspection, exact remove/re-sign round trips, final-strip ordering,
  metadata and key tampering, two-key authority separation, recursive bundles.
- Cache packing/extraction and runtime comparison with no signature metadata
  copied into cache payloads and no stale section-table pointers.
- Actual matching-kernel exec/fexec/open/mmap/descriptor-load tests, pinned-handle
  lifetime tests, ordinary unsigned execution, and personal enrollment tests.
- Strict builds and explicit source/stage provenance. No RAM-savings or latency
  claim is inferred from format acceptance.
