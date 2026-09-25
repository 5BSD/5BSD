# The 5BSD Epic

This directory is an [mdBook](https://rust-lang.github.io/mdBook/) source
tree. The chapters are plain Markdown under `src/` and render directly on
GitHub; `SUMMARY.md` is the table of contents.

## Building

```sh
pkg install mdbook          # mdbook is in the FreeBSD package collection
cd docs/book
mdbook build                # output in book/
mdbook serve --open         # live-reload preview on http://localhost:3000
```

## Publishing

`.github/workflows/handbook.yml` builds the Epic and deploys it to GitHub
Pages on every push to `main` that touches `docs/book/`.

## Structure

Seven parts plus appendices, in `SUMMARY.md`: Orientation, The Capability
System (kernel), The Plane (userland runtime), System Capabilities
Reference (one chapter per provider on a fixed template), Backward
Compatibility (including Linux emulation), Writing Software for 5BSD, and
Operations. `docs/5bsd-inventory.md` is the divergence inventory the book
is scoped from; every chapter is written against the tree at its commit.
The Glossary of Names in the appendix is the canonical-name list every
chapter must follow.

## Conventions

- One chapter per file; each file starts with a single `# Title`.
- Chapters describe committed, tested code. Components that are designed
  but not yet delivered carry an explicit **Status** note.
- Paths in code spans (`sys/dev/mac_capability/`) refer to this source tree.
- Unmodified base-system behavior is documented by the
  [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/), not
  repeated here. Where 5BSD diverges from FreeBSD, this book is the source
  of truth.
