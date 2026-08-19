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

## Conventions

- One chapter per file; each file starts with a single `# Title`.
- Chapters describe committed, tested code. Components that are designed
  but not yet delivered carry an explicit **Status** note.
- Paths in code spans (`sys/dev/mac_capability/`) refer to this source tree.
- Unmodified base-system behavior is documented by the
  [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/), not
  repeated here. Where 5BSD diverges from FreeBSD, this book is the source
  of truth.
