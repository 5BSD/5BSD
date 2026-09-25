# Contributing to 5BSD

5BSD is developed at [github.com/5BSD/5BSD](https://github.com/5BSD/5BSD).
Send pull requests against the `dev` branch. `main` receives what has been
built, packaged and booted from `dev`.

FreeBSD's [contribution guide](https://docs.freebsd.org/en/articles/contributing/)
and [developer's handbook](https://docs.freebsd.org/en/books/developers-handbook/)
still apply to the parts of the tree 5BSD has not changed, and style(9)
applies everywhere. Changes to inherited FreeBSD code that are not specific
to 5BSD are better sent upstream first.

## Before you change something

Read the chapter of [The 5BSD Epic](docs/book/) that covers the area, and
the matching section of [`docs/5bsd-inventory.md`](docs/5bsd-inventory.md),
which lists what exists, where it lives, its man pages and its tests. Most
mistakes in this tree have been made by working from memory of how a
subsystem used to be.

## Rules that are not negotiable

**Current names only.** The plane has been renamed more than once. The
canonical names are in the book's
[Glossary of Names](docs/book/src/appendix/glossary.md), which also lists
every retired name. A retired name may appear in code, a comment, a man
page or a document only in an explicit "renamed from" note. This includes
package names, unit names, wire names and file paths.

**Authority is a held capability.** New code must not decide what a caller
may do from its uid, its pid, a path it opened or the peer credentials on
a socket. It asks for a capability by name over the lookup channel and
acts on what it was handed. Where a uid check is unavoidable during the
migration, mark it as transitional in a comment and in the chapter.

**Fail soft.** A component that needs a capability acquires it lazily and
retries; it never exits because a provider is down.

**Born in capability mode.** A new system daemon starts in capability mode
from its first instruction, gets its directories and devices delivered by
switchboard, logs through liblogcmp rather than syslog, and declares any
privileged operation as a system gate in its manifest.

**Tests.** Anything that touches the trusted computing base, capsule,
switchboard, BSDAuth, BSDFilesystem, the kernel framework or a policy
module, comes with positive, negative, adversarial and lifecycle tests.
Provider changes update the provider's `provider_test`. Kernel changes that
can only be observed on a live plane are validated in the VM rig described
in [Testing](docs/book/src/develop/testing.md), and the commit message says
what was run and what it showed. A skipped privileged test is not a pass.

**Documentation is part of the change.** If a change alters a man page's
truth, the man page changes in the same commit. If it alters what a book
chapter says, the chapter changes too. `mandoc -Tlint` must be clean.
Documents describe committed, tested code; designed or partly delivered
work carries an explicit Status paragraph.

## Commit messages

One change per commit. The first line names the subsystem and the change;
the body says what was wrong, what the change does, and how it was
verified, in plain sentences. Reference commit hashes when a change reverts
or completes an earlier one.

## Kernel changes

The capability framework lives in `sys/dev/mac_capability/` and is compiled
into GENERIC; there is no separate kernel configuration. Policy modules are
static and boot-only. New MAC hooks follow the patterns in
`sys/security/mac/mac_policy.h` and are recorded in
`docs/macf-new-hooks.md`. Out-of-tree modules should note the KPI changes
listed in the book's [BSD Side](docs/book/src/compat/bsd-side.md) chapter.

## Packages

Every installed file carries a `PACKAGE=` tag, every package has a
`packages/<name>/Makefile` and a description under
`release/packages/ucl/`, and tests ship as `<name>-tests`. A bundle's
package owns its `/Capabilities` directories. See
[Packaging and Shipping](docs/book/src/develop/packaging.md).
