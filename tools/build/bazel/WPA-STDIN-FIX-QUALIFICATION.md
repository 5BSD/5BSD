# wpa_passphrase stdin cleanup — 2026-11-02

Source review found two existing issues in the stdin path:

- ENOTTY jumps past `term` initialization, but the old code subsequently reads
  and modifies `term.c_lflag` even when input is a pipe.
- When `fgets` fails or reaches EOF on a terminal, the old early return skips
  restoring echo after the program disabled it.

The focused source change records the input result, restores echo only when the
input is a terminal whose original echo state was enabled, and then reports read
failure. It retains the existing output, password derivation and error statuses.
No user terminal, host configuration or hardware was modified.

`usr.sbin/wpa/wpa_passphrase/stdin_test.py` runs six methods as a non-root user:
argument input, pipe input, pipe EOF, and disposable PTYs with echo on, echo off,
and EOF. It derives the expected key independently with Python's PBKDF2-HMAC-SHA1,
4096 iterations and 32-byte output, matching the maintained tool contract. Every
PTY is private to the test, every child has a deadline and cleanup, and the echo
state is checked after exit. The test accepts explicit program/library-directory
inputs for Make qualification and can use declared runfiles in the upcoming
native target. The native WPA BUILD graph is not implemented by this commit.

Evidence under `/usr/obj/usr/src`:

- `bazel-wpa-utils-make-r1-20261102` and
  `bazel-wpa-crypto-make-r1-20261102`: fresh post-upgrade independent Make private
  archive builds (regular and PIE), no host installation.
- `bazel-wpa-passphrase-make-r1-20261102`: fresh maintained Make compilation,
  with explicit documented LIBWPAUTILSDIR/LIBWPACRYPTODIR and corresponding
  archive variables. The queried DPADD, LDADD and actual Make link metadata all
  select those newly built PIE archives; archive/source hashes and commands are
  retained. No helper accepts arbitrary production Make overrides.
- `bazel-wpa-passphrase-stdin-make-20261102.log`: all six methods pass against
  that actual Make-built executable and explicit staged runtime libraries.
- `bazel-wpa-stdin-original-negative-r2-20261102`: an isolated negative fixture
  from the original source at `a28f294501e`, compiled with the captured Make
  recipe and fresh private archives. It fails exactly the TTY EOF echo-restore
  assertion while the other five methods pass. This fixture is a regression
  input, never a replacement production or parity output. The original first
  preparation failed because `/usr/bin/git` does not exist; it is retained
  separately, and r2 resolves the actual available Git executable.

The pipe uninitialized-value defect is established by the source control flow;
these tests are not a memory-sanitizer claim. The EOF case is a demonstrated
before/after runtime regression. Native source/library/configuration/install
qualification and remaining WPA programs are separate ongoing work. Make is
still the production/default backend. Existing source build targets pick up
this ordinary source fix without new frontend options or backend dispatch.
