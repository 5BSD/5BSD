# SPDX-License-Identifier: BSD-2-Clause
# Local host integration: upstream deliberately uses system tools and paths.
# Bazel owns the candidate executable, source fixtures and temporary layout.
emulate -R zsh
setopt errexit nounset
export PATH=/bin:/usr/bin:/usr/local/bin
export HOME=$TEST_TMPDIR/home
export TMPPREFIX=$TEST_TMPDIR/zsh
mkdir -p "$HOME" "$TEST_TMPDIR/Src" "$TEST_TMPDIR/Test"
export ZTST_exe=$TEST_SRCDIR/$TEST_WORKSPACE/program-bin/$BSD_TEST_PROGRAM
export ZTST_srcdir=${1:h}
ln -s "$ZTST_exe" "$TEST_TMPDIR/Src/zsh"
ln -s "$2" "$TEST_TMPDIR/config.h"
ln -s "$3" "$TEST_TMPDIR/config.modules"
cd "$TEST_TMPDIR/Test"
typeset -a groups=( $ZTST_srcdir/*.ztst(N) )
(( $#groups > 0 )) || { print -u2 'no upstream zsh test groups found'; exit 1; }
export ZTST_testlist=${(F)groups}
print -r -- "Running $#groups unchanged upstream test groups; host UID=$UID"
exec "$ZTST_exe" +Z -f "$1"
