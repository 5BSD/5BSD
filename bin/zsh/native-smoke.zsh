# SPDX-License-Identifier: BSD-2-Clause
# Noninteractive runtime coverage; upstream job-control/pty suites are separate.
emulate -R zsh
setopt errexit nounset pipefail
[[ $MACHTYPE == amd64 && $OSTYPE == freebsd ]]
zmodload zsh/mathfunc zsh/system zsh/parameter zsh/datetime zsh/stat
zmodload zsh/regex zsh/zpty zsh/zle zsh/complete zsh/complist
zmodload zsh/curses zsh/terminfo zsh/net/socket zsh/net/tcp
(( sqrt(81) == 9 ))
typeset -A mapping=(one 1 two 2)
[[ $mapping[two] == 2 ]]
typeset -a words=(alpha beta gamma)
[[ ${(j:,:)words} == alpha,beta,gamma ]]
[[ foobar =~ '^foo(bar)$' && $match[1] == bar ]]
[[ $signals[(Ie)TERM] -gt 0 && $errnos[(Ie)ENOENT] -gt 0 ]]
[[ $(print -r -- pipeline | while read -r value; do print -r -- $value; done) == pipeline ]]
( exit 7 ) && exit 1
[[ $? == 7 ]]
print -r -- 'zsh native runtime smoke passed'
