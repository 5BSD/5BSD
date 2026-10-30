# SPDX-License-Identifier: BSD-2-Clause
printf '1..1\n'
if [ "$(uname)" = 'declared candidate selected' ]; then
    printf 'ok 1 - declared executable overrides host name\n'
else
    printf 'not ok 1 - host executable or missing candidate\n'
fi
