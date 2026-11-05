#!/bin/sh -
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2013 Garrett Cooper
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

set -e

# -s emits reproducible header contents to stdout using explicit source inputs.
stdout=no
case "$#:$1" in
0:) ;;
1:-s)
    stdout=yes
    : "${NEWVERS_SH:?stdout mode requires NEWVERS_SH}"
    : "${PARAMFILE:?stdout mode requires PARAMFILE}"
    : "${NEWVERS_COPYRIGHT:?stdout mode requires NEWVERS_COPYRIGHT}"
    : "${NEWVERS_COPYRIGHT_TEMPLATE:?stdout mode requires NEWVERS_COPYRIGHT_TEMPLATE}"
    ;;
*) echo "usage: mk-osreldate.sh [-s]" >&2; exit 1 ;;
esac
if [ "$stdout" = yes ]; then
    copyright_query=-C
else
    NEWVERS_SH=${NEWVERS_SH:-$(pwd)/../sys/conf/newvers.sh}
    copyright_query=-c
    ${ECHO:=echo} creating osreldate.h from newvers.sh
fi
COPYRIGHT=$(sh "$NEWVERS_SH" "$copyright_query") || exit 1
version=$(sh "$NEWVERS_SH" -V RELDATE) || exit 1
case "$version" in
'RELDATE="'*'"') RELDATE=${version#RELDATE=\"}; RELDATE=${RELDATE%\"} ;;
*) echo "Invalid RELDATE query result" >&2; exit 1 ;;
esac
case "$RELDATE" in
""|*[!0-9]*) echo "Invalid RELDATE value" >&2; exit 1 ;;
esac
emit_header()
{
    printf '%s\n' "$COPYRIGHT" '#ifdef _KERNEL' \
        '#error "<osreldate.h> cannot be used in the kernel, use <sys/param.h>"' \
        '#else' '#undef __FreeBSD_version' "#define __FreeBSD_version $RELDATE" '#endif'
}
if [ "$stdout" = yes ]; then
    emit_header
    exit 0
fi
tmpfile=$(mktemp osreldate.XXXXXXXX)
trap 'rm -f "$tmpfile"' EXIT
emit_header > "$tmpfile"
chmod 644 "$tmpfile"
mv -f "$tmpfile" osreldate.h
