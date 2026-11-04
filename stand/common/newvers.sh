#!/bin/sh -
#
#	$NetBSD: newvers.sh,v 1.1 1997/07/26 01:50:38 thorpej Exp $
#
# Copyright (c) 1984, 1986, 1990, 1993
#	The Regents of the University of California.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# Tool overrides and an explicit output let native build actions declare every
# executable and artifact. Ordinary Make callers retain the same defaults.
version_output=vers.c
include_metadata=true
while getopts ro: opt; do
	case "$opt" in
	r)
		include_metadata=
		;;
	o)
		version_output=$OPTARG
		;;
	*)
		exit 1
		;;
	esac
done
shift $((OPTIND - 1))
if [ "$#" -ne 3 ]; then
	printf 'usage: %s [-r] [-o output] version-file description machine\n' "$0" >&2
	exit 1
fi

LC_ALL=C; export LC_ALL
# Reproducible output does not consume date, user or host metadata.
if [ -n "$include_metadata" ]; then
	u=${USER-root} h=${HOSTNAME-`hostname`}
	if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
		if ! t=$(date -ur "$SOURCE_DATE_EPOCH" 2>/dev/null); then
			echo "Invalid SOURCE_DATE_EPOCH" >&2
			exit 1
		fi
	else
		t="${NEWVERS_DATE:-`date`}"
	fi
fi
r=$("${NEWVERS_AWK:-awk}" -F: ' /^[0-9]\.[0-9]+:/ { print $1; exit }' "$1")
if [ -z "$r" ]; then
	echo "Missing loader revision" >&2
	exit 1
fi

bootprog_info="5BSD/${3} ${2}, Revision ${r}\\n"
if [ -n "$include_metadata" ]; then
	bootprog_info="$bootprog_info(${t} ${u}@${h})\\n"
	if [ -n "${BUILD_UTC:-}" ]; then
		# We can use what(1) to extract BUILD_UTC
		bootprog_info="$bootprog_info\\0@(#)BUILD_UTC=$BUILD_UTC"
	fi
fi

tempfile=$("${NEWVERS_MKTEMP:-mktemp}" "${version_output}.XXXXXX") || exit
trap '"${NEWVERS_RM:-rm}" -f "$tempfile"' EXIT INT TERM
"${NEWVERS_CAT:-cat}" > "$tempfile" <<EOF
char bootprog_info[] = "$bootprog_info";
unsigned bootprog_rev = ${r%%.*} * 1000 + ${r##*.};
EOF
"${NEWVERS_MV:-mv}" "$tempfile" "$version_output"
