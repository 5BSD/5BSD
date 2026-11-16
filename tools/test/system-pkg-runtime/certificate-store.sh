#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Owned disposable-guest probe. No host execution or external network access.
set -eu
openssl=$1 certctl=$2 fetch=$3 bundle=$4 localdir=$5 port=$6 user=$7 uid=$8 work=$9
label=${work##*/}
localcert="$localdir/${label#.}.pem"
server=
created_directory=no
test -s "$bundle"
test ! -e "$localcert" && test ! -L "$localcert"
/bin/cp "$bundle" "$work/original-bundle"
cleanup()
{
    result=$?
    trap - EXIT HUP INT TERM
    if test -n "$server"; then
        kill "$server" 2>/dev/null || :
        wait "$server" 2>/dev/null || :
    fi
    if test -e "$localcert"; then
        /bin/rm "$localcert" || result=1
        "$certctl" rehash || result=1
    fi
    /usr/bin/cmp "$work/original-bundle" "$bundle" || result=1
    if test "$created_directory" = yes; then
        /bin/rmdir "$localdir" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
umask 077
export OPENSSL_CONF=/dev/null
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 1 -subj '/CN=Disposable runtime CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$work/ca.key" -out "$work/ca.pem"
"$openssl" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/server.key" -out "$work/server.csr"
"$openssl" x509 -req -days 1 -in "$work/server.csr" -CA "$work/ca.pem" \
    -CAkey "$work/ca.key" -CAcreateserial -copy_extensions copy -out "$work/server.pem"
"$openssl" s_server -accept "127.0.0.1:$port" -cert "$work/server.pem" \
    -key "$work/server.key" -www > "$work/server.log" 2>&1 < /dev/null &
server=$!
attempt=0
while ! /usr/bin/sockstat -4 -l -p "$port" | /usr/bin/awk -v pid="$server" \
    '$3 == pid { found = 1 } END { exit !found }'; do
    kill -0 "$server"
    attempt=$((attempt + 1))
    test "$attempt" -lt 100
    /bin/sleep 0.1
done
client()
{
    /usr/bin/su -m "$user" -c \
        'test "$(/usr/bin/id -u)" -eq "$3" && exec /usr/bin/env -i PATH=/bin:/usr/bin LC_ALL=C "$1" -T 10 -o /dev/null "$2"' \
        certificate-fetch "$fetch" "https://127.0.0.1:$port/" "$uid"
}
reject()
{
    if client > "$work/rejected.log" 2>&1; then
        echo 'Untrusted TLS server was accepted' >&2
        return 1
    fi
    /bin/cat "$work/rejected.log"
    /usr/bin/grep -qi 'certificate.*verif' "$work/rejected.log"
}
reject
printf 'BQL_TLS_UNTRUSTED_REJECTED\n'
if test ! -d "$localdir"; then
    /bin/mkdir -p -m 755 "$localdir"
    created_directory=yes
fi
/bin/cp "$work/ca.pem" "$localcert"
/bin/chmod 444 "$localcert"
"$certctl" rehash
client
printf 'BQL_TLS_LOCAL_CA_ACCEPTED\n'
/bin/rm "$localcert"
"$certctl" rehash
reject
printf 'BQL_TLS_REMOVED_CA_REJECTED\n'
/usr/bin/cmp "$work/original-bundle" "$bundle"
printf 'BQL_TLS_ORIGINAL_BUNDLE_RESTORED\n'
