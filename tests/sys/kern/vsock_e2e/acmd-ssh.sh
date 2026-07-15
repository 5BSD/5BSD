#!/bin/sh
# ACMD adapter for run-linux.sh.  Configure ALPINE_HOST and, if needed,
# ALPINE_USER/SSH_IDENTITY.
set -eu

command=${1:?guest command required}
limit=${2:-30}
host=${ALPINE_HOST:?set ALPINE_HOST to the Alpine guest address}
user=${ALPINE_USER:-root}

if [ -n "${SSH_IDENTITY:-}" ]; then
	exec timeout "$limit" ssh -i "$SSH_IDENTITY" \
	    -o BatchMode=yes -o ConnectTimeout=5 \
	    -o StrictHostKeyChecking=accept-new \
	    "$user@$host" "$command"
fi

exec timeout "$limit" ssh \
    -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
    "$user@$host" "$command"
