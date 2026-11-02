#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# base-accounts -- create base-system groups and users that an installed
# system is missing.
#
# /etc/group and /etc/master.passwd are package configuration files.  When an
# administrator has changed them, pkg(8) cannot always merge a new base
# release into them and leaves the new versions as .pkgnew files, so a group
# or user introduced by the release (for example audio, gid 43) never appears.
# The runtime package installs a pristine copy of the shipped account files
# under /usr/share/base-accounts and runs this tool after every install or
# upgrade.  It only adds entries: existing local entries are never modified or
# removed, and an entry whose name is free but whose numeric id is already used
# locally is refused, not renumbered.

set -u

PROG=base-accounts
ROOT=/
REFDIR=
STATE=
DRYRUN=false
ALL=false
QUIET=false
VERBOSE=false
PW=${BASE_ACCOUNTS_PW:-/usr/sbin/pw}

usage()
{
	echo "usage: $PROG [-anqv] [-R rootdir] [-r refdir]" >&2
	exit 64
}

msg()
{
	$QUIET || echo "$PROG: $*"
}

vmsg()
{
	$VERBOSE && echo "$PROG: $*"
	return 0
}

warn()
{
	echo "$PROG: $*" >&2
}

while getopts "anqR:r:v" opt; do
	case "$opt" in
	a) ALL=true ;;
	n) DRYRUN=true ;;
	q) QUIET=true ;;
	R) ROOT=$OPTARG ;;
	r) REFDIR=$OPTARG ;;
	v) VERBOSE=true ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage

ROOT=${ROOT%/}
[ -n "$ROOT" ] || ROOT=/
if [ "$ROOT" = / ]; then
	R=
else
	R=$ROOT
fi
[ -n "$REFDIR" ] || REFDIR=$R/usr/share/base-accounts
STATE=$R/var/db/base-accounts
ETC=$R/etc

for f in "$REFDIR/group" "$REFDIR/master.passwd"; do
	if [ ! -r "$f" ]; then
		warn "cannot read reference file $f"
		exit 66
	fi
done
for f in "$ETC/group" "$ETC/master.passwd"; do
	if [ ! -r "$f" ]; then
		warn "cannot read local account file $f"
		exit 66
	fi
done

# The accounts each release introduced.  A source tree (-r /usr/src/etc)
# keeps the list elsewhere; use the installed one.
INTRODUCED=$REFDIR/introduced
[ -r "$INTRODUCED" ] || INTRODUCED=$R/usr/share/base-accounts/introduced
if [ ! -r "$INTRODUCED" ]; then
	vmsg "no list of introduced accounts; a first run creates none"
	INTRODUCED=/dev/null
fi

# Print the name and id fields of the real entries in an account file:
# comments, blank lines and NIS +/- compatibility entries are not accounts.
entries()
{
	awk -F: '/^[[:space:]]*(#|$)/ || /^[+-]/ { next } { print $1, $3 }' "$1"
}

# Name of the local entry in FILE with id ID, or nothing.
name_of_id()
{
	awk -F: -v id="$2" '/^[[:space:]]*(#|$)/ || /^[+-]/ { next }
	    $3 == id { print $1; exit }' "$1"
}

# Id of the local entry in FILE named NAME, or nothing.
id_of_name()
{
	awk -F: -v n="$2" '/^[[:space:]]*(#|$)/ || /^[+-]/ { next }
	    $1 == n { print $3; exit }' "$1"
}

# Was KIND:NAME in the base system before and removed by the administrator?
# The state file records what the last run reconciled.  Without one (the
# first run) a missing entry is taken to have been removed unless the
# reference lists it as introduced by a release, which an upgraded system
# cannot have had.
removed()
{
	$ALL && return 1
	if [ -r "$STATE" ]; then
		grep -qxF "$1:$2" "$STATE"
		return
	fi
	! awk -v k="$1" -v n="$2" '/^[[:space:]]*(#|$)/ { next }
	    substr($1, 1, 1) == k && $2 == n { found = 1; exit }
	    END { exit !found }' "$INTRODUCED"
}

pw_run()
{
	if [ -n "$R" ]; then
		"$PW" -R "$R" "$@"
	else
		"$PW" "$@"
	fi
}

created=0
refused=0
skipped=0
recorded=

record()
{
	recorded="$recorded$1:$2
"
}

# Groups first: a missing user's primary group may be one of them.
while read -r name gid; do
	[ -n "$name" ] || continue
	local_gid=$(id_of_name "$ETC/group" "$name")
	if [ -n "$local_gid" ]; then
		[ "$local_gid" = "$gid" ] || vmsg "keeping local group $name" \
		    "(gid $local_gid; the base system uses gid $gid)"
		record g "$name"
		continue
	fi
	if removed g "$name"; then
		vmsg "group $name was removed locally; not recreating it"
		record g "$name"
		skipped=$((skipped + 1))
		continue
	fi
	owner=$(name_of_id "$ETC/group" "$gid")
	if [ -n "$owner" ]; then
		warn "REFUSED group $name (gid $gid): gid $gid belongs to local" \
		    "group $owner; resolve the conflict by hand"
		refused=$((refused + 1))
		continue
	fi
	# Members are added only when they already exist; existing groups and
	# users are never changed.
	members=
	for m in $(awk -F: -v n="$name" '$1 == n { gsub(",", " ", $4);
	    print $4; exit }' "$REFDIR/group"); do
		if [ -n "$(id_of_name "$ETC/master.passwd" "$m")" ]; then
			members="${members:+$members,}$m"
		else
			vmsg "group $name: member $m does not exist; not adding it"
		fi
	done
	if $DRYRUN; then
		msg "would create group $name (gid $gid)"
	elif pw_run groupadd "$name" -C /dev/null -g "$gid" ${members:+-M "$members"}; then
		msg "created group $name (gid $gid)"
	else
		warn "FAILED to create group $name (gid $gid)"
		refused=$((refused + 1))
		continue
	fi
	created=$((created + 1))
	record g "$name"
done <<EOF
$(entries "$REFDIR/group")
EOF

while IFS=: read -r name pass uid gid class change expire gecos home shell; do
	case "$name" in
	''|'#'*|'+'*|'-'*) continue ;;
	esac
	local_uid=$(id_of_name "$ETC/master.passwd" "$name")
	if [ -n "$local_uid" ]; then
		[ "$local_uid" = "$uid" ] || vmsg "keeping local user $name" \
		    "(uid $local_uid; the base system uses uid $uid)"
		record u "$name"
		continue
	fi
	if removed u "$name"; then
		vmsg "user $name was removed locally; not recreating it"
		record u "$name"
		skipped=$((skipped + 1))
		continue
	fi
	# Never create a superuser alias or an account without a password
	# field; root and toor are the administrator's business.
	if [ "$uid" = 0 ] || [ -z "$pass" ]; then
		vmsg "not creating privileged account $name (uid $uid)"
		record u "$name"
		skipped=$((skipped + 1))
		continue
	fi
	owner=$(name_of_id "$ETC/master.passwd" "$uid")
	if [ -n "$owner" ]; then
		warn "REFUSED user $name (uid $uid): uid $uid belongs to local" \
		    "user $owner; resolve the conflict by hand"
		refused=$((refused + 1))
		continue
	fi
	if [ -z "$(name_of_id "$ETC/group" "$gid")" ] && ! $DRYRUN; then
		warn "REFUSED user $name (uid $uid): primary gid $gid does not" \
		    "exist"
		refused=$((refused + 1))
		continue
	fi
	if $DRYRUN; then
		msg "would create user $name (uid $uid, gid $gid)"
	elif printf '%s\n' "$pass" | pw_run useradd "$name" -C /dev/null \
	    -u "$uid" -g "$gid" -c "$gecos" -d "$home" -s "$shell" \
	    ${class:+-L "$class"} -H 0; then
		msg "created user $name (uid $uid, gid $gid)"
		[ "${change:-0}" = 0 ] && [ "${expire:-0}" = 0 ] || \
		    warn "user $name: password aging fields were not copied"
	else
		warn "FAILED to create user $name (uid $uid)"
		refused=$((refused + 1))
		continue
	fi
	created=$((created + 1))
	record u "$name"
done < "$REFDIR/master.passwd"

if ! $DRYRUN; then
	if mkdir -p "${STATE%/*}" && printf '%s' "$recorded" | sort -u \
	    > "$STATE.new" && mv -f "$STATE.new" "$STATE"; then
		:
	else
		rm -f "$STATE.new"
		warn "cannot record reconciled accounts in $STATE"
	fi
fi

if [ $refused -gt 0 ]; then
	warn "$refused base account(s) could not be created; see above"
	exit 2
fi
if $DRYRUN; then
	vmsg "$created to create, $skipped skipped"
else
	vmsg "$created created, $skipped skipped"
fi
exit 0
