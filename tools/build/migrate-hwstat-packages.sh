#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Prepare installed telemetry package identities for the hwstat upgrade.
# Run after pkg update and immediately before pkg upgrade, in the target root.
set -eu

pkgcmd=${PKG:-pkg}
repository=${PKG_REPOSITORY:-5BSD-base}
prefix=${PKG_NAME_PREFIX:-5BSD}
pending=
prepared=

installed()
{
	if "$pkgcmd" info -e "$1"; then
		return 0
	else
		status=$?
		[ "$status" -eq 1 ] || exit "$status"
		return 1
	fi
}

# Complete preflight before changing any installed package identity.
for suffix in '' -man -dbg -tests; do
	old=${prefix}-hwtlm${suffix}
	new=${prefix}-hwstat${suffix}
	if installed "$old"; then
		if installed "$new"; then
			echo "Both $old and $new are installed; resolve this before migrating." >&2
			exit 1
		fi
		existing=$old
		pending="$pending $suffix:"
	elif installed "$new"; then
		# A prior run may have renamed this entry without upgrading files.
		origin=$("$pkgcmd" query '%o' "$new")
		[ "$origin" = "base/$old" ] || continue
		existing=$new
	else
		continue
	fi
	if [ "$("$pkgcmd" query '%o' "$existing")" != "base/$old" ]; then
		echo "$existing has an unexpected origin; refusing to rename it." >&2
		exit 1
	fi
	if [ "$("$pkgcmd" query '%k' "$existing")" != 0 ]; then
		echo "$existing is locked; unlock it before migrating." >&2
		exit 1
	fi
	if ! target=$("$pkgcmd" rquery -r "$repository" -e "%n == $new" '%v') ||
	    [ -z "$target" ]; then
		echo "$new is missing from $repository; publish/update the repository first." >&2
		exit 1
	fi
	current=$("$pkgcmd" query '%v' "$existing")
	if [ "$("$pkgcmd" version -t "$current" "$target")" != '<' ]; then
		echo "$new ($target) must be newer than installed $existing ($current)." >&2
		echo "Publish a newer PKG_VERSION and update $repository before migrating." >&2
		exit 1
	fi
	prepared=yes
done

for entry in $pending; do
	suffix=${entry%:}
	old=${prefix}-hwtlm${suffix}
	new=${prefix}-hwstat${suffix}
	# Upgrade replaces origin/version/files from the new manifest. Rename
	# dependency references too, so installed test/metapackages stay coherent.
	"$pkgcmd" set -a -y -n "$old:$new"
done

if [ -n "$prepared" ]; then
	echo "Package names prepared. Run pkg upgrade -r $repository to replace the files."
fi
