# SPDX-License-Identifier: BSD-2-Clause
# Authenticated VM script, executed by staged /bin/sh as UID 65534.
# A marker follows a checked operation, never just an executable's presence.
work=$(/usr/bin/mktemp -d /tmp/programs.XXXXXXXX)
case "$work" in /tmp/programs.*) ;; *) exit 1 ;; esac
[ -d "$work" ]
trap '/bin/rm -rf "$work"' EXIT
printf 'PROGRAM_PASS /usr/bin/mktemp private-directory\n'
/bin/mkdir "$work/subdir"
[ -d "$work/subdir" ]
printf 'PROGRAM_PASS /bin/mkdir create-directory\n'
printf 'beta\nalpha\n' > "$work/input"
[ "$(/bin/cat "$work/input")" = "$(printf 'beta\nalpha')" ]
printf 'PROGRAM_PASS /bin/cat read-back\n'
/bin/cp "$work/input" "$work/subdir/copied"
[ "$(/bin/cat "$work/subdir/copied")" = "$(printf 'beta\nalpha')" ]
printf 'PROGRAM_PASS /bin/cp copy-content\n'
/bin/mv "$work/subdir/copied" "$work/moved"
[ ! -e "$work/subdir/copied" ]
[ "$(/bin/cat "$work/moved")" = "$(printf 'beta\nalpha')" ]
printf 'PROGRAM_PASS /bin/mv move-content\n'
/usr/bin/sort "$work/input" -o "$work/sorted"
[ "$(/bin/cat "$work/sorted")" = "$(printf 'alpha\nbeta')" ]
printf 'PROGRAM_PASS /usr/bin/sort sort-content\n'
/bin/rm "$work/moved"
[ ! -e "$work/moved" ]
printf 'PROGRAM_PASS /bin/rm remove-file\n'
# Shell interpretation of data remains allowed. noexec is not a script sandbox.
printf 'printf "script-data-readable"\n' > "$work/script"
[ "$(/bin/sh "$work/script")" = 'script-data-readable' ]
# These tests inspect the actual binary account databases in isolated scratch.
# All executables remain on the authenticated root, not the noexec tmpfs.
for account_case in alternate_uid_update alternate_duplicate_uid malformed_update_retains_database in_place_input_metadata; do
    /bin/mkdir "$work/$account_case"
    (
        cd "$work/$account_case"
        /usr/libexec/security-pwd-test -r result -v pwd_mkdb=/usr/sbin/pwd_mkdb "$account_case"
        [ "$(/bin/cat result)" = passed ]
    ) || exit 1
done
printf 'PROGRAM_PASS /usr/sbin/pwd_mkdb alternate-account-databases\n'
for cap_case in alternate_output inherited_input default_output reader_selection long_name long_continued_name; do
    /bin/mkdir "$work/cap-$cap_case"
    (
        cd "$work/cap-$cap_case"
        /usr/libexec/security-cap-test -r result -v cap_mkdb=/usr/bin/cap_mkdb "$cap_case"
        [ "$(/bin/cat result)" = passed ]
    ) || exit 1
done
printf 'PROGRAM_PASS /usr/bin/cap_mkdb text-input-database-construction\n'
/bin/rm -rf "$work"
[ ! -e "$work" ]
trap - EXIT
printf 'PROGRAM_PASS /bin/sh script-pipeline-and-redirection\n'
