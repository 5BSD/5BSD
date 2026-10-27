# SPDX-License-Identifier: BSD-2-Clause
# Inputs: explicit BSD policy, upstream dist.mk, then one template.
function reject(message) { print message > "/dev/stderr"; failed=1; exit 1 }
BEGIN {
    # awk retains command-line variable assignments in ARGV.
    for (i=1; i<ARGC; i++)
        if (ARGV[i] !~ /^[A-Za-z_][A-Za-z0-9_]*=/) inputs[++input_count]=ARGV[i]
    if (input_count != 3) reject("expected policy, version and template inputs")
}
FILENAME == inputs[1] {
    if ($0 ~ /^[[:space:]]*(#|$)/) next
    equal=index($0,"=")
    key=substr($0,1,equal-1); value=substr($0,equal+1)
    if (!equal || key !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || key in values || value ~ /@/)
        reject("invalid or duplicate ncurses policy: " $0)
    if (key ~ /^NCURSES_(MAJOR|MINOR|PATCH)$/) reject("version belongs in dist.mk")
    values[key]=value
    next
}
FILENAME == inputs[2] {
    if ($1 ~ /^NCURSES_(MAJOR|MINOR|PATCH)$/ && $2 == "=") {
        if ($3 !~ /^[0-9]+$/ || $1 in values) reject("invalid or duplicate ncurses version")
        values[$1]=$3
    }
    next
}
FILENAME == inputs[3] {
    if (!("NCURSES_MAJOR" in values) || !("NCURSES_MINOR" in values) || !("NCURSES_PATCH" in values))
        reject("missing ncurses version")
    text=$0
    for (key in values) {
        if (substitution_names && !index("," substitution_names ",", "," key ",")) continue
        token="@" key "@"
        result=""
        while ((position=index(text,token)) != 0) {
            result=result substr(text,1,position-1) values[key]
            text=substr(text,position+length(token))
        }
        text=result text
    }
    if (bsd_wchar_names) {
        gsub(/ _WCHAR_T/, " __wchar_t", text)
        gsub(/ _WINT_T/, " __wint_t", text)
    }
    print text
    next
}
END { if (failed) exit 1 }
