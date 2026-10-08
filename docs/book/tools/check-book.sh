#!/bin/sh
#
# Check the 5BSD book (docs/book/src) against the source tree it describes.
#
# usage: check-book.sh [-m man-inventory] [-s sysctl-inventory] root
#        check-book.sh -g man|sysctl root
#
# root mirrors the source layout: the top of a source tree, or a staged copy
# holding docs/book/src, sys/kern/syscalls.master and the sys/sys headers the
# system call appendix names.  The manual page and sysctl inventories are
# collected from root when they are not given; -g prints one and exits, so a
# build can collect them once and install them beside a staged copy.
#
# Checks:
#  - every relative Markdown link (and #anchor) in the book resolves inside
#    the book, and every chapter is reachable from SUMMARY.md;
#  - every system call number, name and flag in the tables of
#    appendix/syscalls-and-sysctls.md matches sys/kern/syscalls.master;
#  - every "`CONSTANT` (value)" in that appendix, every constant listed in a
#    table with a header, and every DTYPE_, KF_TYPE_, AF_ and PF_ constant
#    named anywhere in the book matches the header that defines it;
#  - every sysctl named in the appendix's sysctl tables is declared in sys/;
#    sysctls created at run time are reported as unverified, not failed;
#  - every manual page cross-reference in appendix/man-index.md and in the
#    appendix's "Manual page" column exists in the tree.
#
# Problems are printed as "FAIL: file:line: message" and make the script
# exit 1.  Claims that cannot be checked statically are printed as
# "UNVERIFIED: ..." and do not fail.

set -u
LC_ALL=C
export LC_ALL

usage()
{
	echo "usage: check-book.sh [-m man-inventory] [-s sysctl-inventory] root" >&2
	echo "       check-book.sh -g man|sysctl root" >&2
	exit 2
}

# Every manual page the tree provides, as name.section: page sources
# (including generated *.in templates) and the MAN and MLINKS lists of the
# build Makefiles.
gen_man()
{
	{
		find "$1" -name .git -prune -o -type f -name '*.[1-9]*' -print |
		    sed -e 's,.*/,,' -e 's,\.in$,,'
		find "$1" -name .git -prune -o -type f \
		    \( -name Makefile -o -name 'Makefile.*' -o -name '*.mk' \) \
		    -print | xargs awk '
			/^[ \t]*(MAN[0-9]*|MLINKS)[ \t]*[+?:]?=/ { inlist = 1 }
			inlist {
				for (i = 1; i <= NF; i++)
					if ($i ~ /^[A-Za-z0-9_.:+-]+\.[1-9][a-z]*$/)
						print $i
				if ($0 !~ /\\$/)
					inlist = 0
			}'
	} | grep -E '^[A-Za-z0-9_.:+-]+\.[1-9][a-z]*$' | sort -u
}

# Every statically declared sysctl as "S parent-oid leaf" (parent-oid is the
# SYSCTL_NODE symbol, e.g. _kern_vsock), and every leaf created with a
# literal name at run time as "D leaf".
gen_sysctl()
{
	find "$1/sys" -name .git -prune -o -type f \( -name '*.c' -o -name '*.h' \) \
	    -print | xargs grep -l 'SYSCTL_' | xargs awk '
	function splitargs(s, args,    n, depth, i, c, cur) {
		n = 0; depth = 0; cur = ""
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (c == "(") depth++
			else if (c == ")") {
				if (depth == 0) break
				depth--
			} else if (c == "," && depth == 0) {
				args[++n] = cur; cur = ""; continue
			}
			cur = cur c
		}
		args[++n] = cur
		for (i = 1; i <= n; i++) {
			gsub(/^[ \t]+|[ \t]+$/, "", args[i])
		}
		return n
	}
	function emit(macro, rest,    n, a, parent, name, p) {
		if (macro ~ /^SYSCTL_(DECL|CHILDREN|PARENT|HANDLER_ARGS|IN|OUT|STATIC_CHILDREN|NODE_CHILDREN|ADD_ROOT_NODE)$/)
			return
		n = splitargs(rest, a)
		if (macro == "SYSCTL_ROOT_NODE") {
			if (n >= 2) print "S _ " a[2]
			return
		}
		if (macro ~ /^SYSCTL_ADD_/) {
			if (n < 4) return
			name = a[4]
			if (name !~ /^"[^"]*"$/) return
			name = substr(name, 2, length(name) - 2)
			parent = a[2]
			if (parent ~ /^SYSCTL_STATIC_CHILDREN\(/) {
				p = parent
				sub(/^SYSCTL_STATIC_CHILDREN\([ \t]*/, "", p)
				sub(/[ \t]*\)$/, "", p)
				if (p ~ /^_[A-Za-z0-9_]*$/) {
					print "S " p " " name
					return
				}
			}
			print "D " name
			return
		}
		if (n < 3) return
		parent = a[1]; name = a[3]
		if (name !~ /^[A-Za-z_][A-Za-z0-9_]*$/) return
		if (parent == "ELF_NODE_OID") {
			print "S _kern_elf32 " name
			print "S _kern_elf64 " name
		} else if (parent ~ /^_[A-Za-z0-9_]*$/)
			print "S " parent " " name
		else
			print "D " name
	}
	FNR == 1 { acc = ""; lines = 0 }
	{
		if (acc == "") {
			if (!match($0, /SYSCTL_[A-Z0-9_]+[ \t]*\(/))
				next
			acc = substr($0, RSTART)
			lines = 0
		} else
			acc = acc " " $0
		lines++
		# The parent, number and name always fit in a few lines.
		t = acc
		if (gsub(/,/, ",", t) < 4 && t !~ /[;{]/ && lines < 4)
			next
		macro = acc
		sub(/[ \t]*\(.*/, "", macro)
		rest = acc
		sub(/^[^(]*\(/, "", rest)
		emit(macro, rest)
		acc = ""
	}' | sort -u
}

genonly=
maninv=
sysctlinv=
while getopts g:m:s: opt; do
	case "$opt" in
	g) genonly=$OPTARG ;;
	m) maninv=$OPTARG ;;
	s) sysctlinv=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage
root=$1
[ -d "$root" ] || { echo "check-book.sh: $root: not a directory" >&2; exit 2; }

case "$genonly" in
"") ;;
man) gen_man "$root"; exit $? ;;
sysctl) gen_sysctl "$root"; exit $? ;;
*) usage ;;
esac

book=$root/docs/book/src
appendix=$book/appendix/syscalls-and-sysctls.md
manindex=$book/appendix/man-index.md
syscalls=$root/sys/kern/syscalls.master
for f in "$book/SUMMARY.md" "$appendix" "$manindex" "$syscalls"; do
	[ -f "$f" ] || { echo "FAIL: missing input $f"; exit 1; }
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-book.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT
trap 'exit 2' HUP INT TERM

if [ -z "$maninv" ]; then
	gen_man "$root" >"$tmp/man" || exit 2
	maninv=$tmp/man
fi
if [ -z "$sysctlinv" ]; then
	gen_sysctl "$root" >"$tmp/sysctl" || exit 2
	sysctlinv=$tmp/sysctl
fi

(cd "$book" && find . -type f -name '*.md' | sed 's,^\./,,' | sort) \
    >"$tmp/chapters"

# The system call table as "number name flags".
awk '
	/^[0-9]+[ \t]/ {
		num = $1; flags = $3; name = ""
		if ($0 ~ /\{[ \t]*$/) { want = 1; next }
		if (NF >= 4) name = $4
		print num, name, flags
		next
	}
	want && match($0, /[A-Za-z_][A-Za-z0-9_]*\(/) {
		print num, substr($0, RSTART, RLENGTH - 1), flags
		want = 0
	}' "$syscalls" >"$tmp/syscalls"

# The #define table of every sys/ header the appendix names, plus the headers
# behind the DTYPE_, KF_TYPE_ and AF_ families: "header name value".
hdrs=$(grep -ohE 'sys/sys/[A-Za-z0-9_]+\.h' "$appendix" | sort -u)
hdrs=$(printf '%s\n' $hdrs sys/sys/file.h sys/sys/user.h sys/sys/socket.h |
    sort -u)
: >"$tmp/defines"
for h in $hdrs; do
	if [ ! -f "$root/$h" ]; then
		echo "FAIL: appendix/syscalls-and-sysctls.md: header $h is not in the tree"
		echo x >>"$tmp/fail"
		continue
	fi
	awk -v h="$h" '
		/^#[ \t]*define[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t(]/ {
			line = $0
			sub(/\/\*.*/, "", line)
			sub(/^#[ \t]*define[ \t]+/, "", line)
			name = line; sub(/[ \t(].*/, "", name)
			if (substr(line, length(name) + 1, 1) == "(")
				next	# function-like macro
			val = substr(line, length(name) + 1)
			gsub(/[ \t]/, "", val)
			print h, name, (val == "" ? "-" : val)
		}' "$root/$h" >>"$tmp/defines"
done

for f in "$maninv" "$sysctlinv"; do
	[ -s "$f" ] || { echo "FAIL: empty inventory $f"; exit 1; }
done

# All checks run in one awk program over the book and the collected tables.
(cd "$book" && find . -type f -name '*.md' | sed 's,^\./,,' | sort |
    while read -r ch; do printf '%s\n' "$book/$ch"; done) >"$tmp/files"
awk -v book="$book" \
    -v chapters="$tmp/chapters" -v syscalls="$tmp/syscalls" \
    -v defines="$tmp/defines" -v maninv="$maninv" -v sysctlinv="$sysctlinv" \
'
function fail(msg) { print "FAIL: " rel ":" FNR ": " msg; nfail++ }
function unverified(msg) { print "UNVERIFIED: " rel ":" FNR ": " msg; nunv++ }

# Normalize a path relative to the book root; returns "" if it leaves it.
function normpath(p,    n, parts, out, i, k) {
	n = split(p, parts, "/")
	k = 0
	for (i = 1; i <= n; i++) {
		if (parts[i] == "" || parts[i] == ".") continue
		if (parts[i] == "..") {
			if (k == 0) return ""
			k--
			continue
		}
		out[++k] = parts[i]
	}
	p = ""
	for (i = 1; i <= k; i++) p = p (i > 1 ? "/" : "") out[i]
	return p
}

# mdBook heading ids: lower case; letters, digits, "_" and "-" kept; spaces
# become "-"; everything else is dropped.
function slug(s,    out, i, c) {
	s = tolower(s)
	out = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c ~ /[a-z0-9_-]/) out = out c
		else if (c == " ") out = out "-"
	}
	return out
}

function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }

function numval(v,    neg, n, i, c, d) {
	gsub(/[()]/, "", v)
	sub(/[uUlL]+$/, "", v)
	neg = 0
	if (substr(v, 1, 1) == "-") { neg = 1; v = substr(v, 2) }
	if (v ~ /^0[xX][0-9a-fA-F]+$/) {
		n = 0
		v = tolower(substr(v, 3))
		for (i = 1; i <= length(v); i++) {
			c = substr(v, i, 1)
			d = index("0123456789abcdef", c) - 1
			n = n * 16 + d
		}
	} else if (v ~ /^[0-9]+$/)
		n = v + 0
	else
		return "?"
	return neg ? -n : n
}

# Resolve a constant through symbolic #defines (PF_VSOCK -> AF_VSOCK -> 46).
function resolve(name,    v, depth) {
	v = defval[name]
	for (depth = 0; depth < 8 && (v in defval); depth++)
		v = defval[v]
	return numval(v)
}

# Verify "`NAME`[, `NAME`]... (value)" claims in text.
function check_values(text,    s, seg, names, n, i, val, m, nm, v) {
	s = text
	while (match(s, /(`[A-Z][A-Z0-9_]*`(, | and | or |\/))*`[A-Z][A-Z0-9_]*` \(-?(0x)?[0-9A-Fa-f]+[ )]/)) {
		seg = substr(s, RSTART, RLENGTH)
		s = substr(s, RSTART + RLENGTH)
		val = seg
		sub(/.*\(/, "", val)
		sub(/[ )]$/, "", val)
		n = 0
		while (match(seg, /`[A-Z][A-Z0-9_]*`/)) {
			names[++n] = substr(seg, RSTART + 1, RLENGTH - 2)
			seg = substr(seg, RSTART + RLENGTH)
		}
		for (i = 1; i <= n; i++) {
			nm = names[i]
			if (!(nm in defval)) {
				if (strict || nm ~ /^(DTYPE|KF_TYPE|AF|PF)_/)
					fail("`" nm "` (" val ") is not defined in the checked headers")
				continue
			}
			v = resolve(nm)
			if (v == "?")
				unverified("`" nm "` has a non-numeric definition `" defval[nm] "`")
			else if (v != numval(val))
				fail("`" nm "` is " v " in " defhdr[nm] ", not " val)
		}
	}
}

# Every DTYPE_/KF_TYPE_/AF_/PF_ name used anywhere must exist.
function check_families(text,    s, nm) {
	# Chapters about the Linux ABI name Linux socket families.
	if (rel ~ /(^|\/)linux(\/|-)/) return
	s = text
	while (match(s, /`(DTYPE|KF_TYPE|AF|PF)_[A-Z0-9_]+`/)) {
		nm = substr(s, RSTART + 1, RLENGTH - 2)
		s = substr(s, RSTART + RLENGTH)
		if (nm ~ /_$/ || nm ~ /\*/) continue
		if (!(nm in defval))
			fail("`" nm "` is not defined in sys/sys/file.h, user.h or socket.h")
	}
}

function check_man(ref,    page) {
	page = ref
	sub(/\(/, ".", page)
	sub(/\)$/, "", page)
	if (!(page in manpage))
		fail("manual page " ref " does not exist in the tree")
}

function check_mans(text,    s, ref) {
	s = text
	while (match(s, /[A-Za-z0-9_.:+-]+\([1-9][a-z]*\)/)) {
		ref = substr(s, RSTART, RLENGTH)
		s = substr(s, RSTART + RLENGTH)
		check_man(ref)
	}
}

function check_sysctl(name,    n, parts, parent, i, leaf, pfx) {
	if (name ~ /</) {
		pfx = name
		sub(/\.?<.*/, "", pfx)
		if (pfx != "" && pfx != name)
			check_sysctl(pfx)
		unverified("sysctl `" name "` is a pattern; only its prefix was checked")
		return
	}
	n = split(name, parts, ".")
	parent = ""
	for (i = 1; i < n; i++) parent = parent "_" parts[i]
	if (parent == "") parent = "_"
	leaf = parts[n]
	if ((parent SUBSEP leaf) in sysctl)
		return
	if (leaf in dynsysctl)
		unverified("sysctl `" name "` is not declared statically; a leaf `" leaf "` is created at run time")
	else
		fail("sysctl `" name "` is not declared in sys/")
}

function splitrow(line, cells,    n) {
	line = trim(line)
	sub(/^\|/, "", line)
	sub(/\|$/, "", line)
	n = split(line, cells, "|")
	return n
}

BEGIN {
	while ((getline l < chapters) > 0) chapter[l] = 1
	while ((getline l < maninv) > 0) manpage[l] = 1
	while ((getline l < sysctlinv) > 0) {
		split(l, f, " ")
		if (f[1] == "S") sysctl[f[2], f[3]] = 1
		else if (f[1] == "D") dynsysctl[f[2]] = 1
	}
	while ((getline l < syscalls) > 0) {
		split(l, f, " ")
		scname[f[1]] = f[2]
		scflags[f[1]] = f[3]
	}
	while ((getline l < defines) > 0) {
		split(l, f, " ")
		if (!(f[2] in defval)) {
			defval[f[2]] = f[3]
			defhdr[f[2]] = f[1]
		}
		hdrdef[f[1], f[2]] = 1
	}
	# Pass 1 over all chapters collects heading ids, pass 2 checks.
	pass = 1
}

FNR == 1 {
	if (FILENAME == firstfile) pass = 2
	if (firstfile == "") firstfile = FILENAME
	rel = substr(FILENAME, length(book) + 2)
	dir = rel
	if (dir ~ /\//) sub(/\/[^\/]*$/, "", dir); else dir = ""
	infence = 0
	section = ""
	tablehdr = ""
	curheader = ""
	prevfull = ""
	prevtail = ""
	strict = (rel == "appendix/syscalls-and-sysctls.md")
	delete seenid
}

/^[ \t]*(```|~~~)/ { infence = !infence; next }
infence { next }

pass == 1 {
	if (match($0, /^#+[ \t]+/)) {
		id = slug(trim(substr($0, RLENGTH + 1)))
		if (id in seenid) { seenid[id]++; id = id "-" seenid[id] - 1 }
		else seenid[id] = 1
		anchor[rel, id] = 1
	}
	next
}

# ---- pass 2 ----
{
	line = $0
	if (line ~ /^## /) section = line

	# Links: inline [text](target) and reference definitions.
	s = line
	while (match(s, /\]\([^)]*\)/)) {
		target = substr(s, RSTART + 2, RLENGTH - 3)
		s = substr(s, RSTART + RLENGTH)
		check_link(target)
	}
	if (match(line, /^[ \t]*\[[^]]+\]:[ \t]+/))
		check_link(substr(line, RLENGTH + 1))

	if (rel == "SUMMARY.md") {
		s = line
		while (match(s, /\]\([^)#]*\.md/)) {
			linked[normpath(substr(s, RSTART + 2, RLENGTH - 2))] = 1
			s = substr(s, RSTART + RLENGTH)
		}
	}

	check_families(line)
	# A "`NAME` (value)" claim may wrap after the name.
	vtext = line
	if (prevtail != "" && line ~ /^\(/)
		vtext = prevtail " " line
	check_values(vtext)
	prevtail = ""
	if (match(line, /`[A-Z][A-Z0-9_]*`$/))
		prevtail = substr(line, RSTART)

	if (rel == "appendix/man-index.md")
		check_mans(line)

	if (strict)
		appendix_line(line)
}

function check_link(target,    path, frag, p) {
	target = trim(target)
	sub(/[ \t]+".*"$/, "", target)
	sub(/^</, "", target); sub(/>$/, "", target)
	if (target ~ /^[A-Za-z][A-Za-z0-9+.-]*:/) return	# URL
	if (target == "") { fail("empty link target"); return }
	frag = ""
	path = target
	if (index(target, "#")) {
		frag = substr(target, index(target, "#") + 1)
		path = substr(target, 1, index(target, "#") - 1)
	}
	if (path == "")
		p = rel
	else {
		p = normpath((dir == "" ? "" : dir "/") path)
		if (p == "") {
			fail("link `" target "` leaves the book; it does not resolve in the installed book")
			return
		}
		if (!(p in chapter)) {
			fail("link `" target "` does not resolve")
			return
		}
	}
	if (frag != "" && !((p SUBSEP frag) in anchor))
		fail("link `" target "`: no heading #" frag " in " p)
}

function appendix_line(line,    n, cells, i, h, c, s, tok, num, name, flags,
    fl, nf, k, col) {
	if (match(line, /^`sys\/[^`]*\.h`:/))
		curheader = substr(line, 2, RLENGTH - 3)
	if (line !~ /^\|/) {
		tablehdr = ""
		return
	}
	if (line ~ /^\|[- |:]+\|$/) return
	n = splitrow(line, cells)
	if (tablehdr == "") {
		tablehdr = line
		ncol = n
		for (i = 1; i <= n; i++) colname[i] = trim(cells[i])
		rowheader = ""
		return
	}
	num = ""
	for (i = 1; i <= n; i++) {
		col = colname[i]
		c = trim(cells[i])
		if (col == "Number" && c ~ /^[0-9]+$/) num = c
		if (col == "Number" && c !~ /^[0-9]+$/) num = ""
	}
	for (i = 1; i <= n; i++) {
		col = colname[i]
		c = trim(cells[i])
		if (col == "Name" && num != "" && match(c, /`[a-z_][a-z0-9_]*/)) {
			name = substr(c, RSTART + 1, RLENGTH - 1)
			if (!(num in scname))
				fail("system call " num " is not in syscalls.master")
			else if (scname[num] != name)
				fail("system call " num " is " scname[num] ", not " name)
		}
		if (col == "Flags" && num != "" && (num in scflags)) {
			nf = split(c, fl, /[^A-Z]+/)
			for (k = 1; k <= nf; k++)
				if (fl[k] != "" && index("|" scflags[num] "|", "|" fl[k] "|") == 0)
					fail("system call " num " is " scflags[num] ", not " fl[k])
		}
		if (col == "Manual page" && c != "none")
			check_mans(c)
		if (col == "Header" && c ~ /^`sys\//) {
			rowheader = c
			gsub(/`/, "", rowheader)
		}
		if (col == "Constant") {
			h = (rowheader != "" ? rowheader : curheader)
			s = c
			while (match(s, /`[A-Z][A-Z0-9_]*`/)) {
				tok = substr(s, RSTART + 1, RLENGTH - 2)
				s = substr(s, RSTART + RLENGTH)
				if (!(tok in defval))
					fail("`" tok "` is not defined in " (h != "" ? h : "the checked headers"))
				else if (h != "" && !((h SUBSEP tok) in hdrdef))
					fail("`" tok "` is defined in " defhdr[tok] ", not " h)
			}
		}
		if (section ~ /sysctl/ && i == 1 && col == "Name") {
			s = c
			while (match(s, /`[^`]+`/)) {
				tok = substr(s, RSTART + 1, RLENGTH - 2)
				s = substr(s, RSTART + RLENGTH)
				if (substr(tok, 1, 1) == ".") {
					if (prevfull == "") { fail("relative sysctl `" tok "` without a full name"); continue }
					p = prevfull
					sub(/\.[^.]*$/, "", p)
					tok = p tok
				} else
					prevfull = tok
				check_sysctl(tok)
			}
		}
	}
}

END {
	if (firstfile == "") { print "FAIL: no chapters"; exit 1 }
	for (c in chapter)
		if (c != "SUMMARY.md" && !(c in linked)) {
			print "FAIL: SUMMARY.md: chapter " c " is not linked from the table of contents"
			nfail++
		}
	printf "check-book: %d failure(s), %d unverified claim(s)\n", nfail, nunv
	exit nfail > 0
}
' $(cat "$tmp/files") $(cat "$tmp/files") || echo x >>"$tmp/fail"

[ ! -e "$tmp/fail" ]
