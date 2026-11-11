#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
#
# The DescriptorQueue resolution ledger (design 11, D127, plan 0c item 1):
# every place an attached process's names are marked or consulted, and
# every lookup the kernel can make in an attached process's thread.
#
#   MARK     file function op flags accept complete xform
#                                             an intent (class 1, 2 or 3);
#                                             accept: PASS, or PASS+kinds
#                                             of dq_intent_enter_served
#                                             (a trailing ? when a kind can
#                                             be withheld per call);
#                                             complete: the completion its
#                                             DQRES_SERVED runs, or -;
#                                             xform: the errnos the impl
#                                             (FUNC_dqimpl) tests and may
#                                             transform, for sign-off (D157)
#   SLOT     file function slot pointer       a slot the intent declares
#   CONSULT  file function op class           dqres_consult_sun,
#                                             dqres_consult_socket; and
#                                             the served-start choke
#                                             points (1c-iii-b): op
#                                             SERVED (namei_setup's served
#                                             branch), SYMLINK (namei's
#                                             re-consultation, D172),
#                                             START (fgetvp_lookup_start
#                                             asking the vector) and
#                                             CWDROOT (1c-iii-c: namei_setup
#                                             choosing a served cwd or
#                                             root through
#                                             dqres_namei_setup_start, the
#                                             D175 EXDEV refusal of class
#                                             2/3 and unmarked lookups,
#                                             and the served-root
#                                             EXEC_INTERP consultation)
#   USERNDI  file function pointer coverage   NDINIT* of UIO_USERSPACE
#   VARSEG   file function segment coverage   NDINIT* whose segment is a
#                                             variable
#   SYSNDI   file function pointer class      NDINIT* of UIO_SYSSPACE
#   SYSCALL  file function callee class       a marked kern_*() entry
#                                             called with UIO_SYSSPACE
#   SOCKET   file function callee class       a call of socreate,
#                                             socreate_proto or sopeeloff
#
# User-space coverage is proved by pointer and slot:
#   slotN		the NDINIT's pointer is the pointer slot N declares,
#			in the same function or, for a *_dqimpl, in its
#			wrapper of the same file (which passes its arguments
#			through); a VARSEG row inside a *_dqimpl must pass the
#			same test
#   slotN@FILE:FUNC	a helper: one of the three lines before the NDINIT
#			says "dq-ledger: slot N PTR of FILE:FUNC" (several,
#			comma-separated, joined by "+"), and FUNC in FILE is
#			checked to declare slot N with pointer PTR
#   UNMARKED, FLAG	none of these: the build fails
#
# A kernel-space lookup by an attached thread outside an exempt region is
# refused at run time (EPERM, counted in ds2_resolve_unmarked); here each
# one must be classified, or the build fails (UNCLASSIFIED):
#   EXEMPT		its namei/vn_open (or the kern_*() call) is wrapped in
#			DQRES_EXEMPT, or its own function opens a region
#			(DQRES_NORESOLVE_ENTER); paths the kernel computes
#   REFUSED		its function calls dqres_kpath_refused before it
#   MARKED		its pointer is a slot's (as slotN above)
#   via:K@FILE:FUNC	"dq-ledger: exempt|refused|content via FILE:FUNC":
#			FUNC in FILE is checked to open an exempt region, to
#			call dqres_kpath_refused, or to declare a content slot
#			(dq_intent_slot_content, dqres_consult_sun)
#   KTHREAD, BOOT	"dq-ledger: kthread|boot (reason)": recorded, runs
#			only in kernel threads or before init (not machine
#			checked: review these rows)
#
# Socket creation (1c-ii, D139): each call that makes a socket must be
# classified, or the build fails (UNCLASSIFIED):
#   CONSULT		dqres_consult_socket is called earlier in the same
#			function (socket(2), socketpair(2))
#   DERIVED:REASON	"dq-ledger: derived (REASON)", accepted only for
#			sopeeloff: a socket split off one the process made
#   KERNEL:REASON	"dq-ledger: kernel (REASON)": a socket the kernel
#			makes for itself or for a facility (I7), recorded
#
# EDQRESOLVED containment (D157): every file and function or macro whose
# code (not comments) names EDQRESOLVED is a row, ALLOWED only for its
# definition (errno.h), the consumer macro DQRES_SERVED (dqres.h), the
# producers dqres_namei, dqres_namei_served, dqres_namei_symlink and
# dq_symlink_served_root (1c-iii-c)
# (1c-iii-b) and the stray mapping in syscall_dq_stray and syscallret,
# STRAY otherwise (the build fails).  A MARK row is FLAG when
# a served intent has no DQRES_SERVED completion or the reverse, when the
# DQRES_SERVED does not sit after the impl call and before
# dq_intent_leave, or when the completion (a *_dqserved function) does
# not name every served kind of the accept set.  XFORM lists the errnos
# an impl compares any variable with, and its switch cases.
#
#	dq_resolve_ledger.sh generate SRCDIR	write the ledger to stdout
#	dq_resolve_ledger.sh check SRCDIR LEDGER [SOURCE-LIST]
#						fail if LEDGER differs or
#						has an UNMARKED, FLAG or
#						UNCLASSIFIED row
#
set -e

# Optional complete regular C/header inventory supplied by a build system.
# Resolve before scan_edq changes directory. find-based scans retain their
# existing tree/filename rules; only recursive grep discovery uses this list.
# A declared source view can contain build-system symlinks even when the real
# source files are regular. Explicit grep operands read those declared bytes.
DQ_LEDGER_SOURCE_LIST=
if [ -n "${4:-}" ]; then
	case "$4" in
	/*) DQ_LEDGER_SOURCE_LIST=$4 ;;
	*) DQ_LEDGER_SOURCE_LIST=$PWD/$4 ;;
	esac
	if [ ! -f "$DQ_LEDGER_SOURCE_LIST" ] || [ ! -r "$DQ_LEDGER_SOURCE_LIST" ]; then
		echo "dq_resolve_ledger: unreadable source inventory: $DQ_LEDGER_SOURCE_LIST" >&2
		exit 2
	fi
fi

# The trees scanned: every one that can call namei for a process.
DQ_LEDGER_DIRS="kern vm security compat fs dev cam geom netinet netinet6 \
    net netgraph ufs opencrypto contrib/openzfs/module/os/freebsd"
# And for socket creation, also the RPC, NFS boot, NLM and pf trees.
DQ_LEDGER_SOCK_DIRS="${DQ_LEDGER_DIRS} nfs nlm rpc netpfil"

scan_sockets()
(
	cd "$1"
	# shellcheck disable=SC2086
	find $DQ_LEDGER_SOCK_DIRS -name '*.c' 2>/dev/null | LC_ALL=C sort |
	    xargs grep -lE '(socreate|socreate_proto|sopeeloff)\(' |
	    while read -r f; do
		awk -v file="$f" '
		function annot(    s) {
			s = ""
			if (p3 ~ /dq-ledger:/) s = p3
			if (p2 ~ /dq-ledger:/) s = p2
			if (p1 ~ /dq-ledger:/) s = p1
			sub(/.*dq-ledger: */, "", s)
			sub(/ *\*\/.*/, "", s)
			gsub(/\t/, " ", s)
			return (s)
		}
		/^[A-Za-z_][A-Za-z0-9_]*\(/ {
			fn = $0; sub(/\(.*/, "", fn); consulted = 0
		}
		{
			code = $0
			gsub(/"[^"]*"/, "\"\"", code)
		}
		code ~ /^[ \t]*(\*|\/\*|\/\/)/ { code = "" }
		code ~ /dqres_consult_socket\(/ { consulted = 1 }
		code ~ /(^|[^A-Za-z0-9_])(socreate|socreate_proto|sopeeloff)\(/ &&
		    code !~ /^(socreate|socreate_proto|sopeeloff)\(/ {
			match(code, /(socreate_proto|socreate|sopeeloff)\(/)
			callee = substr(code, RSTART, RLENGTH - 1)
			a = annot()
			if (consulted)
				c = "CONSULT"
			else if (a ~ /^derived \(.*\)$/ && callee == "sopeeloff") {
				sub(/^derived \(/, "", a); sub(/\)$/, "", a)
				c = "DERIVED:" a
			} else if (a ~ /^kernel \(.*\)$/) {
				sub(/^kernel \(/, "", a); sub(/\)$/, "", a)
				c = "KERNEL:" a
			} else
				c = "UNCLASSIFIED"
			printf("SOCKET\t%s\t%s\t%s\t%s\n", file, fn, callee, c)
		}
		{ p3 = p2; p2 = p1; p1 = $0 }' "$f"
	    done
)

scan()
(
	cd "$1"
	# shellcheck disable=SC2086
	find $DQ_LEDGER_DIRS -name '*.c' 2>/dev/null | LC_ALL=C sort |
	    xargs grep -lF -e NDINIT -e dq_intent_ -e dqres_ -e DQRES_ \
	    -e UIO_SYSSPACE |
	    while read -r f; do
		awk -v file="$f" '
		function args(s, a,    n, i, c, d, cur) {
			n = 0; d = 0; cur = ""
			for (i = 1; i <= length(s); i++) {
				c = substr(s, i, 1)
				if (c == "(") d++
				else if (c == ")") d--
				if (c == "," && d == 0) {
					a[++n] = cur; cur = ""
				} else
					cur = cur c
			}
			a[++n] = cur
			return (n)
		}
		function callargs(s, name,    i, d, c, out) {
			i = index(s, name "(")
			if (i == 0)
				return ("")
			s = substr(s, i + length(name) + 1)
			d = 1; out = ""
			for (i = 1; i <= length(s) && d > 0; i++) {
				c = substr(s, i, 1)
				if (c == "(") d++
				else if (c == ")") d--
				if (d > 0) out = out c
			}
			return (out)
		}
		function strip(s) { gsub(/[ \t]/, "", s); return (s) }
		# "dq-ledger: X" in the three lines before a statement.
		function annot(    s) {
			s = ""
			if (p3 ~ /dq-ledger:/) s = p3
			if (p2 ~ /dq-ledger:/) s = p2
			if (p1 ~ /dq-ledger:/) s = p1
			if (s == "")
				return ("")
			sub(/.*dq-ledger: */, "", s)
			sub(/ *\*\/.*/, "", s)
			gsub(/\t/, " ", s)
			return (s)
		}
		function flush(ex) {
			if (pend)
				printf("N\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", file,
				    pfn, pseg, pptr, pann, ex, pref)
			pend = 0
		}
		/^[A-Za-z_][A-Za-z0-9_]*\(/ {
			flush(0)
			fn = $0; sub(/\(.*/, "", fn)
			refused = 0
			printf("F\t%s\t%s\n", file, fn)
		}
		/DQRES_NORESOLVE_ENTER\(/ && fn != "" {
			printf("E\t%s\t%s\n", file, fn)
		}
		/DQRES_EXEMPT\(/ && fn != "" {
			printf("X\t%s\t%s\n", file, fn)
		}
		/dqres_kpath_refused\(/ && !/^dqres_kpath_refused/ {
			refused = 1
			printf("R\t%s\t%s\n", file, fn)
		}
		/dq_intent_slot_content\(|dqres_consult_sun\(/ && \
		    !/^dq_intent_slot_content|^dqres_consult_sun/ {
			printf("K\t%s\t%s\n", file, fn)
		}
		function accepted(e,    k, r) {
			r = "PASS"
			if (e ~ /DQ_RESOLVE_FD/ || e ~ /dq_setattr_accept/)
				r = r "+FD"
			if (e ~ /DQ_RESOLVE_ATTR/) r = r "+ATTR"
			if (e ~ /DQ_RESOLVE_LINK/) r = r "+LINK"
			if (e ~ /DQ_RESOLVE_OK/ || e ~ /dq_setattr_accept/)
				r = r "+OK"
			if (e ~ /\?/ || (e ~ /dq_setattr_accept/ &&
			    e !~ /dq_setattr_accept\(false\)/))
				r = r "?"
			return (r)
		}
		/dq_intent_enter(_served)?\(/ && !/^dq_intent_enter/ && \
		    fn != "dq_intent_enter_served" { me = 1; mel = "" }
		me { mel = mel $0 }
		me && /;/ {
			me = 0
			if (mel ~ /dq_intent_enter_served\(/) {
				n = args(callargs(mel, "dq_intent_enter_served"),
				    a)
				acc = accepted(a[5])
			} else {
				n = args(callargs(mel, "dq_intent_enter"), a)
				acc = "PASS"
			}
			printf("M\t%s\t%s\t%s\t%s\t%s\n", file, fn,
			    strip(a[3]), strip(a[4]), acc)
		}
		# Order in a wrapper: the impl call, DQRES_SERVED, the leave.
		/^[A-Za-z_][A-Za-z0-9_]*\(/ { implat = servedat = 0 }
		/= [A-Za-z0-9_]+_dqimpl\(/ && !/^[A-Za-z_]/ { implat = FNR }
		/dq_intent_leave\(/ && !/^dq_intent_leave/ && servedat != 0 {
			printf("O\t%s\t%s\t%d\n", file, fn,
			    implat != 0 && implat < servedat)
			servedat = 0
		}
		/DQRES_SERVED\(/ && !/^#define/ { md = 1; mdl = "" }
		md { mdl = mdl $0 }
		md && /;/ {
			md = 0
			servedat = FNR
			n = args(callargs(mdl, "DQRES_SERVED"), a)
			comp = strip(a[4]); sub(/\(.*/, "", comp)
			printf("D\t%s\t%s\t%s\n", file, fn, comp)
		}
		# The kinds a completion handles: those it names.
		fn ~ /_dqserved$/ {
			code = $0
			while (match(code, /DQ_RESOLVE_(FD|ATTR|LINK|OK)/)) {
				printf("H\t%s\t%s\t%s\n", file, fn,
				    substr(code, RSTART + 11, RLENGTH - 11))
				code = substr(code, RSTART + RLENGTH)
			}
		}
		# The errnos an impl tests: any variable compared with an
		# errno, and switch cases.
		fn ~ /_dqimpl$/ {
			code = $0
			gsub(/"[^"]*"/, "", code)
			if (code ~ /^[ \t]*(\*|\/\*|\/\/)/)
				code = ""
			while (match(code, /[A-Za-z_][A-Za-z0-9_>.-]* [!=]= E[A-Z][A-Z0-9]+|case E[A-Z][A-Z0-9]+:/)) {
				e = substr(code, RSTART, RLENGTH)
				sub(/.* /, "", e); sub(/:$/, "", e)
				printf("Z\t%s\t%s\t%s\n", file, fn, e)
				code = substr(code, RSTART + RLENGTH)
			}
		}
		/dq_intent_slot(_content)?\(/ && \
		    !/^dq_intent_slot/ { ms = 1; msl = "" }
		ms { msl = msl $0 }
		ms && /;/ {
			ms = 0
			nm = (msl ~ /dq_intent_slot_content\(/) ? \
			    "dq_intent_slot_content" : "dq_intent_slot"
			n = args(callargs(msl, nm), a)
			printf("S\t%s\t%s\t%s\t%s\n", file, fn, strip(a[2]),
			    strip(a[3]))
		}
		/dqres_consult_(sun|socket)\(/ && \
		    !/^dqres_consult_(sun|socket)/ { mc = 1; mcl = "" }
		mc { mcl = mcl $0 }
		mc && /;/ {
			mc = 0
			# The op is the third argument of _sun, the second
			# of _socket.
			if (mcl ~ /dqres_consult_socket\(/) {
				n = args(callargs(mcl, "dqres_consult_socket"), a)
				op = strip(a[2])
			} else {
				n = args(callargs(mcl, "dqres_consult_sun"), a)
				op = strip(a[3])
			}
			printf("C\t%s\t%s\t%s\t1\n", file, fn, op)
		}
		# The served-start choke points (1c-iii-b).
		/dqres_(namei_(served|symlink|setup_start)|lookup_start)\(/ && \
		    !/^dqres_/ && fn != "" {
			op = $0
			sub(/.*dqres_/, "", op); sub(/\(.*/, "", op)
			op = op == "namei_served" ? "SERVED" : \
			    op == "namei_symlink" ? "SYMLINK" : \
			    op == "namei_setup_start" ? "CWDROOT" : "START"
			if (!((file SUBSEP fn SUBSEP op) in crow)) {
				crow[file, fn, op] = 1
				printf("C\t%s\t%s\t%s\t1\n", file, fn, op)
			}
		}
		# The lookup after a pending kernel-space NDINIT.
		pend && !nd && /namei\(|vn_open/ {
			flush($0 ~ /DQRES_EXEMPT\(/ ? 1 : 0)
		}
		/NDINIT[A-Z_]*\(/ && !/^#define/ {
			# A kernel-space NDINIT with no lookup before the next
			# one is an #if alternative of it: only one is a row.
			pend = 0
			nd = 1; ndl = ""; cite = annot()
		}
		nd { ndl = ndl $0 }
		nd && /;/ {
			nd = 0
			m = ndl; sub(/.*NDINIT/, "NDINIT", m)
			name = m; sub(/\(.*/, "", name)
			n = args(callargs(m, name), a)
			seg = strip(a[4]); ptr = strip(a[5])
			if (seg == "UIO_SYSSPACE") {
				pend = 1; pfn = fn; pseg = seg; pptr = ptr
				pann = cite; pref = refused
				if (m ~ /namei\(|vn_open/)
					flush(m ~ /DQRES_EXEMPT\(/ ? 1 : 0)
			} else
				printf("N\t%s\t%s\t%s\t%s\t%s\t0\t%d\n", file,
				    fn, seg, ptr, cite, refused)
		}
		# A kern_*() call with a kernel-space path.
		/[^A-Za-z0-9_]kern_[a-z0-9_]+\(/ && !/^kern_/ && !kc {
			kc = 1; kcl = ""; kann = annot()
		}
		kc { kcl = kcl $0 }
		kc && /;/ {
			kc = 0
			# A user-space path with a kernel-space buffer (the
			# times of utimes, the handle of getfh) is no row.
			if (kcl ~ /UIO_SYSSPACE/ && kcl !~ /UIO_USERSPACE/) {
				callee = kcl
				sub(/^.*[^A-Za-z0-9_]kern_/, "kern_", callee)
				sub(/\(.*/, "", callee)
				s = kcl; sub(/.*[^A-Za-z0-9_]kern_[a-z0-9_]+\(/,
				    "", s)
				printf("Q\t%s\t%s\t%s\t%s\t%d\t%d\n", file, fn,
				    callee, kann, (kcl ~ /DQRES_EXEMPT\(/),
				    refused)
			}
		}
		{ p3 = p2; p2 = p1; p1 = $0 }
		END { flush(0) }' "$f"
	    done
)

generate()
{
	raw=$(mktemp -t dqledger)
	scan "$1" > "$raw"
	awk -F '\t' '
	NR == FNR {
		if ($1 == "S") {
			slot[$2 "\t" $3 "\t" $5] = $4
			slotk[$2 "\t" $3 "\t" $4 "\t" $5] = 1
		}
		if ($1 == "E") region[$2 "\t" $3] = exempt[$2 "\t" $3] = 1
		if ($1 == "X") exempt[$2 "\t" $3] = 1
		if ($1 == "R") refuse[$2 "\t" $3] = 1
		if ($1 == "K") content[$2 "\t" $3] = 1
		if ($1 == "D") served[$2 "\t" $3] = $4
		if ($1 == "O") order[$2 "\t" $3] = $4
		if ($1 == "H") handles[$2 "\t" $3 "\t" $4] = 1
		if ($1 == "Z" && index("+" xf[$2 "\t" $3] "+",
		    "+" $4 "+") == 0)
			xf[$2 "\t" $3] = xf[$2 "\t" $3] \
			    (xf[$2 "\t" $3] == "" ? "" : "+") $4
		if ($1 == "F" && $3 ~ /_dqimpl$/) {
			b = $3; sub(/_dqimpl$/, "", b); wrapped[b] = 1
		}
		next
	}
	function cover(file, fn, ptr,    base) {
		if ((file "\t" fn "\t" ptr) in slot)
			return ("slot" slot[file "\t" fn "\t" ptr])
		base = fn; sub(/_dqimpl$/, "", base)
		if (base != fn && (file "\t" base "\t" ptr) in slot)
			return ("slot" slot[file "\t" base "\t" ptr])
		return ("")
	}
	# "slot N PTR of FILE:FUNC[, ...]"
	function cited(ann,    k, cs, j, w, r, fl) {
		if (ann !~ /^slot /)
			return ("")
		k = split(ann, cs, ",")
		r = ""
		for (j = 1; j <= k; j++) {
			split(cs[j], w, " ")
			# w: slot N PTR of FILE:FUNC
			if (w[1] != "slot" || w[4] != "of")
				return ("")
			split(w[5], fl, ":")
			if (!((fl[1] "\t" fl[2] "\t" w[2] "\t" w[3]) in slotk))
				return ("")
			r = r (j > 1 ? "+" : "") "slot" w[2] "@" w[5]
		}
		return (r)
	}
	# "exempt|refused|content via FILE:FUNC", "kthread ...", "boot ..."
	function via(ann,    w, fl, key) {
		if (ann ~ /^kthread/)
			return ("KTHREAD")
		if (ann ~ /^boot/)
			return ("BOOT")
		split(ann, w, " ")
		if (w[2] != "via")
			return ("")
		split(w[3], fl, ":")
		key = fl[1] "\t" fl[2]
		if (w[1] == "exempt" && (key in exempt))
			return ("via:exempt@" w[3])
		if (w[1] == "refused" && (key in refuse))
			return ("via:refused@" w[3])
		if (w[1] == "content" && (key in content))
			return ("via:content@" w[3])
		return ("")
	}
	function sysclass(file, fn, ptr, ann, ex, ref,    c) {
		if (ex)
			return ("EXEMPT")
		if ((file "\t" fn) in region)
			return ("EXEMPT")
		if (ref)
			return ("REFUSED")
		if (ptr != "" && (c = cover(file, fn, ptr)) != "")
			return ("MARKED:" c)
		if (ann != "" && (c = via(ann)) != "")
			return (c)
		return ("UNCLASSIFIED")
	}
	# Every served kind of the accept set handled by the completion.
	function unhandled(file, comp, acc,    n, i, w, kk) {
		gsub(/\?/, "", acc)
		n = split(acc, w, "+")
		for (i = 2; i <= n; i++) {
			kk = file "\t" comp "\t" w[i]
			if (!(kk in handles))
				return (1)
		}
		return (0)
	}
	$1 == "M" {
		k = $2 "\t" $3
		comp = (k in served) ? served[k] : "-"
		x = $6 == "PASS" ? "-" : \
		    ((($2 "\t" $3 "_dqimpl") in xf) ? xf[$2 "\t" $3 "_dqimpl"] : \
		    "-")
		bad = ($6 != "PASS") != (comp != "-")
		if (!bad && comp != "-")
			bad = !((k in order) && order[k] == 1) ||
			    unhandled($2, comp, $6)
		printf("MARK\t%s\t%s\t%s\t%s\t%s\t%s\t%s%s\n", $2, $3, $4, $5,
		    $6, comp, x, bad ? "\tFLAG" : "")
		marked[k] = 1
	}
	$1 == "D" && !(($2 "\t" $3) in mserved) {
		mserved[$2 "\t" $3] = 1
	}
	$1 == "S" { printf("SLOT\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5) }
	$1 == "C" { printf("CONSULT\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5) }
	$1 == "N" && $4 == "UIO_USERSPACE" {
		c = cover($2, $3, $5)
		if (c == "") c = cited($6)
		printf("USERNDI\t%s\t%s\t%s\t%s\n", $2, $3, $5,
		    c != "" ? c : "UNMARKED")
	}
	$1 == "N" && $4 == "UIO_SYSSPACE" {
		printf("SYSNDI\t%s\t%s\t%s\t%s\n", $2, $3, $5,
		    sysclass($2, $3, $5, $6, $7, $8))
	}
	$1 == "N" && $4 != "UIO_USERSPACE" && $4 != "UIO_SYSSPACE" {
		c = cover($2, $3, $5)
		if (c == "") c = cited($6)
		printf("VARSEG\t%s\t%s\t%s\t%s\n", $2, $3, $4,
		    c != "" ? c : "FLAG")
	}
	$1 == "Q" && ($4 in wrapped) {
		printf("SYSCALL\t%s\t%s\t%s\t%s\n", $2, $3, $4,
		    sysclass($2, $3, "", $5, $6, $7))
	}
	END {
		for (k in served)
			if (!(k in marked))
				printf("SERVED\t%s\t%s\tFLAG\n", k, served[k])
	}' "$raw" "$raw"
	rm -f "$raw"
	scan_sockets "$1"
	scan_edq "$1"
}

# EDQRESOLVED in code (not comments), per file and the function or macro
# it appears in (D157): ALLOWED only for its definition (errno.h), the
# consumer macro (DQRES_SERVED), the producer (dqres_namei) and the stray
# mapping (syscall_dq_stray, syscallret's assertion).
scan_edq()
(
	cd "$1"
	if [ -n "$DQ_LEDGER_SOURCE_LIST" ]; then
		xargs grep -lE 'EDQRESOLVED' -- < "$DQ_LEDGER_SOURCE_LIST"
	else
		grep -rlE --include='*.c' --include='*.h' 'EDQRESOLVED' .
	fi |
	    sed 's,^\./,,' | LC_ALL=C sort | while read -r f; do
		awk -v file="$f" '
		/^[A-Za-z_][A-Za-z0-9_]*\(/ {
			fn = $0; sub(/\(.*/, "", fn)
		}
		/^#[ \t]*define[ \t]/ {
			mac = $0; sub(/^#[ \t]*define[ \t]+/, "", mac)
			sub(/[ \t(].*/, "", mac)
			inmac = 1
		}
		{
			code = $0
			if (code ~ /^[ \t]*(\*|\/\*|\/\/)/)
				code = ""
			sub(/\/\*.*/, "", code)
			if (code ~ /EDQRESOLVED/) {
				ctx = inmac ? mac : (fn != "" ? fn : "-")
				key = file ":" ctx
				if (!(key in seen)) {
					seen[key] = 1
					ok = key == "sys/errno.h:EDQRESOLVED" ||
					    key == "sys/dqres.h:DQRES_SERVED" ||
					    key == "kern/kern_dqres.c:dqres_namei" ||
					    key == "kern/kern_dqres.c:dqres_namei_served" ||
					    key == "kern/kern_dqres.c:dqres_namei_symlink" ||
					    key == "kern/kern_dqres.c:dq_symlink_served_root" ||
					    key == "kern/subr_syscall.c:syscall_dq_stray" ||
					    key == "kern/subr_syscall.c:syscallret"
					printf("EDQRESOLVED\t%s\t%s\n", key,
					    ok ? "ALLOWED" : "STRAY")
				}
			}
			if (inmac && $0 !~ /\\$/)
				inmac = 0
		}' "$f"
	done
)

case "$1" in
generate)
	generate "$2"
	;;
check)
	tmp=$(mktemp -t dqledger)
	generate "$2" > "$tmp"
	if ! cmp -s "$tmp" "$3"; then
		echo "dq_resolve_ledger: $3 is stale; regenerate it with" >&2
		echo "  sh $2/tools/dq_resolve_ledger.sh generate $2 > $3" >&2
		diff -u "$3" "$tmp" >&2 || true
		rm -f "$tmp"
		exit 1
	fi
	if grep -E '	(UNMARKED|FLAG|UNCLASSIFIED|STRAY)$' "$tmp" >&2; then
		echo "dq_resolve_ledger: unmarked or unclassified lookups" \
		    "above" >&2
		rm -f "$tmp"
		exit 1
	fi
	rm -f "$tmp"
	;;
*)
	echo "usage: $0 generate|check SRCDIR [LEDGER [SOURCE-LIST]]" >&2
	exit 2
	;;
esac
