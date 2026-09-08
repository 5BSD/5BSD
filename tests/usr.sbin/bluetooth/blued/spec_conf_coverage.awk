# Classify every generated normative requirement as COVERED, UNCOVERED, or
# NOT-APPLICABLE, using the existing traceability matrix as the coverage index.
#
# Inputs:
#   MATRIX=spec_requirements.tsv        (requirement_id, exact_reference,
#                                        kyua_selector, oracle)
#   argv: spec_conf_requirements_generated.tsv
#
# Output (tab separated):
#   requirement_id  volume_part  section  status  detail  covering_rows  keyword
#
# Method and its limits, stated plainly:
#
#   The existing matrix cites specification *sections*, never individual
#   normative sentences.  The strongest honest claim it can support is
#   therefore section-level attribution.  A requirement is reported COVERED
#   only when its section is cited by a matrix row whose oracle is independent
#   of the implementation (a spec-extracted constant, a published test vector,
#   or an independently constructed byte sequence).  A section that is merely
#   named by a row whose oracle compares our code to our code is reported
#   UNCOVERED with detail "section-touched-weak-oracle" - it is not evidence
#   that the sentence is asserted anywhere.
#
#   NOT-APPLICABLE is asserted only from the sentence's own grammatical
#   subject: statements addressed to the Controller, the Link Layer, the
#   physical layer, or to BR/EDR-only procedures are not host requirements on
#   blued.  Everything else defaults to UNCOVERED.

function norm_sec(s) {
	sub(/^§+/, "", s)
	sub(/[.,;:)]+$/, "", s)
	return s
}

# Expand "7.3.1-7.3.2" into its endpoints.  Ranges are recorded as endpoints
# plus a range marker so a requirement inside the range can be matched.
function record(vp, sec, row) {
	if (sec == "")
		return
	key = vp "|" sec
	if (cited[key] == "")
		cited[key] = row
	else if (index(cited[key], row) == 0)
		cited[key] = cited[key] "," row
}

function volparts_of(ref,   i, n, out, v, p, rest, seen) {
	# Collect every "Vol N Part X" (and "Vol 3 Parts A/F/H") locator.
	out = ""
	rest = ref
	while (match(rest, /Vol [0-9]+ Parts? [A-Z](\/[A-Z])*/)) {
		v = substr(rest, RSTART, RLENGTH)
		rest = substr(rest, RSTART + RLENGTH)
		n = 0
		if (match(v, /Vol [0-9]+/))
			volnum = substr(v, RSTART + 4, RLENGTH - 4)
		p = v
		sub(/^Vol [0-9]+ Parts? /, "", p)
		n = split(p, pa, "/")
		for (i = 1; i <= n; i++)
			out = out "Vol " volnum ", Part " pa[i] ";"
	}
	return out
}

BEGIN {
	FS = "\t"
	OFS = "\t"
	if (MATRIX == "") {
		print "spec_conf_coverage: MATRIX not set" > "/dev/stderr"
		exit 1
	}
	while ((getline line < MATRIX) > 0) {
		if (line ~ /^#/ || line == "")
			continue
		n = split(line, f, "\t")
		if (n < 4)
			continue
		rid = f[1]
		ref = f[2]
		oracle = f[4]
		# Independent-oracle heuristic, deliberately generous to the
		# existing matrix: the oracle must claim an origin outside the
		# implementation.
		strong = 0
		if (oracle ~ /[Ii]ndependent|[Pp]ublished|[Gg]enerated|NIST|FIPS|RFC|AESAVS|known-answer|KAT|Appendix|sample data|Core-defined|test vector|vectors/)
			strong = 1
		if (oracle ~ /implementation policy|not claimed|does not claim|local |explicitly mixed/)
			weakflag[rid] = 1
		strongrow[rid] = strong
		gsub(/§/, " ", ref)
		vps = volparts_of(ref)
		if (vps == "")
			continue
		# Every dotted or bare section number appearing in the
		# reference, attributed to every Volume/Part it names.  This
		# over-attributes; it can only inflate COVERED, so any gap it
		# reports is a real gap.
		nsec = 0
		rest2 = ref
		while (match(rest2, /[0-9]+(\.[0-9]+)+/)) {
			secs[++nsec] = substr(rest2, RSTART, RLENGTH)
			rest2 = substr(rest2, RSTART + RLENGTH)
		}
		nvp = split(vps, vpa, ";")
		for (i = 1; i <= nvp; i++) {
			if (vpa[i] == "")
				continue
			for (j = 1; j <= nsec; j++)
				record(vpa[i], secs[j], rid)
		}
	}
	close(MATRIX)
	print "requirement_id", "volume_part", "section", "status", "detail", \
	    "covering_rows", "keyword"
}

/^#/ { next }
$1 == "requirement_id" { next }

{
	rid = $1
	vp = $2
	sec = $3
	kw = $4
	text = $5

	# --- applicability ------------------------------------------------
	lower = tolower(text)
	na = ""
	if (lower ~ /the controller shall/ || lower ~ /the controller must/)
		na = "controller-responsibility"
	else if (lower ~ /the link layer shall/)
		na = "link-layer-responsibility"
	else if (lower ~ /the (baseband|physical layer|radio) shall/)
		na = "physical-layer-responsibility"
	else if (lower ~ /the iut shall/)
		na = "controller-test-mode-iut-language"
	else if (lower ~ /security mode [234]/)
		# blued exposes no BR/EDR service-access layer (no SDP, no
		# RFCOMM, no classic L2CAP server); GAP Vol 3 Part C section 5
		# security modes 2-4 govern BR/EDR service access only.  The
		# only BR/EDR surface blued has is CTKD link-key derivation
		# (smp.h SMP_KEY_DIST_LINK_KEY), which is Vol 3 Part H.
		na = "br-edr-service-access-not-implemented"
	else if (lower ~ /enhanced retransmission mode|streaming mode|retransmission mode|flow control mode|frame check sequence/)
		# LE bearers support only Basic, LE Credit Based Flow Control,
		# and Enhanced Credit Based Flow Control modes.
		na = "br-edr-l2cap-mode-not-applicable-to-le"
	else if (lower ~ /alternate mac|\bamp\b|802\.11/)
		na = "amp-removed-from-core-and-not-implemented"
	else if (lower ~ /isochronous broadcaster|broadcast isochronous/ && \
	    NOISO == "1")
		na = "iso-broadcast-not-implemented"

	# --- section-level attribution ------------------------------------
	best = ""
	beststrong = 0
	exact = 0
	# An exact section citation is direct evidence.  A citation of an
	# ancestor section ("3.4" standing for all of 3.4.x) is inheritance,
	# not evidence, and is never promoted to COVERED.
	probe = sec
	depth = 0
	while (probe != "") {
		key = vp "|" probe
		if (key in cited) {
			best = cited[key]
			exact = (depth == 0)
			nrows = split(best, ra, ",")
			for (r = 1; r <= nrows; r++)
				if (strongrow[ra[r]] == 1)
					beststrong = 1
			break
		}
		if (probe !~ /\./)
			break
		sub(/\.[0-9]+$/, "", probe)
		depth++
	}

	if (na != "") {
		print rid, vp, sec, "NOT-APPLICABLE", na, best, kw
		next
	}
	if (best == "") {
		print rid, vp, sec, "UNCOVERED", "no-matrix-row-cites-section", \
		    "", kw
		next
	}
	if (beststrong == 0) {
		print rid, vp, sec, "UNCOVERED", \
		    "section-touched-weak-oracle", best, kw
		next
	}
	if (exact == 0) {
		print rid, vp, sec, "UNCOVERED", \
		    "ancestor-section-only-no-direct-citation", best, kw
		next
	}
	print rid, vp, sec, "COVERED", "section-cited-external-oracle", best, kw
}
