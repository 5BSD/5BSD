# Classify every generated profile/supplement normative requirement as COVERED,
# UNCOVERED, or NOT-APPLICABLE, using the existing traceability matrix as the
# coverage index.
#
# This is the profile-document counterpart of spec_conf_coverage.awk.  The Core
# classifier attributes matrix rows by "Vol N, Part X" locators; the documents
# handled here (Mesh Protocol, Mesh Model, Core Specification Supplement, HID
# Over GATT Profile, HID Service) are cited by name instead, so attribution is
# by document family and, for the Supplement, by part.
#
# Inputs:
#   MATRIX=spec_requirements.tsv        (requirement_id, exact_reference,
#                                        kyua_selector, oracle)
#   argv: spec_conf_profile_requirements_generated.tsv
#
# Output (tab separated):
#   requirement_id  volume_part  section  status  detail  covering_rows  keyword
#
# Method and its limits, stated plainly:
#
#   The matrix cites specification *sections*, never individual normative
#   sentences, so the strongest honest claim is section-level attribution.  A
#   requirement is COVERED only when its exact section is cited by a matrix row
#   whose oracle is independent of the implementation.  A section named only by
#   a row whose oracle compares our code to our code is UNCOVERED with detail
#   "section-touched-weak-oracle"; a section reached only through an ancestor
#   citation is UNCOVERED with detail "ancestor-section-only-no-direct-citation".
#
#   Citations are matched by document *family*, not by document version.  Six
#   matrix rows cite "CSS v12" while the in-tree normative text is v15; matching
#   on family keeps those rows attributable, and the version skew is counted and
#   reported separately by spec_conf_generate_profile.sh rather than silently
#   resolved here.
#
#   NOT-APPLICABLE is asserted only for roles and features this stack does not
#   implement: blued is a HID Host and never a HID Device, and it implements no
#   HID ISO transport.
#
#   The Supplement gets one further exclusion on the same footing.  CSS v15
#   specifies every advertising data type the SIG has assigned, including 5.4
#   additions and data types owned by profiles this stack does not implement,
#   so measuring blued against all of Part A measures it against a superset of
#   what any 5.2-era stack advertises.  ADSCOPE carries the Part A sections
#   reached from the AD types blued's own source defines, derived by
#   spec_conf_css_adscope.awk from Assigned Numbers Section 2.3; a Part A
#   section outside it is NOT-APPLICABLE with the reason naming the data type
#   scope, so nothing is dropped without one.

# A Part A section is in scope when it, or the data-type section it belongs to,
# is one of the sections reached from blued's AD types.  Chapter-level rows
# (a bare "1") govern the whole of Part A and are always kept.
function css_ad_in_scope(sec,   probe) {
	if (sec !~ /\./)
		return 1
	probe = sec
	while (probe ~ /\./) {
		if (probe in adsec)
			return 1
		sub(/\.[0-9]+$/, "", probe)
	}
	return 0
}

function norm_sec(s) {
	sub(/^§+/, "", s)
	sub(/[.,;:)]+$/, "", s)
	return s
}

function record(doc, part, sec, row,   key) {
	if (sec == "")
		return
	key = doc "|" part "|" sec
	if (cited[key] == "")
		cited[key] = row
	else if (index(cited[key], row) == 0)
		cited[key] = cited[key] "," row
}

# Identify which document family a reference segment names, strip the document
# name and its version token so the version is never mistaken for a section,
# and return the family tag ("" if the segment names none of our documents).
function doc_of(seg,   d, i, n, pats, tag) {
	# Order matters: "Mesh Model" must be tested before "Mesh Protocol"
	# only in that both may appear; each is matched independently below.
	if (seg ~ /Mesh Model|MshMDL|MMDL/) {
		docfam = "MSHMDL111"
		gsub(/Mesh Model( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
		gsub(/MshMDL(_v[0-9]+(\.[0-9]+)*)?/, " ", seg)
		gsub(/MMDL( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
	} else if (seg ~ /Mesh Protocol|MshPRT|Mesh Remote Provisioning/) {
		docfam = "MSHPRT111"
		gsub(/Mesh Protocol( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
		gsub(/MshPRT(_v[0-9]+(\.[0-9]+)*)?/, " ", seg)
		gsub(/Mesh Remote Provisioning( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
	} else if (seg ~ /CSS|Core Specification Supplement/) {
		docfam = "CSS15"
		gsub(/Core Specification Supplement( v?[0-9]+(\.[0-9]+)*)?/, \
		    " ", seg)
		gsub(/CSS( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
	} else if (seg ~ /HID [Oo]ver GATT|HOGP/) {
		docfam = "HOGP11"
		gsub(/HID [Oo]ver GATT Profile( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
		gsub(/HOGP( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
	} else if (seg ~ /HID Service|HIDS/) {
		docfam = "HIDS11"
		gsub(/HID Service( Specification)?( v?[0-9]+(\.[0-9]+)*)?/, \
		    " ", seg)
		gsub(/HIDS( v?[0-9]+(\.[0-9]+)*)?/, " ", seg)
	} else {
		docfam = ""
	}
	# Part locator, used by the Supplement only.
	docpart = ""
	if (docfam == "CSS15") {
		if (seg ~ /Part A/)
			docpart = "V1PA"
		else if (seg ~ /Part B/)
			docpart = "V1PB"
		else if (seg ~ /Part C/)
			docpart = "V1PC"
		gsub(/Vol [0-9]+,? ?/, " ", seg)
		gsub(/Parts? [A-Z](\/[A-Z])*/, " ", seg)
	}
	segout = seg
	return docfam
}

BEGIN {
	FS = "\t"
	OFS = "\t"
	if (MATRIX == "") {
		print "spec_conf_coverage_profile: MATRIX not set" > "/dev/stderr"
		exit 1
	}
	nadsec = split(ADSCOPE, adsecl, ",")
	for (i = 1; i <= nadsec; i++)
		if (adsecl[i] != "")
			adsec[adsecl[i]] = 1
	while ((getline line < MATRIX) > 0) {
		if (line ~ /^#/ || line == "")
			continue
		n = split(line, f, "\t")
		if (n < 4)
			continue
		rid = f[1]
		ref = f[2]
		oracle = f[4]
		# Independent-oracle heuristic, identical to spec_conf_coverage.awk:
		# the oracle must claim an origin outside the implementation.
		strong = 0
		if (oracle ~ /[Ii]ndependent|[Pp]ublished|[Gg]enerated|NIST|FIPS|RFC|AESAVS|known-answer|KAT|Appendix|sample data|Core-defined|test vector|vectors/)
			strong = 1
		strongrow[rid] = strong
		gsub(/§/, " ", ref)
		# One reference may cite several documents; they are separated
		# by semicolons in every row of the matrix.
		nseg = split(ref, segs, ";")
		for (i = 1; i <= nseg; i++) {
			d = doc_of(segs[i])
			if (d == "")
				continue
			if (d == "CSS15" && docpart != "")
				citedver[d "|" docpart] = 1
			part = docpart
			rest = segout
			nsec = 0
			# Dotted section numbers, plus bare integers that are
			# left over once the document name and version have
			# been removed.
			while (match(rest, /[0-9]+(\.[0-9]+)+/)) {
				secl[++nsec] = substr(rest, RSTART, RLENGTH)
				rest = substr(rest, RSTART + RLENGTH)
			}
			rest = segout
			gsub(/[0-9]+(\.[0-9]+)+/, " ", rest)
			while (match(rest, /[0-9]+/)) {
				secl[++nsec] = substr(rest, RSTART, RLENGTH)
				rest = substr(rest, RSTART + RLENGTH)
			}
			for (j = 1; j <= nsec; j++)
				record(d, part, secl[j], rid)
			# The Supplement is also cited without a part; attribute
			# such rows to Part A, the only part blued reads.
			if (d == "CSS15" && part == "")
				for (j = 1; j <= nsec; j++)
					record(d, "V1PA", secl[j], rid)
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

	# Recover the document tag and part from the requirement id.
	doc = rid
	sub(/-.*$/, "", doc)
	part = ""
	if (rid ~ /^CSS15-V[0-9]P[A-Z]-/) {
		part = rid
		sub(/^CSS15-/, "", part)
		sub(/-.*$/, "", part)
	}

	# --- applicability ------------------------------------------------
	lower = tolower(text)
	na = ""
	if (lower ~ /the controller shall|the controller must/)
		na = "controller-responsibility"
	else if (lower ~ /the link layer shall/)
		na = "link-layer-responsibility"
	else if (lower ~ /the iut shall|test case|test suite/)
		na = "test-specification-language"
	else if ((doc == "HOGP11" || doc == "HIDS11") && \
	    lower ~ /the hid device shall|a hid device shall|hid devices shall/)
		# blued is a HID Host: it discovers and consumes a HID Service,
		# and never publishes one.  Requirements addressed to the HID
		# Device are not requirements on this stack.
		na = "hid-device-role-not-implemented"
	else if (doc == "CSS15" && part == "V1PA" && nadsec > 0 && sec != "" &&
	    !css_ad_in_scope(sec))
		na = "advertising data type not emitted or parsed by blued" \
		    " (Part A sections in scope: " ADSCOPE ")"
	else if (doc == "HOGP11" && (sec ~ /^5(\.|$)/ || sec ~ /^6(\.|$)/))
		# HOGP 1.1 chapters 5 and 6 are the LE Audio HID ISO transport
		# and its service.  blued implements no HID ISO path.
		na = "hid-iso-not-implemented"

	# --- section-level attribution ------------------------------------
	best = ""
	beststrong = 0
	exact = 0
	probe = sec
	depth = 0
	while (probe != "") {
		key = doc "|" part "|" probe
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
