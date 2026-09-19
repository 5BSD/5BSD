# Rank UNCOVERED normative requirements by risk.
#
# Input:  spec_conf_coverage_generated.tsv
# Output: score-ordered TSV: score, requirement_id, volume_part, section,
#         risk_classes, text
#
# The weights encode the defect classes this project has actually shipped:
# byte order and wire representation, key-distribution rules, state-machine
# and PDU-legality transitions, error-code selection, and per-connection versus
# shared state.  Interoperability-mandatory language and security relevance are
# weighted on top of those.

function has(s, w) { return index(s, " " w " ") > 0 }

BEGIN {
	FS = "\t"
	OFS = "\t"
	if (REQS == "") {
		print "spec_conf_rank: REQS not set" > "/dev/stderr"
		exit 1
	}
	while ((getline line < REQS) > 0) {
		if (line ~ /^#/ || line == "")
			continue
		n = split(line, r, "\t")
		if (n < 5 || r[1] == "requirement_id")
			continue
		req[r[1]] = r[5]
	}
	close(REQS)
	print "score", "requirement_id", "volume_part", "section", \
	    "risk_classes", "text"
}

NR == 1 { next }
$4 != "UNCOVERED" { next }

{
	rid = $1; vp = $2; sec = $3; kw = $7
	detail = $5
	sentence = req[rid]
	if (sentence == "")
		next

	low = " " tolower(sentence) " "
	gsub(/[^a-z0-9]+/, " ", low)
	low = " " low " "

	score = 0
	cls = ""

	# --- historically defect-dense classes ---------------------------
	if (low ~ / octet | octets | byte | bytes | little endian | endian | format | field | fields | encoded | encoding | length | size /) {
		score += 30; cls = cls "wire-representation;"
	}
	if (low ~ / key | keys | ltk | irk | csrk | edx | distribute | distributed | distribution | bond | bonded | bonding /) {
		score += 30; cls = cls "key-distribution;"
	}
	if (low ~ / state | states | transition | until | before | after | while | pending | outstanding | in progress | shall not be sent | ignore | ignored /) {
		score += 25; cls = cls "state-machine;"
	}
	if (low ~ / error | error code | error response | reject | rejected | fail | failure /) {
		score += 25; cls = cls "error-code-selection;"
	}
	if (low ~ / per connection | each connection | connection specific | bearer | bearers | channel | channels | shared /) {
		score += 20; cls = cls "per-connection-state;"
	}

	# --- security -----------------------------------------------------
	if (low ~ / encrypt | encrypted | encryption | authenticate | authenticated | authentication | mitm | man in the middle | privacy | resolvable | random address | sign | signature | authorization | authorisation | security /) {
		score += 35; cls = cls "security;"
	}

	# --- interoperability-mandatory ------------------------------------
	if (kw == "shall not" || kw == "must not") {
		score += 15; cls = cls "prohibition;"
	}
	if (low ~ / mandatory | shall support | shall be supported /) {
		score += 20; cls = cls "mandatory-support;"
	}

	# --- layer weighting ------------------------------------------------
	if (vp == "Vol 3, Part F" || vp == "Vol 3, Part G")
		score += 15	# ATT/GATT: every peer exercises these
	else if (vp == "Vol 3, Part H")
		score += 20	# SMP: security TCB
	else if (vp == "Vol 3, Part A")
		score += 10
	else if (vp == "Vol 3, Part C")
		score += 10

	# A requirement whose section nothing cites at all is a wider hole than
	# one whose section is at least touched.
	if (detail == "no-matrix-row-cites-section")
		score += 10

	sub(/;$/, "", cls)
	if (cls == "")
		cls = "general"
	printf "%d\t%s\t%s\t%s\t%s\t%s\n", score, rid, vp, sec, cls, sentence
}
