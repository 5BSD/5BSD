# Rank UNCOVERED profile/supplement normative requirements by risk.
#
# Input:  spec_conf_profile_coverage_generated.tsv
# Output: score-ordered TSV: score, requirement_id, volume_part, section,
#         risk_classes, text
#
# The defect-class weights are identical to spec_conf_rank.awk, so a mesh gap
# and a Core gap are directly comparable.  Only the final layer-weighting block
# differs: it keys on the document family instead of the Core Volume/Part, and
# assigns the mesh security surface (provisioning, key material, network
# obfuscation and authentication) the same weight the Core list gives SMP.

function has(s, w) { return index(s, " " w " ") > 0 }

BEGIN {
	FS = "\t"
	OFS = "\t"
	if (REQS == "") {
		print "spec_conf_rank_profile: REQS not set" > "/dev/stderr"
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
	if (low ~ / key | keys | ltk | irk | csrk | edx | distribute | distributed | distribution | bond | bonded | bonding | netkey | appkey | devkey | device key /) {
		score += 30; cls = cls "key-distribution;"
	}
	if (low ~ / state | states | transition | until | before | after | while | pending | outstanding | in progress | shall not be sent | ignore | ignored /) {
		score += 25; cls = cls "state-machine;"
	}
	if (low ~ / error | error code | error response | reject | rejected | fail | failure /) {
		score += 25; cls = cls "error-code-selection;"
	}
	if (low ~ / per connection | each connection | connection specific | bearer | bearers | channel | channels | shared | subnet | subnets /) {
		score += 20; cls = cls "per-connection-state;"
	}

	# --- security -----------------------------------------------------
	if (low ~ / encrypt | encrypted | encryption | authenticate | authenticated | authentication | mitm | man in the middle | privacy | resolvable | random address | sign | signature | authorization | authorisation | security | obfuscat | nonce | replay /) {
		score += 35; cls = cls "security;"
	}

	# --- interoperability-mandatory ------------------------------------
	if (kw == "shall not" || kw == "must not") {
		score += 15; cls = cls "prohibition;"
	}
	if (low ~ / mandatory | shall support | shall be supported /) {
		score += 20; cls = cls "mandatory-support;"
	}

	# --- document weighting ---------------------------------------------
	# Mesh Protocol carries the mesh security TCB (provisioning, key
	# refresh, network obfuscation, replay protection); it is weighted like
	# Vol 3 Part H.  Mesh Model and the Supplement are peer-visible wire
	# surfaces, weighted like ATT/GATT.  HOGP/HIDS are profile layers over
	# an already-weighted GATT surface.
	if (vp ~ /^Mesh Protocol/)
		score += 20
	else if (vp ~ /^Mesh Model/)
		score += 15
	else if (vp ~ /^Supplement to the Bluetooth Core Specification/)
		score += 15
	else if (vp ~ /^HID Over GATT Profile|^HID Service/)
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
