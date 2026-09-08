# Extract normative requirements from the Bluetooth Core Specification text.
#
# Input:  Core_Specification_6_3.txt (the machine-readable render of the PDF).
# Output: a tab-separated catalogue of normative statements for the layers this
#         stack implements.  The output is a pure function of the input text and
#         of the scope table below, so it can be regenerated and diffed to
#         detect drift exactly like generate_core63_oracles.awk.
#
# Columns:
#   requirement_id  stable id: CORE63-V<vol>P<part>-<section>-<ordinal>
#   volume_part     e.g. "Vol 3, Part F"
#   section         nearest preceding numbered heading, e.g. "3.4.1.1"
#   keyword         shall | shall not | must | must not | mandatory-table
#   text            the verbatim normative sentence (whitespace-normalised)
#
# Scope: only volumes/parts this host stack implements are emitted.  Vol 4
# Part E (HCI) and Vol 6 Part B (Link Layer) are additionally narrowed by
# section prefix, because blued is a host and is responsible for only a small
# slice of those Parts.  The HCI section allow-list is generated from the
# opcodes blued actually issues (see spec_conf_generate.sh).

function norm(s) {
	gsub(/[ \t\r\f]+/, " ", s)
	sub(/^ /, "", s)
	sub(/ $/, "", s)
	return s
}

# Return 1 if the current Vol/Part is in scope at all.
function part_in_scope(vp) {
	return (vp in scope_part)
}

# Return 1 if section "sec" passes the per-part section filter (if any).
function section_in_scope(vp, sec,   i, n, pref) {
	if (!(vp in scope_prefix))
		return 1
	if (sec == "")
		return 0
	n = split(scope_prefix[vp], pref, ",")
	for (i = 1; i <= n; i++) {
		if (pref[i] == "")
			continue
		if (sec == pref[i])
			return 1
		if (index(sec ".", pref[i] ".") == 1)
			return 1
	}
	return 0
}

function flush_para(   text, i, n, parts, s, kw, id, lower) {
	text = norm(para)
	para = ""
	if (text == "")
		return
	if (!part_in_scope(cur_vp))
		return
	if (!section_in_scope(cur_vp, cur_sec))
		return

	# Protect abbreviations and section/figure/table cross references so the
	# sentence splitter does not cut inside them.
	gsub(/e\.g\./, "e<DOT>g<DOT>", text)
	gsub(/i\.e\./, "i<DOT>e<DOT>", text)
	gsub(/etc\./, "etc<DOT>", text)
	gsub(/Vol\./, "Vol<DOT>", text)
	gsub(/Fig\./, "Fig<DOT>", text)
	gsub(/No\./, "No<DOT>", text)
	# A period between digits or before a digit is a section number, not a
	# sentence end.
	while (match(text, /[0-9]\.[0-9]/)) {
		text = substr(text, 1, RSTART) "<DOT>" \
		    substr(text, RSTART + 2)
	}

	n = split(text, parts, /\. /)
	for (i = 1; i <= n; i++) {
		s = parts[i]
		if (i < n)
			s = s "."
		s = norm(s)
		gsub(/<DOT>/, ".", s)
		if (length(s) < 20)
			continue
		# Word-boundary matching without GNU extensions: reduce the
		# sentence to space-delimited lowercase words.
		lower = tolower(s)
		gsub(/[^a-z0-9]+/, " ", lower)
		lower = " " lower " "
		kw = ""
		if (index(lower, " shall not ") > 0)
			kw = "shall not"
		else if (index(lower, " shall ") > 0)
			kw = "shall"
		else if (index(lower, " must not ") > 0)
			kw = "must not"
		else if (index(lower, " must ") > 0)
			kw = "must"
		if (kw == "")
			continue
		# Boilerplate and conformance-language definitions are not
		# requirements on an implementation.
		if (s ~ /Bluetooth SIG Proprietary/)
			continue
		if (index(lower, " the term shall ") > 0)
			continue
		if (index(lower, " keywords shall ") > 0)
			continue
		ord[cur_vp SUBSEP cur_sec]++
		id = sprintf("CORE63-%s-%s-%02d", tag[cur_vp], \
		    (cur_sec == "" ? "0" : cur_sec), ord[cur_vp SUBSEP cur_sec])
		printf "%s\t%s\t%s\t%s\t%s\n", id, cur_vp, cur_sec, kw, s
		emitted++
	}
}

BEGIN {
	FS = "\n"
	OFS = "\t"

	# --- scope table -------------------------------------------------
	# Host layers implemented by blued/libble.
	scope_part["Vol 3, Part A"] = 1	# L2CAP
	scope_part["Vol 3, Part C"] = 1	# GAP
	scope_part["Vol 3, Part F"] = 1	# ATT
	scope_part["Vol 3, Part G"] = 1	# GATT
	scope_part["Vol 3, Part H"] = 1	# SMP
	scope_part["Vol 4, Part E"] = 1	# HCI (section-scoped)
	scope_part["Vol 6, Part B"] = 1	# Link Layer (section-scoped)

	tag["Vol 3, Part A"] = "V3PA"
	tag["Vol 3, Part C"] = "V3PC"
	tag["Vol 3, Part F"] = "V3PF"
	tag["Vol 3, Part G"] = "V3PG"
	tag["Vol 3, Part H"] = "V3PH"
	tag["Vol 4, Part E"] = "V4PE"
	tag["Vol 6, Part B"] = "V6PB"

	# Vol 6 Part B: only the areas for which the host, not the controller,
	# carries the requirement (device addresses, privacy/RPA generation and
	# resolution, and the feature-support table the host consults).
	scope_prefix["Vol 6, Part B"] = "1.3,4.7,6"

	# Vol 4 Part E: narrowed by the caller.  HCI_SECTIONS is a
	# comma-separated list of section prefixes derived from the opcodes
	# blued issues; if unset, fall back to the LE command/event chapters.
	if (HCI_SECTIONS != "")
		scope_prefix["Vol 4, Part E"] = HCI_SECTIONS
	else
		scope_prefix["Vol 4, Part E"] = "7.7.65,7.8"

	cur_vp = ""
	cur_sec = ""
	para = ""
	skip_title = 0
	emitted = 0
}

# Page header carries the authoritative Volume/Part locator.
/BLUETOOTH CORE SPECIFICATION Version/ {
	if (match($0, /Vol [0-9]+, Part [A-Z]+/)) {
		newvp = substr($0, RSTART, RLENGTH)
		if (newvp != cur_vp) {
			flush_para()
			cur_vp = newvp
			cur_sec = ""
		}
	}
	skip_title = 1
	next
}

# The line directly after the page header is the running Part title.
skip_title == 1 {
	skip_title = 0
	next
}

/Bluetooth SIG Proprietary/ { next }
/^[ \t]*Page [0-9]+[ \t]*$/ { next }

# Table-of-contents lines use dot leaders.
/\.\.\.\./ { flush_para(); next }

# Figure and table captions break paragraphs but are not sentences.
/^[ \t]*(Figure|Table) [0-9]+\.[0-9]+:/ { flush_para(); next }

# Numbered heading at column zero starts a new section.
/^\f?[0-9]+(\.[0-9]+)*[ \t]+[A-Za-z[]/ {
	flush_para()
	head = $0
	sub(/^\f/, "", head)
	if (match(head, /^[0-9]+(\.[0-9]+)*/))
		cur_sec = substr(head, RSTART, RLENGTH)
	next
}

# Blank line ends a paragraph.
/^[ \t\f]*$/ { flush_para(); next }

{
	line = norm($0)
	if (line == "")
		next
	if (para == "")
		para = line
	else
		para = para " " line
}

END {
	flush_para()
	if (emitted == 0) {
		print "spec_conf: no normative requirements extracted" > \
		    "/dev/stderr"
		exit 1
	}
}
