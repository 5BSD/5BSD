# Extract normative requirements from a Bluetooth SIG profile/supplement
# specification text (Mesh Protocol, Mesh Model, Core Specification Supplement,
# HID Over GATT Profile, HID Service).
#
# Input:  the machine-readable render of one SIG PDF, produced by
#         "pdftotext -layout" exactly as bluetooth-specs/Core_Specification_6_3.txt
#         was produced.
# Output: a tab-separated catalogue of normative statements, in the same schema
#         and with the same sentence rules as spec_conf_extract_requirements.awk,
#         so the Core and profile catalogues can be concatenated and classified
#         by one coverage pass.  The output is a pure function of the input text
#         and of the variables below, so it can be regenerated and diffed to
#         detect drift.
#
# Columns:
#   requirement_id  stable id: <DOC>[-<part tag>]-<section>-<ordinal>
#   volume_part     document name, plus ", Vol N, Part X" for part-structured
#                   documents (the Core Specification Supplement)
#   section         nearest preceding numbered heading, e.g. "3.4.6.3"
#   keyword         shall | shall not | must | must not
#   text            the verbatim normative sentence (whitespace-normalised)
#
# Variables (all set by spec_conf_generate_profile.sh):
#   DOC       short document tag used as the requirement-id prefix, e.g.
#             MSHPRT111, MSHMDL111, CSS15, HOGP11, HIDS11
#   DOCNAME   human document name, e.g. "Mesh Protocol 1.1.1"
#   HEADRE    regex matching the running page header line, which is dropped
#   PARTED    "1" if the document carries "Vol N, Part X" part headers (CSS)
#   SECTIONS  optional comma-separated list of in-scope section prefixes; empty
#             means the whole document is in scope
#   PARTS     optional comma-separated list of in-scope part tags (e.g. V1PA)
#
# Scope is a deliberate, reviewable statement of which chapters of a document
# this stack is responsible for.  It is narrowed only where a chapter describes
# a role the stack does not implement, never to flatter the coverage number.

function norm(s) {
	gsub(/[ \t\r\f]+/, " ", s)
	sub(/^ /, "", s)
	sub(/ $/, "", s)
	return s
}

# Return 1 if the current part is in scope (documents without parts always are).
function part_in_scope(   i, n, p) {
	if (PARTS == "")
		return 1
	if (cur_parttag == "")
		return 0
	n = split(PARTS, p, ",")
	for (i = 1; i <= n; i++)
		if (p[i] == cur_parttag)
			return 1
	return 0
}

# Return 1 if section "sec" passes the section filter (if any).
function section_in_scope(sec,   i, n, pref) {
	if (SECTIONS == "")
		return 1
	if (sec == "")
		return 0
	n = split(SECTIONS, pref, ",")
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

function locator(   l) {
	l = DOCNAME
	if (cur_part != "")
		l = l ", " cur_part
	return l
}

function flush_para(   text, i, n, parts, s, kw, id, lower, key) {
	text = norm(para)
	para = ""
	if (text == "")
		return
	if (!part_in_scope())
		return
	if (!section_in_scope(cur_sec))
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
		# Front-matter licence and disclaimer text.
		if (index(lower, " this specification is your acknowledgement ") > 0)
			continue
		if (index(lower, " bluetooth sig ") > 0 && \
		    index(lower, " licen ") > 0)
			continue
		key = cur_parttag SUBSEP cur_sec
		ord[key]++
		id = DOC (cur_parttag == "" ? "" : "-" cur_parttag) "-" \
		    (cur_sec == "" ? "0" : cur_sec) \
		    sprintf("-%02d", ord[key])
		printf "%s\t%s\t%s\t%s\t%s\n", id, locator(), cur_sec, kw, s
		emitted++
	}
}

BEGIN {
	FS = "\n"
	OFS = "\t"
	if (DOC == "" || DOCNAME == "" || HEADRE == "") {
		print "spec_conf_profile: DOC, DOCNAME and HEADRE required" > \
		    "/dev/stderr"
		exit 1
	}
	cur_sec = ""
	cur_part = ""
	cur_parttag = ""
	para = ""
	skip_title = 0
	emitted = 0
}

# Running page header.  It carries no content and never belongs to a paragraph.
$0 ~ HEADRE {
	flush_para()
	next
}

# Part header (Core Specification Supplement only): "Vol 1, Part A" followed by
# the running part title on the next line.
PARTED == "1" && /^[ \t]*Vol [0-9]+, Part [A-Z][ \t]*$/ {
	flush_para()
	newpart = norm($0)
	if (newpart != cur_part) {
		cur_part = newpart
		cur_sec = ""
	}
	cur_parttag = cur_part
	sub(/^Vol /, "V", cur_parttag)
	sub(/, Part /, "P", cur_parttag)
	skip_title = 1
	next
}

skip_title == 1 {
	skip_title = 0
	next
}

/Bluetooth SIG Proprietary/ { next }
/^[ \t]*Page [0-9]+[ \t]*$/ { next }
/^[ \t]*Version Date:/ { next }

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
		print "spec_conf_profile: no normative requirements extracted" \
		    > "/dev/stderr"
		exit 1
	}
}
