# Attribute every extracted Core requirement to the Bluetooth generation that
# introduced the feature it governs.
#
# Inputs:
#   CORE=bluetooth-specs/Core_Specification_6_3.txt
#   MAP=spec_conf_generation_map.tsv
#   argv: spec_conf_requirements_generated.tsv
#
# Output (tab separated):
#   requirement_id  volume_part  section  generation  feature  evidence
#
# METHOD, and what it will and will not claim
# -------------------------------------------
# Two authorities inside the Core text itself give feature -> version:
#
#   [T42] Vol 0, Part D, Section 4, Table 4.2 "Features and their types".
#   [CH]  Vol 1, Part C "New features" bullet lists, one per version.
#
# Both are parsed here.  Every row of MAP must name a feature that one of them
# lists at the version MAP claims; a disagreement is a hard error, so the map
# cannot drift away from the specification silently.
#
# A requirement is then attributed by where it sits, not by what it says,
# wherever that is possible:
#
#   1. heading   The section heading of the requirement's own section, or of
#                the nearest ancestor section, contains a feature's recognising
#                phrase.  This is the strong signal: Core gives each feature its
#                own command, event and procedure sections, so the heading
#                identifies the feature the whole section governs.  The most
#                specific section wins, so a 5.4 sub-feature nested under a 5.0
#                chapter is attributed to 5.4.
#   2. sentence  Failing that, the normative sentence itself contains the
#                phrase.
#   3. UNKNOWN   Neither.  This is the honest answer for the large body of
#                baseline L2CAP/ATT/GATT/SMP/GAP text that predates the feature
#                table and is not attributable to any named feature.  UNKNOWN is
#                never treated as out of scope.
#
# The method deliberately cannot attribute a generation to text that names no
# feature.  It is built to answer one question reliably -- "is this requirement
# about something introduced after our target?" -- and to say UNKNOWN rather
# than guess when it cannot.

function norm(s) {
	gsub(/[ \t\r\f]+/, " ", s)
	sub(/^ /, "", s)
	sub(/ $/, "", s)
	return s
}

function fail(msg) {
	print "spec_conf_generation: " msg > "/dev/stderr"
	exit 1
}

# Read Table 4.2 and the change-history bullets; fill authv[feature] = version.
function read_core(   line, vp, skip, sec, in_t42, in_ch, chver, f, v, i, n, w) {
	in_t42 = 0
	in_ch = 0
	chver = ""
	while ((getline line < CORE) > 0) {
		if (line ~ /BLUETOOTH CORE SPECIFICATION Version/) {
			if (match(line, /Vol [0-9]+, Part [A-Z]+/))
				vp = substr(line, RSTART, RLENGTH)
			skip = 1
			continue
		}
		if (skip) { skip = 0; continue }
		if (line ~ /Bluetooth SIG Proprietary/)
			continue

		# --- [T42] Vol 0, Part D, Section 4, Table 4.2 ------------
		if (vp == "Vol 0, Part D") {
			if (line ~ /^ *Feature +Version +Type *$/) {
				in_t42 = 1
				continue
			}
			if (line ~ /^ *Table 4\.2:/) {
				in_t42 = 0
				continue
			}
			if (in_t42) {
				# "<feature>  <version>  <type>".  Long feature
				# names wrap onto a following line that carries no
				# version; such a line is the tail of the row above,
				# so it is appended to the last feature parsed.
				l = norm(line)
				if (l == "") continue
				if (match(l, / (1\.2|2\.0 \+ EDR|2\.1ded|2\.1\+? ?\.?\+? EDR|3\.0 \+ HS|4\.0|4\.1|4\.2|5\.0|5\.1|5\.2|5\.3|5\.4|6\.0|6\.1|6\.2|6\.3|Addendum [0-9]+\/?)( +[0-9n][^ ]*)? *$/)) {
					f = norm(substr(l, 1, RSTART))
					v = norm(substr(l, RSTART, RLENGTH))
					sub(/ +[0-9n][^ ]*$/, "", v)
					v = norm(v)
					sub(/\/$/, "", v)
					if (f != "") {
						t42[f] = v
						lastf = f
					}
					continue
				}
				if (lastf != "" && l !~ /Version Date|Page [0-9]/) {
					v = t42[lastf]
					delete t42[lastf]
					lastf = lastf " " l
					t42[lastf] = v
				}
				continue
			}
		}

		# --- [CH] Vol 1, Part C "New features" bullet lists --------
		if (vp == "Vol 1, Part C") {
			if (match(line, /new features? (is|are) introduced in (the )?v(ersion )?[0-9]+\.[0-9]+/)) {
				w = substr(line, RSTART, RLENGTH)
				if (match(w, /[0-9]+\.[0-9]+$/))
					chver = substr(w, RSTART, RLENGTH)
				in_ch = 1
				continue
			}
			if (in_ch) {
				l = norm(line)
				if (l ~ /^• /) {
					sub(/^• /, "", l)
					sub(/,.*$/, "", l)
					if (l != "")
						ch[l] = chver
					continue
				}
				if (l != "")
					in_ch = 0
			}
		}

		# --- section headings -------------------------------------
		if (line ~ /\.\.\.\./)
			continue
		if (line ~ /^\f?[0-9]+(\.[0-9]+)*[ \t]+[A-Za-z[]/) {
			h = line
			sub(/^\f/, "", h)
			if (match(h, /^[0-9]+(\.[0-9]+)*/)) {
				sec = substr(h, RSTART, RLENGTH)
				t = norm(substr(h, RSTART + RLENGTH))
				k = vp "|" sec
				if (!(k in head))
					head[k] = t
			}
		}
	}
	close(CORE)
	n = 0
	for (f in t42) n++
	if (n < 60)
		fail("Table 4.2 parse produced only " n " features")
	n = 0
	for (f in ch) n++
	if (n < 15)
		fail("change-history parse produced only " n " features")
}

# Confirm MAP's version claim against [T42] and [CH].
function verify(feature, version,   f, best) {
	if (feature in t42) {
		if (t42[feature] == version)
			return "T42"
		fail("map says " feature " is " version \
		    " but Table 4.2 says " t42[feature])
	}
	if (feature in ch) {
		if (ch[feature] == version)
			return "CH"
		fail("map says " feature " is " version \
		    " but the change history says " ch[feature])
	}
	# Table 4.2 wraps long names; accept a unique prefix match.
	best = ""
	for (f in t42) {
		if (index(f, feature) == 1 || index(feature, f) == 1) {
			if (best != "" && best != f)
				fail(feature " matches several Table 4.2 rows")
			best = f
		}
	}
	if (best != "") {
		if (t42[best] == version)
			return "T42"
		fail("map says " feature " is " version \
		    " but Table 4.2 says " t42[best] " for " best)
	}
	fail("map feature not found in Table 4.2 or the change history: " \
	    feature)
}

function vnum(v,   a) {
	split(v, a, ".")
	return a[1] * 1000 + a[2]
}

BEGIN {
	FS = "\t"
	OFS = "\t"
	if (CORE == "") fail("CORE not set")
	if (MAP == "") fail("MAP not set")
	if (TARGET == "") TARGET = "5.2"

	read_core()

	npat = 0
	while ((getline line < MAP) > 0) {
		if (line ~ /^#/ || line == "")
			continue
		n = split(line, f, "\t")
		if (n < 5 || f[1] == "feature")
			continue
		verify(f[1], f[2])
		npat++
		pf[npat] = f[1]
		pv[npat] = f[2]
		ps[npat] = f[3]
		pm[npat] = f[4]
		pp[npat] = tolower(f[5])
	}
	close(MAP)
	if (npat == 0)
		fail("no patterns read from " MAP)

	print "requirement_id", "volume_part", "section", "generation", \
	    "feature", "evidence"
	tgt = vnum(TARGET)
}

/^#/ { next }
$1 == "requirement_id" { next }

{
	rid = $1; vp = $2; sec = $3; text = $5

	gen = ""; feat = ""; ev = ""

	# 1. heading of this section, then of each ancestor.
	probe = sec
	while (probe != "" && gen == "") {
		h = head[vp "|" probe]
		if (h != "") {
			lh = tolower(h)
			bestv = -1
			for (i = 1; i <= npat; i++) {
				if (pm[i] != "heading" && pm[i] != "both")
					continue
				if (index(lh, pp[i]) == 0)
					continue
				# Most recent generation wins within one
				# heading: a 5.4 sub-feature named in a
				# heading is not a 5.0 feature.
				if (vnum(pv[i]) > bestv) {
					bestv = vnum(pv[i])
					gen = pv[i]; feat = pf[i]
					scp = ps[i]
					ev = "heading:" probe " \"" h "\""
				}
			}
		}
		if (probe !~ /\./)
			break
		sub(/\.[0-9]+$/, "", probe)
	}

	# 2. the sentence itself.
	if (gen == "") {
		lt = tolower(text)
		bestv = -1
		for (i = 1; i <= npat; i++) {
			if (pm[i] != "text" && pm[i] != "both")
				continue
			if (index(lt, pp[i]) == 0)
				continue
			if (vnum(pv[i]) > bestv) {
				bestv = vnum(pv[i])
				gen = pv[i]; feat = pf[i]
				scp = ps[i]
				ev = "sentence"
			}
		}
	}

	if (gen == "") {
		print rid, vp, sec, "UNKNOWN", "", "no-feature-attribution"
		next
	}
	if (scp == "in-scope-extra")
		ev = ev " [in-scope-extra]"
	print rid, vp, sec, gen, feat, ev
}
