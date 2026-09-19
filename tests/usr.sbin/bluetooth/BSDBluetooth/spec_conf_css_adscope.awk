# Derive the Core Specification Supplement Part A sections that are in scope
# for this stack, from the AD types blued actually emits and parses.
#
# Input:  bluetooth-specs/Assigned_Numbers.html
#         ADTYPES=file listing the AD type values found in the blued and
#                 libble sources, one "0xNN" per line
# Output: a comma-separated list of CSS Part A section numbers on stdout, and
#         a human-readable audit trail on stderr.
#
# WHY
# ---
# CSS v15 defines every advertising and EIR data type the SIG has ever
# assigned, including 5.4 additions (Encrypted Advertising Data, Periodic
# Advertising Response Timing Information) and data types for profiles this
# stack does not implement.  Measuring blued against all of them measures it
# against a superset of what any 5.2-era stack advertises.
#
# The scope is therefore taken from the intersection of two machine-readable
# facts, neither of them editorial:
#
#   * the AD type values defined in the blued/libble source, and
#   * Assigned Numbers, Section 2.3 "Common Data Types", which maps each AD
#     type value to the CSS Part A section that specifies it.
#
# An AD type whose Assigned Numbers reference is not CSS (the three Mesh types,
# 0x29/0x2A/0x2B, are specified by the Mesh Protocol) contributes no CSS
# section and is reported separately.

BEGIN {
	# ADTYPES is read line by line, so RS is only switched to the table-row
	# separator once that file has been consumed.
	RS = "\n"
	if (ADTYPES == "") {
		print "spec_conf_css_adscope: ADTYPES not set" > "/dev/stderr"
		exit 1
	}
	while ((getline line < ADTYPES) > 0) {
		gsub(/[ \t\r]/, "", line)
		if (line == "")
			continue
		line = toupper(line)
		sub(/^0X/, "0x", line)
		want[line] = 1
		nwant++
	}
	close(ADTYPES)
	RS = "</tr>"
	if (nwant == 0) {
		print "spec_conf_css_adscope: no AD types supplied" > \
		    "/dev/stderr"
		exit 1
	}
}

{
	row = $0
	gsub(/<[^>]*>/, " ", row)
	gsub(/&#[0-9]+;|&[a-z]+;/, " ", row)
	gsub(/[ \t\n\r]+/, " ", row)
	# Assigned Numbers has many tables whose first column is a hex value.
	# Only Section 2.3 "Common Data Types" is wanted, so the scan is armed
	# by that table's header row and disarmed by the first row that is not
	# one of its data rows.
	if (row ~ /Common Data Type .*Name .*Reference/) {
		in_cdt = 1
		next
	}
	if (!in_cdt)
		next
	if (row !~ /^ *0x[0-9A-Fa-f][0-9A-Fa-f] /) {
		in_cdt = 0
		next
	}
	if (match(row, /0x[0-9A-Fa-f][0-9A-Fa-f]/) == 0)
		next
	val = toupper(substr(row, RSTART, RLENGTH))
	sub(/^0X/, "0x", val)
	if (!(val in want))
		next
	seen[val] = 1
	if (match(row, /Core Specification Supplement, Part A, Section [0-9]+(\.[0-9]+)*/)) {
		s = substr(row, RSTART, RLENGTH)
		sub(/.*Section /, "", s)
		if (!(s in sec)) {
			sec[s] = 1
			nsec++
		}
		printf "spec_conf_css_adscope: %s -> Part A %s\n", val, s > \
		    "/dev/stderr"
	} else {
		printf "spec_conf_css_adscope: %s specified outside CSS\n", \
		    val > "/dev/stderr"
	}
}

END {
	for (v in want)
		if (!(v in seen))
			printf "spec_conf_css_adscope: %s not in Assigned Numbers Common Data Types\n", v > "/dev/stderr"
	if (nsec == 0) {
		print "spec_conf_css_adscope: no CSS sections derived" > \
		    "/dev/stderr"
		exit 1
	}
	n = 0
	for (s in sec)
		list[++n] = s
	# Deterministic numeric-dotted ordering.
	for (i = 1; i <= n; i++)
		for (j = i + 1; j <= n; j++) {
			split(list[i], a, ".")
			split(list[j], b, ".")
			if (a[1] * 1000 + a[2] > b[1] * 1000 + b[2]) {
				t = list[i]; list[i] = list[j]; list[j] = t
			}
		}
	out = ""
	for (i = 1; i <= n; i++)
		out = out (out == "" ? "" : ",") list[i]
	print out
	printf "spec_conf_css_adscope: %d AD types -> %d CSS Part A sections\n", \
	    nwant, nsec > "/dev/stderr"
}
