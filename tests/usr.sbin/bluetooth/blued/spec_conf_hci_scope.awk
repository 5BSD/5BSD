# Derive the in-scope Vol 4 Part E section list from the HCI opcodes blued
# actually issues.
#
# Input 1 (OPCODES=file): one NG_HCI_OCF_* symbol per line, as grepped out of
#                         usr.sbin/bluetooth/blued.
# Input 2 (argv):         Core_Specification_6_3.txt
#
# Output: a comma-separated section-prefix list on stdout, and a diagnostic
# report of unmatched opcodes on stderr.  The mapping is by expanded word-token
# containment: every token of the opcode name (after abbreviation expansion)
# must appear in the specification heading.  This keeps the scope derived from
# the code rather than hand-curated.

function expand(name,   i, n, w, out, t) {
	sub(/^NG_HCI_OCF_/, "", name)
	n = split(tolower(name), w, "_")
	out = ""
	for (i = 1; i <= n; i++) {
		t = w[i]
		if (t in alias)
			t = alias[t]
		if (t == "")
			continue
		out = out " " t
	}
	gsub(/  +/, " ", out)
	sub(/^ /, "", out)
	sub(/ $/, "", out)
	return out
}

function heading_tokens(line,   s) {
	s = tolower(line)
	gsub(/[^a-z0-9]+/, " ", s)
	gsub(/  +/, " ", s)
	return " " s " "
}

BEGIN {
	alias["adv"] = "advertising"
	alias["advertise"] = "advertising"
	alias["params"] = "parameters"
	alias["param"] = "parameter"
	alias["dev"] = "device"
	alias["enh"] = "enhanced"
	alias["ext"] = "extended"
	alias["connless"] = "connectionless"
	alias["conn"] = "connection"
	alias["rcv"] = "receive"
	alias["req"] = "request"
	alias["rsp"] = "response"
	alias["ltk"] = "long term key"
	alias["sca"] = "sca"
	alias["tx"] = "transmit"
	alias["rx"] = "receive"
	alias["max"] = "maximum"
	alias["min"] = "min"
	alias["auth"] = "authenticated"
	alias["enc"] = "encryption"
	alias["rpa"] = "resolvable private address"
	alias["bdaddr"] = "bd addr"
	alias["past"] = "periodic advertising sync transfer"
	alias["discon"] = "disconnect"
	alias["addr"] = "address"
	alias["num"] = "number of"
	alias["white"] = "filter"
	alias["list"] = "list"
	alias["iq"] = "iq"
	alias["cte"] = "cte"
	alias["big"] = "big"
	alias["cig"] = "cig"
	alias["cis"] = "cis"
	alias["phy"] = "phy"
	alias["iso"] = "iso"
	# NG_HCI names say WHITE_LIST where Core 6.3 says Filter Accept List.
	alias["accept"] = "accept"

	if (OPCODES == "") {
		print "spec_conf_hci_scope: OPCODES not set" > "/dev/stderr"
		exit 1
	}
	# Opcodes whose FreeBSD ng_hci symbol cannot be reduced to the Core 6.3
	# heading by abbreviation expansion alone.  Each entry is justified by
	# the heading it names.
	override["NG_HCI_OCF_LE_START_ENCRYPTION"] = "7.8.24"
	    # "LE Enable Encryption command"
	override["NG_HCI_OCF_LE_READ_BUFFER_SIZE_V2"] = "7.8.2"
	    # "LE Read Buffer Size command" (the [v2] form shares the section)
	override["NG_HCI_OCF_WRITE_LE_HOST_SUPPORTED"] = "7.3.79"
	    # "Write LE Host Support command"
	override["NG_HCI_OCF_LE_ADD_DEV_PERIODIC_ADV_LIST"] = "7.8.70"
	override["NG_HCI_OCF_LE_REMOVE_DEV_PERIODIC_ADV_LIST"] = "7.8.71"
	override["NG_HCI_OCF_LE_CLEAR_PERIODIC_ADV_LIST"] = "7.8.72"
	override["NG_HCI_OCF_LE_READ_PERIODIC_ADV_LIST_SIZE"] = "7.8.73"
	    # Core 6.3 says "Periodic Advertiser List", ng_hci says ADV_LIST.
	override["NG_HCI_OCF_LE_READ_ISO_TX_SYNC"] = "7.8.96"
	    # "LE Read ISO TX Sync command" keeps the literal "TX".

	nop = 0
	while ((getline line < OPCODES) > 0) {
		if (line == "")
			continue
		nop++
		ocf[nop] = line
		if (line in override) {
			matched[nop] = override[line]
			sections[override[line]] = 1
			want[nop] = ""
			continue
		}
		want[nop] = expand(line)
		# "white list" in the NG_HCI vocabulary is Core's
		# "filter accept list".
		gsub(/filter list/, "filter accept list", want[nop])
	}
	close(OPCODES)
	vp = ""
}

/BLUETOOTH CORE SPECIFICATION Version/ {
	if (match($0, /Vol [0-9]+, Part [A-Z]+/))
		vp = substr($0, RSTART, RLENGTH)
	next
}

vp != "Vol 4, Part E" { next }
/\.\.\.\./ { next }

/^\f?7\.[0-9]+(\.[0-9]+)*[ \t]+[A-Za-z]/ {
	head = $0
	sub(/^\f/, "", head)
	if (!match(head, /^7\.[0-9]+(\.[0-9]+)*/))
		next
	sec = substr(head, RSTART, RLENGTH)
	title = substr(head, RSTART + RLENGTH)
	if (title !~ /command|event/)
		next
	toks = heading_tokens(title)
	for (i = 1; i <= nop; i++) {
		if (matched[i] != "")
			continue
		nw = split(want[i], w, " ")
		ok = 1
		for (j = 1; j <= nw; j++)
			if (index(toks, " " w[j] " ") == 0) {
				ok = 0
				break
			}
		if (ok) {
			matched[i] = sec
			sections[sec] = 1
		}
	}
	next
}

END {
	unmatched = 0
	for (i = 1; i <= nop; i++)
		if (matched[i] == "") {
			print "spec_conf_hci_scope: unmatched opcode " ocf[i] > \
			    "/dev/stderr"
			unmatched++
		}
	# The LE Meta event chapter is always in scope: blued parses these.
	sections["7.7.65"] = 1
	# Core events blued consumes regardless of the commands it issues.
	sections["7.7.3"] = 1	# Connection Complete
	sections["7.7.5"] = 1	# Disconnection Complete
	sections["7.7.8"] = 1	# Encryption Change
	sections["7.7.14"] = 1	# Command Complete
	sections["7.7.15"] = 1	# Command Status
	sections["7.7.19"] = 1	# Number Of Completed Packets
	n = 0
	for (s in sections)
		list[++n] = s
	# Deterministic order: sort numerically by dotted components.
	for (a = 1; a <= n; a++)
		for (b = a + 1; b <= n; b++)
			if (seccmp(list[a], list[b]) > 0) {
				t = list[a]; list[a] = list[b]; list[b] = t
			}
	out = ""
	for (a = 1; a <= n; a++)
		out = out (out == "" ? "" : ",") list[a]
	print out
	printf "spec_conf_hci_scope: %d/%d opcodes mapped to %d sections\n", \
	    nop - unmatched, nop, n > "/dev/stderr"
}

function seccmp(x, y,   xa, ya, nx, ny, i) {
	nx = split(x, xa, ".")
	ny = split(y, ya, ".")
	for (i = 1; i <= (nx < ny ? nx : ny); i++) {
		if (xa[i] + 0 != ya[i] + 0)
			return (xa[i] + 0) - (ya[i] + 0)
	}
	return nx - ny
}
