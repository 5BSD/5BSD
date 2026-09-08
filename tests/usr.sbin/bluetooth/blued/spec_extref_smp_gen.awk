# Generate the EXTERNAL reference SMP vector header from two external sources:
#
#   1. Bluetooth Core Specification 6.3 plain text
#      (Vol 3, Part H, Sections 2.2.2/2.2.3/2.2.4 prose and Appendix D).
#   2. The BlueZ source snapshot's unit/test-crypto.c.
#
# Nothing here reads, derives from, or depends on the 5BSD blued sources.
# Every emitted value is parsed out of one of the two input files; the only
# computed value is a pure byte reordering of an already-parsed constant and
# is labelled as such in the generated output.
#
# Usage:
#   awk -f spec_extref_smp_gen.awk \
#       Core_Specification_6_3.txt \
#       <bluez>/unit/test-crypto.c > spec_extref_smp_vectors.h
#
# The spec text MUST be the first argument and test-crypto.c the second.

function fail(msg) {
	printf("spec_extref_smp_gen: %s\n", msg) > "/dev/stderr"
	exit 1
}

function ishexgrp(t) {
	return (t ~ /^[0-9a-fA-F]+$/) && (length(t) % 2 == 0)
}

function allhex(   i) {
	if (NF < 1)
		return 0
	for (i = 1; i <= NF; i++)
		if (!ishexgrp($i))
			return 0
	return 1
}

function nth_hex(line, wanted,   rest, found, value) {
	rest = line
	found = 0
	while (match(rest, /0[xX][0-9a-fA-F]+/)) {
		found++
		value = substr(rest, RSTART + 2, RLENGTH - 2)
		if (found == wanted)
			return tolower(value)
		rest = substr(rest, RSTART + RLENGTH)
	}
	return ""
}

# Register a C symbol: which section/label feeds it, its expected octet
# length, and the descriptive comment emitted above it.
function reg(mapkey, cname, octets, text) {
	if (mapkey != "")
		cmap[mapkey] = cname
	if (!(cname in clen)) {
		clen[cname] = octets * 2
		desc[cname] = text
		order[++nord] = cname
	}
}

function setval(cname, hex, line) {
	if (cname in val)
		fail(cname " assigned twice (line " line ")")
	val[cname] = tolower(hex)
	srcline[cname] = line
}

function expect(cname, hex, line) {
	if (!(cname in val))
		fail(cname " cross-check before assignment (line " line ")")
	if (val[cname] != tolower(hex))
		fail(cname " cross-check mismatch at line " line ": " \
		    val[cname] " vs " tolower(hex))
}

function byte(hex, i) {
	return substr(hex, 2 * i + 1, 2)
}

BEGIN {
	# ---- Vol 3, Part H, Appendix D.1: AES-CMAC RFC 4493 test vectors ----
	reg("D.1:K", "rfc4493_k", 16, "RFC 4493 Section 4 key K")
	reg("D.1:AES_128(key,0)", "rfc4493_subkey_l", 16, \
	    "RFC 4493 subkey generation: AES-128(K, 0^128)")
	reg("D.1:K1", "rfc4493_k1", 16, "RFC 4493 subkey K1")
	reg("D.1:K2", "rfc4493_k2", 16, "RFC 4493 subkey K2")
	reg("D.1.1:AES_CMAC", "rfc4493_ex1_cmac", 16, \
	    "RFC 4493 Example 1 (Len = 0) AES-CMAC; message is the empty string")
	reg("D.1.2:M", "rfc4493_ex2_msg", 16, "RFC 4493 Example 2 (Len = 16) M")
	reg("D.1.2:AES_CMAC", "rfc4493_ex2_cmac", 16, \
	    "RFC 4493 Example 2 (Len = 16) AES-CMAC")
	reg("D.1.3:M0", "rfc4493_ex3_msg", 40, "RFC 4493 Example 3 (Len = 40) M")
	reg("D.1.3:M1", "rfc4493_ex3_msg")
	reg("D.1.3:M2", "rfc4493_ex3_msg")
	reg("D.1.3:AES_CMAC", "rfc4493_ex3_cmac", 16, \
	    "RFC 4493 Example 3 (Len = 40) AES-CMAC")
	reg("D.1.4:M0", "rfc4493_ex4_msg", 64, "RFC 4493 Example 4 (Len = 64) M")
	reg("D.1.4:M1", "rfc4493_ex4_msg")
	reg("D.1.4:M2", "rfc4493_ex4_msg")
	reg("D.1.4:M3", "rfc4493_ex4_msg")
	reg("D.1.4:AES_CMAC", "rfc4493_ex4_cmac", 16, \
	    "RFC 4493 Example 4 (Len = 64) AES-CMAC")

	# ---- Appendix D.2: f4 ----
	reg("D.2:U", "f4_u", 32, "f4 input U (public key X coordinate)")
	reg("D.2:V", "f4_v", 32, "f4 input V (public key X coordinate)")
	reg("D.2:X", "f4_x", 16, "f4 input X (AES-CMAC key)")
	reg("D.2:Z", "f4_z", 1, "f4 input Z")
	reg("D.2:M0", "f4_msg", 65, "f4 AES-CMAC message M = U || V || Z")
	reg("D.2:M1", "f4_msg")
	reg("D.2:M2", "f4_msg")
	reg("D.2:M3", "f4_msg")
	reg("D.2:AES_CMAC", "f4_out", 16, "f4 output (AES-CMAC value)")

	# ---- Appendix D.3: f5 ----
	reg("D.3:DHKey(W)", "f5_w", 32, "f5 input W (DHKey)")
	reg("", "f5_salt", 16, \
	    "f5 SALT, the AES-CMAC key used to derive T; normative constant from" \
	    " Vol 3, Part H, Section 2.2.7, not from Appendix D.  Corroborated by" \
	    " BlueZ src/shared/crypto.c bt_crypto_f5() lines 658-659, which holds" \
	    " the same 16 octets in reverse (little-endian) order")
	reg("D.3:T", "f5_t", 16, "f5 intermediate T = AES-CMAC_SALT(W)")
	reg("D.3:keyID", "f5_keyid", 4, "f5 keyID (\"btle\")")
	reg("D.3:N1", "f5_n1", 16, "f5 input N1")
	reg("D.3:N2", "f5_n2", 16, "f5 input N2")
	reg("D.3:A1", "f5_a1", 7, "f5 input A1 (addr type || address)")
	reg("D.3:A2", "f5_a2", 7, "f5 input A2 (addr type || address)")
	reg("D.3:Length", "f5_length", 2, "f5 Length field")
	reg("D.3:LTK:M0", "f5_ltk_msg", 53, \
	    "f5 LTK AES-CMAC message (Counter=1 || keyID || N1 || N2 || A1 || A2 || Length)")
	reg("D.3:LTK:M1", "f5_ltk_msg")
	reg("D.3:LTK:M2", "f5_ltk_msg")
	reg("D.3:LTK:M3", "f5_ltk_msg")
	reg("D.3:LTK:AES_CMAC", "f5_ltk", 16, "f5 output LTK")
	reg("D.3:MACKEY:M0", "f5_mackey_msg", 53, \
	    "f5 MacKey AES-CMAC message (Counter=0 || keyID || N1 || N2 || A1 || A2 || Length)")
	reg("D.3:MACKEY:M1", "f5_mackey_msg")
	reg("D.3:MACKEY:M2", "f5_mackey_msg")
	reg("D.3:MACKEY:M3", "f5_mackey_msg")
	reg("D.3:MACKEY:AES_CMAC", "f5_mackey", 16, "f5 output MacKey")

	# ---- Appendix D.4: f6 ----
	reg("D.4:N1", "f6_n1", 16, "f6 input N1")
	reg("D.4:N2", "f6_n2", 16, "f6 input N2")
	reg("D.4:MacKey", "f6_mackey", 16, "f6 input MacKey (AES-CMAC key)")
	reg("D.4:R", "f6_r", 16, "f6 input R")
	reg("D.4:IOcap", "f6_iocap", 3, "f6 input IOcap")
	reg("D.4:A1", "f6_a1", 7, "f6 input A1")
	reg("D.4:A2", "f6_a2", 7, "f6 input A2")
	reg("D.4:M0", "f6_msg", 65, \
	    "f6 AES-CMAC message M = N1 || N2 || R || IOcap || A1 || A2")
	reg("D.4:M1", "f6_msg")
	reg("D.4:M2", "f6_msg")
	reg("D.4:M3", "f6_msg")
	reg("D.4:M4", "f6_msg")
	reg("D.4:AES_CMAC", "f6_out", 16, "f6 output (check value)")

	# ---- Appendix D.5: g2 ----
	reg("D.5:U", "g2_u", 32, "g2 input U")
	reg("D.5:V", "g2_v", 32, "g2 input V")
	reg("D.5:X", "g2_x", 16, "g2 input X (AES-CMAC key)")
	reg("D.5:Y", "g2_y", 16, "g2 input Y")
	reg("D.5:M0", "g2_msg", 80, "g2 AES-CMAC message M = U || V || Y")
	reg("D.5:M1", "g2_msg")
	reg("D.5:M2", "g2_msg")
	reg("D.5:M3", "g2_msg")
	reg("D.5:M4", "g2_msg")
	reg("D.5:AES_CMAC", "g2_cmac", 16, "g2 full AES-CMAC output")
	reg("D.5:g2", "g2_out", 4, \
	    "g2 result: the least significant 32 bits of the AES-CMAC output")

	# ---- Appendix D.6: h6 ----
	reg("D.6:Key", "h6_key", 16, "h6 input Key W")
	reg("D.6:keyID", "h6_keyid", 4, "h6 keyID (\"lebr\")")
	reg("D.6:M", "h6_msg", 4, "h6 AES-CMAC message M = keyID")
	reg("D.6:AES_CMAC", "h6_out", 16, "h6 output")

	# ---- Appendix D.7: ah ----
	reg("D.7:IRK", "ah_irk", 16, "ah input k (IRK)")
	reg("D.7:prand", "ah_prand", 16, "ah prand, already padded to 128 bits")
	reg("D.7:M", "ah_msg", 16, "ah security-function-e plaintext r' = padding || r")
	reg("D.7:AES_128", "ah_e_out", 16, "ah intermediate e(k, r') full 128-bit output")
	reg("D.7:ah", "ah_out", 3, \
	    "ah result: the least significant 24 bits of e(k, r')")

	# ---- Appendix D.8: h7 ----
	reg("D.8:Key", "h7_key", 16, "h7 input Key W")
	reg("D.8:SALT", "h7_salt", 16, "h7 SALT (AES-CMAC key), \"tmp1\" in the low 4 octets")
	reg("D.8:AES_CMAC", "h7_out", 16, "h7 output")

	# ---- Vol 3, Part H, Section 2.2.3 prose: c1 ----
	reg("", "c1_k", 16, "c1 input k")
	reg("", "c1_r", 16, "c1 input r")
	reg("", "c1_preq", 7, "c1 input preq (56 bits)")
	reg("", "c1_pres", 7, "c1 input pres (56 bits)")
	reg("", "c1_iat", 1, "c1 input iat' (iat concatenated with 7 zero bits)")
	reg("", "c1_rat", 1, "c1 input rat' (rat concatenated with 7 zero bits)")
	reg("", "c1_ia", 6, "c1 input ia")
	reg("", "c1_ra", 6, "c1 input ra")
	reg("", "c1_p1", 16, "c1 intermediate p1 = pres || preq || rat' || iat'")
	reg("", "c1_p2", 16, "c1 intermediate p2 = padding || ia || ra")
	reg("", "c1_out", 16, "c1 output = e(k, e(k, r XOR p1) XOR p2)")

	# ---- Vol 3, Part H, Section 2.2.4 prose: s1 ----
	reg("", "s1_k", 16, "s1 input k")
	reg("", "s1_r1", 16, "s1 input r1")
	reg("", "s1_r2", 16, "s1 input r2")
	reg("", "s1_r1p", 8, "s1 intermediate r1' (r1 with its most significant 64 bits discarded)")
	reg("", "s1_r2p", 8, "s1 intermediate r2' (r2 with its most significant 64 bits discarded)")
	reg("", "s1_rp", 16, "s1 intermediate r' = r1' || r2'")
	reg("", "s1_out", 16, "s1 output = e(k, r')")

	# ---- Vol 3, Part H, Section 2.2.2 prose: ah padding example ----
	reg("", "ah_prose_r", 3, "ah prose example: 24-bit r")
	reg("", "ah_prose_rp", 16, "ah prose example: r' = padding || r")

	# ---- BlueZ unit/test-crypto.c signed-write vectors ----
	bzreg("key", "bluez_sign_key", "signed-write key (BlueZ little-endian in-memory order)")
	bzreg("msg_1", "bluez_sign1_msg", "sign_att_1 message buffer (test uses msg_len 0)")
	bzreg("t_msg_1", "bluez_sign1_sig", "sign_att_1 expected 12-octet signature")
	bzreg("msg_2", "bluez_sign2_msg", "sign_att_2 message (16 octets)")
	bzreg("t_msg_2", "bluez_sign2_sig", "sign_att_2 expected 12-octet signature")
	bzreg("msg_3", "bluez_sign3_msg", "sign_att_3 message (40 octets)")
	bzreg("t_msg_3", "bluez_sign3_sig", "sign_att_3 expected 12-octet signature")
	bzreg("msg_4", "bluez_sign4_msg", "sign_att_4 message (64 octets)")
	bzreg("t_msg_4", "bluez_sign4_sig", "sign_att_4 expected 12-octet signature")
	bzreg("key_5", "bluez_sign5_key", "sign_att_5 key (BlueZ little-endian in-memory order)")
	bzreg("msg_5", "bluez_sign5_msg", "sign_att_5 message (5 octets), sign counter 1")
	bzreg("t_msg_5", "bluez_sign5_sig", "sign_att_5 expected 12-octet signature")
	bzreg("msg_to_verify_pass", "bluez_verify_pass_pdu", \
	    "verify_sign_pass PDU (message || 12-octet signature)")
	bzreg("msg_to_verify_bad_sign", "bluez_verify_bad_pdu", \
	    "verify_sign_bad_sign PDU (last octet corrupted)")
	bzreg("msg_to_verify_too_short", "bluez_verify_short_pdu", \
	    "verify_sign_too_short PDU (shorter than 12 octets)")
	bzreg("w", "bluez_h6_w", "/crypto/h6 input W (little-endian; reverse of Appendix D.6 Key)")
	bzreg("m", "bluez_h6_m", "/crypto/h6 keyID (little-endian; reverse of Appendix D.6 keyID)")
	bzreg("exp", "bluez_h6_exp", "/crypto/h6 expected output (little-endian; reverse of Appendix D.6 AES_CMAC)")
}

function bzreg(arrname, cname, text) {
	bzmap[arrname] = cname
	bzdesc[cname] = text
	bzorder[++nbz] = cname
}

# pdftotext emits a form feed at the head of every page-break line; strip it
# (and any stray carriage return) so that the anchors below stay simple.
{ gsub(/[\f\r]/, "") }

# ---------------------------------------------------------------------------
# Pass over the BlueZ unit test.
# ---------------------------------------------------------------------------
FILENAME ~ /test-crypto\.c$/ {
	if (!bz_in) {
		if (!match($0, /uint8_t[[:space:]]+[A-Za-z0-9_]+\[[0-9]*\][[:space:]]*=[[:space:]]*\{/))
			next
		hdr = substr($0, RSTART, RLENGTH)
		sub(/^uint8_t[[:space:]]+/, "", hdr)
		sub(/\[.*$/, "", hdr)
		bz_name = hdr
		bz_line = FNR
		bz_acc = ""
		bz_in = 1
		bz_rest = substr($0, RSTART + RLENGTH)
	} else
		bz_rest = $0

	n = split(bz_rest, tk, /[^0-9a-fA-FxX]+/)
	for (i = 1; i <= n; i++)
		if (tk[i] ~ /^0[xX][0-9a-fA-F][0-9a-fA-F]$/)
			bz_acc = bz_acc tolower(substr(tk[i], 3))
	if (bz_rest ~ /\}/) {
		if (bz_name in bzmap && !(bzmap[bz_name] in bzval)) {
			bzval[bzmap[bz_name]] = bz_acc
			bzline[bzmap[bz_name]] = bz_line
		}
		bz_in = 0
	}
	next
}

# ---------------------------------------------------------------------------
# Vol 3, Part H, Section 2.2.2 prose: ah padding example.
# ---------------------------------------------------------------------------
!("ah_prose_r" in val) && /24-bit value r is 0x/ && /then r/ {
	setval("ah_prose_r", nth_hex($0, 1), FNR)
	want_ah_rp = 1
	next
}
want_ah_rp && /^0[xX][0-9a-fA-F]+\.?[[:space:]]*$/ {
	setval("ah_prose_rp", nth_hex($0, 1), FNR)
	want_ah_rp = 0
	next
}

# ---------------------------------------------------------------------------
# Vol 3, Part H, Section 2.2.7: the normative f5 SALT constant.
# ---------------------------------------------------------------------------
/^SALT is the 128-bit value:[[:space:]]*$/ { want_f5_salt = 1; next }
want_f5_salt && /0[xX][0-9a-fA-F_]+/ {
	line = $0
	gsub(/_/, "", line)
	setval("f5_salt", nth_hex(line, 1), FNR)
	want_f5_salt = 0
	next
}

# ---------------------------------------------------------------------------
# Vol 3, Part H, Section 2.2.3 prose: c1.
# ---------------------------------------------------------------------------
!("c1_iat" in val) && /8-bit iat/ && /8-bit rat/ && /56-bit preq/ {
	setval("c1_iat", nth_hex($0, 1), FNR)
	setval("c1_rat", nth_hex($0, 2), FNR)
	next
}
!("c1_preq" in val) && /^is 0[xX]/ && /56 bit pres is 0[xX]/ {
	setval("c1_preq", nth_hex($0, 1), FNR)
	setval("c1_pres", nth_hex($0, 2), FNR)
	want_c1_p1 = 1
	next
}
want_c1_p1 && /^0[xX][0-9a-fA-F]+\.?[[:space:]]*$/ {
	setval("c1_p1", nth_hex($0, 1), FNR)
	want_c1_p1 = 0
	next
}
!("c1_ia" in val) && /48-bit ia is 0[xX]/ && /48-bit ra is 0[xX]/ {
	setval("c1_ia", nth_hex($0, 1), FNR)
	setval("c1_ra", nth_hex($0, 2), FNR)
	next
}
!("c1_p2" in val) && /^then p2 is 0[xX]/ {
	setval("c1_p2", nth_hex($0, 1), FNR)
	next
}
!("c1_k" in val) && /if the 128-bit k is 0[xX]/ {
	setval("c1_k", nth_hex($0, 1), FNR)
	next
}
!("c1_r" in val) && /^128-bit value r is 0[xX]/ {
	setval("c1_r", nth_hex($0, 1), FNR)
	next
}
("c1_r" in val) && !("c1_out" in val) && /^p1 is 0[xX]/ && /128-bit value p2 is/ {
	expect("c1_p1", nth_hex($0, 1), FNR)
	next
}
("c1_r" in val) && !("c1_out" in val) && /^0[xX]/ && /output from the c1/ {
	expect("c1_p2", nth_hex($0, 1), FNR)
	next
}
!("c1_out" in val) && /^function is 0[xX]/ {
	setval("c1_out", nth_hex($0, 1), FNR)
	next
}

# ---------------------------------------------------------------------------
# Vol 3, Part H, Section 2.2.4 prose: s1.
# ---------------------------------------------------------------------------
!("s1_r1" in val) && /^For example if the 128-bit value r1 is 0[xX]/ {
	setval("s1_r1", nth_hex($0, 1), FNR)
	next
}
!("s1_r1p" in val) && /^then r1/ && /128-bit value r2 is$/ {
	setval("s1_r1p", nth_hex($0, 1), FNR)
	next
}
!("s1_r2" in val) && /^0[xX]/ && /then r2/ {
	setval("s1_r2", nth_hex($0, 1), FNR)
	setval("s1_r2p", nth_hex($0, 2), FNR)
	next
}
("s1_r2p" in val) && !("s1_rp" in val) && /64-bit value r1/ && /and r2/ {
	expect("s1_r1p", nth_hex($0, 1), FNR)
	next
}
("s1_r2p" in val) && !("s1_rp" in val) && /^0[xX]/ && /then r/ {
	expect("s1_r2p", nth_hex($0, 1), FNR)
	setval("s1_rp", nth_hex($0, 2), FNR)
	next
}
/^For example if the 128-bit value k is$/ { want_s1 = "s1_k"; next }
/^and the 128-bit value r. is$/ { want_s1 = "check_rp"; next }
/^then the output from the key generation function s1 is$/ {
	want_s1 = "s1_out"
	next
}
want_s1 != "" && /^[[:space:]]*0[xX][0-9a-fA-F]+\.?[[:space:]]*$/ {
	if (want_s1 == "check_rp")
		expect("s1_rp", nth_hex($0, 1), FNR)
	else
		setval(want_s1, nth_hex($0, 1), FNR)
	want_s1 = ""
	next
}

# ---------------------------------------------------------------------------
# Vol 3, Part H, Appendix D tables.
# ---------------------------------------------------------------------------
/^D\.1[[:space:]]+AES-CMAC RFC4493 test vectors[[:space:]]*$/ { in_appd = 1 }
in_appd && /^BLUETOOTH CORE SPECIFICATION Version 6\.3 \| Vol 4/ { in_appd = 0 }

in_appd && /^[[:space:]]*$/ { next }
in_appd && /^[[:space:]]*Bluetooth SIG Proprietary/ { next }
in_appd && /^BLUETOOTH CORE SPECIFICATION/ { next }
in_appd && /^Security Manager Specification[[:space:]]*$/ { next }

in_appd && $1 ~ /^D\.[0-9]+(\.[0-9]+)?$/ {
	sec = $1
	cur = ""
	f5sub = ""
	next
}
in_appd && $1 == "(LTK)" { f5sub = "LTK"; cur = ""; next }
in_appd && $1 == "(MacKey)" { f5sub = "MACKEY"; cur = ""; next }

in_appd && sec != "" {
	label = $1
	mk = sec ":" label
	if (sec == "D.3" && f5sub != "" && label ~ /^(M[0-9]|AES_CMAC)$/)
		mk = sec ":" f5sub ":" label
	# Note: labels such as "A1" are themselves valid hex groups, so the
	# label table has to be consulted before the continuation test.
	if (!(mk in cmap)) {
		if (allhex()) {
			# Continuation of the value started on an earlier line.
			if (cur != "")
				for (i = 1; i <= NF; i++)
					val[cur] = val[cur] tolower($i)
		} else
			cur = ""
		next
	}
	cur = cmap[mk]
	if (!(cur in srcline))
		srcline[cur] = FNR
	for (i = 2; i <= NF; i++) {
		tok = $i
		sub(/^0[xX]/, "", tok)
		if (!ishexgrp(tok))
			fail("non-hex token \"" $i "\" for " mk " at line " FNR)
		val[cur] = val[cur] tolower(tok)
	}
	next
}

END {
	# ---- completeness and length validation --------------------------
	for (i = 1; i <= nord; i++) {
		c = order[i]
		if (!(c in val))
			fail("no value parsed for " c)
		if (length(val[c]) != clen[c])
			fail(c " is " (length(val[c]) / 2) " octets, expected " \
			    (clen[c] / 2))
	}
	for (i = 1; i <= nbz; i++) {
		c = bzorder[i]
		if (!(c in bzval))
			fail("no BlueZ value parsed for " c)
	}

	# ---- structural cross-checks internal to the spec ----------------
	if (val["f4_msg"] != val["f4_u"] val["f4_v"] val["f4_z"])
		fail("Appendix D.2: M != U || V || Z")
	if (val["g2_msg"] != val["g2_u"] val["g2_v"] val["g2_y"])
		fail("Appendix D.5: M != U || V || Y")
	if (val["g2_out"] != substr(val["g2_cmac"], 25))
		fail("Appendix D.5: g2 != low 32 bits of AES_CMAC")
	if (val["f6_msg"] != val["f6_n1"] val["f6_n2"] val["f6_r"] \
	    val["f6_iocap"] val["f6_a1"] val["f6_a2"])
		fail("Appendix D.4: M != N1 || N2 || R || IOcap || A1 || A2")
	if (val["f5_ltk_msg"] != "01" val["f5_keyid"] val["f5_n1"] val["f5_n2"] \
	    val["f5_a1"] val["f5_a2"] val["f5_length"])
		fail("Appendix D.3: LTK M != 01 || keyID || N1 || N2 || A1 || A2 || Length")
	if (val["f5_mackey_msg"] != "00" val["f5_keyid"] val["f5_n1"] val["f5_n2"] \
	    val["f5_a1"] val["f5_a2"] val["f5_length"])
		fail("Appendix D.3: MacKey M != 00 || keyID || N1 || N2 || A1 || A2 || Length")
	if (val["h6_msg"] != val["h6_keyid"])
		fail("Appendix D.6: M != keyID")
	if (val["ah_msg"] != val["ah_prand"])
		fail("Appendix D.7: M != prand")
	if (val["ah_out"] != substr(val["ah_e_out"], 27))
		fail("Appendix D.7: ah != low 24 bits of AES_128")
	if (val["s1_rp"] != val["s1_r1p"] val["s1_r2p"])
		fail("Section 2.2.4: r' != r1' || r2'")
	if (val["s1_r1p"] != substr(val["s1_r1"], 17))
		fail("Section 2.2.4: r1' != low 64 bits of r1")
	if (val["s1_r2p"] != substr(val["s1_r2"], 17))
		fail("Section 2.2.4: r2' != low 64 bits of r2")
	if (val["c1_p1"] != val["c1_pres"] val["c1_preq"] val["c1_rat"] val["c1_iat"])
		fail("Section 2.2.3: p1 != pres || preq || rat' || iat'")
	if (val["c1_p2"] != "00000000" val["c1_ia"] val["c1_ra"])
		fail("Section 2.2.3: p2 != padding || ia || ra")
	if (val["ah_prose_rp"] != "00000000000000000000000000" val["ah_prose_r"])
		fail("Section 2.2.2: r' != padding || r")

	# ---- BlueZ / spec agreement --------------------------------------
	# BlueZ stores SMP values least-significant-octet-first, so its arrays
	# are the spec's printed hex reversed.  Reverse them back and compare.
	if (revhex(bzval["bluez_h6_w"]) != val["h6_key"])
		fail("BlueZ /crypto/h6 W disagrees with Appendix D.6 Key")
	if (revhex(bzval["bluez_h6_m"]) != val["h6_keyid"])
		fail("BlueZ /crypto/h6 M disagrees with Appendix D.6 keyID")
	if (revhex(bzval["bluez_h6_exp"]) != val["h6_out"])
		fail("BlueZ /crypto/h6 expected disagrees with Appendix D.6 AES_CMAC")
	if (revhex(bzval["bluez_sign_key"]) != val["rfc4493_k"])
		fail("BlueZ signed-write key disagrees with Appendix D.1 K")
	if (bzval["bluez_sign2_msg"] != val["rfc4493_ex2_msg"])
		fail("BlueZ msg_2 disagrees with Appendix D.1.2 M")
	if (bzval["bluez_sign3_msg"] != val["rfc4493_ex3_msg"])
		fail("BlueZ msg_3 disagrees with Appendix D.1.3 M")
	if (bzval["bluez_sign4_msg"] != val["rfc4493_ex4_msg"])
		fail("BlueZ msg_4 disagrees with Appendix D.1.4 M")

	# ---- derived signature truncation demonstration ------------------
	# Pure byte reordering of Appendix D.1.2's published AES_CMAC; see the
	# comment emitted with the array below.
	sig_cnt = 1
	out = val["rfc4493_ex2_cmac"]
	demo = substr(out, 1, 16) "00000001" substr(out, 25, 8)
	demo_sig = ""
	for (i = 11; i >= 0; i--)
		demo_sig = demo_sig byte(demo, i)

	# ---- emit ---------------------------------------------------------
	print "/*"
	print " * Generated by spec_extref_smp_gen.awk; do not edit."
	print " *"
	print " * EXTERNAL reference vectors for the Security Manager cryptographic"
	print " * toolbox.  Every value in this file is transcribed mechanically from"
	print " * one of two external sources and from nothing else:"
	print " *"
	print " *   [SPEC]  Bluetooth Core Specification 6.3, Vol 3, Part H"
	print " *           (Sections 2.2.2, 2.2.3 and 2.2.4 prose, and Appendix D)."
	print " *           Cited line numbers are 1-based lines of the plain-text"
	print " *           rendering Core_Specification_6_3.txt."
	print " *"
	print " *   [BLUEZ] BlueZ unit/test-crypto.c.  Cited line numbers are lines"
	print " *           of that file in the reviewed snapshot."
	print " *"
	print " * No value here was obtained by reading or running the blued sources."
	print " *"
	print " * BYTE ORDER"
	print " * =========="
	print " * Unless a symbol name contains \"bluez\", every array below is in"
	print " * SPEC DISPLAY ORDER: most significant octet first, i.e. exactly the"
	print " * left-to-right order in which the specification prints the hex."
	print " * Array index 0 therefore holds the most significant octet, matching"
	print " * the spec's own convention that \"the most significant octet of key"
	print " * corresponds to key[0]\" ([SPEC] Vol 3, Part H, Section 2.2.1)."
	print " *"
	print " * BlueZ holds the same SMP values in memory least-significant-octet"
	print " * first.  Its aes_cmac() (src/shared/crypto.c) calls swap_buf() on the"
	print " * key, on the message and on the result for exactly that reason, and"
	print " * so the arrays in unit/test-crypto.c are generally the reverse of the"
	print " * spec's printed hex.  The bt_extref_bluez_* arrays below preserve"
	print " * BlueZ's little-endian order verbatim; nothing has been silently"
	print " * reversed anywhere in this file."
	print " */"
	print ""
	print "#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_SMP_VECTORS_H"
	print "#define TESTS_BLUETOOTH_SPEC_EXTREF_SMP_VECTORS_H"
	print ""
	print "#include <stdint.h>"
	print ""
	print "/*"
	print " * [SPEC] Vol 3, Part H, Appendix D.1.1: the RFC 4493 Example 1 message"
	print " * is the empty string, so there is no array for it."
	print " */"
	print "#define BT_EXTREF_RFC4493_EX1_MSG_LEN 0"
	print ""

	for (i = 1; i <= nord; i++) {
		c = order[i]
		emit(c, val[c], "[SPEC] " desc[c] " (line " srcline[c] ")")
	}

	print "/*"
	print " * [BLUEZ] unit/test-crypto.c.  LITTLE-ENDIAN (BlueZ in-memory) order:"
	print " * index 0 is the LEAST significant octet."
	print " *"
	print " * WHY THERE IS NO CORE 6.3 CITATION FOR THESE VECTORS."
	print " * LE data signing is a current feature of Core 5.2, which is what this"
	print " * stack targets, and implementing it is deliberate.  It was removed"
	print " * later, in Core 6.3 and only in 6.3 ([SPEC] Vol 1, Part C, Section"
	print " * 17.2 \"Removed features\": \"Data signing\").  Because the in-tree Core"
	print " * text is 6.3, it no longer prints the feature: ATT opcode 0xD2"
	print " * (Signed Write Command), SMP command code 0x0A (Signing Information)"
	print " * and the LE key distribution SignKey bit ([SPEC] Vol 3, Part H,"
	print " * Section 3.6.1, Figure 3.11) all appear as \"Previously used\", a term"
	print " * defined in [SPEC] Vol 1, Part E, Section 2.4.2."
	print " *"
	print " * So the gap is in the in-tree document, not in the feature.  The"
	print " * signature construction has no citation in the 6.3 text; its sources"
	print " * here are:"
	print " *   (a) RFC 4493 for the AES-CMAC values themselves, and"
	print " *   (b) BlueZ src/shared/crypto.c bt_crypto_sign_att() /"
	print " *       bt_crypto_verify_att_sign() for the truncate-and-reverse"
	print " *       convention, whose own comment cites Bluetooth Core 4.1,"
	print " *       Vol 3, Part C, Section 10.4.1 - text that is present in every"
	print " *       Core from 4.1 through 6.2 and absent only from 6.3."
	print " */"
	for (i = 1; i <= nbz; i++) {
		c = bzorder[i]
		emit(c, bzval[c], "[BLUEZ] " bzdesc[c] " (line " bzline[c] ")")
	}
	print "#define BT_EXTREF_BLUEZ_SIGN1_MSG_LEN 0"
	print "#define BT_EXTREF_BLUEZ_SIGN5_SIGN_CNT 1"
	print ""

	print "/*"
	print " * ATT signed-write truncation transform, demonstrated on an externally"
	print " * published constant."
	print " *"
	print " * SOURCE VALUE: [SPEC] Vol 3, Part H, Appendix D.1.2 AES_CMAC"
	print " * (= RFC 4493 Section 4 Example 2), reproduced above as"
	print " * bt_extref_rfc4493_ex2_cmac, in spec display order (MSB first)."
	print " *"
	print " * TRANSFORM: this is BlueZ bt_crypto_sign_att()'s tail, applied by hand"
	print " * to that constant.  It is PURE BYTE REORDERING of a published value;"
	print " * no cipher was run to obtain it, and it is NOT claimed to be the"
	print " * signature of any particular ATT PDU (BlueZ byte-swaps the message"
	print " * before the CMAC, so the CMAC input differs from RFC 4493's)."
	print " *"
	print " *   out[0..15] = 07 0a 16 b4 6b 4d 41 44 f7 9b dd 9d d0 4a 28 7c"
	print " *   put_be32(1, out + 8)  overwrites out[8..11] with 00 00 00 01:"
	print " *   out[0..15] = 07 0a 16 b4 6b 4d 41 44 00 00 00 01 d0 4a 28 7c"
	print " *   swap_buf(out, tmp, 16) gives tmp[i] = out[15 - i]:"
	print " *   tmp[0..15] = 7c 28 4a d0 01 00 00 00 44 41 4d 6b b4 16 0a 07"
	print " *   signature  = tmp[4..15]"
	print " *              = 01 00 00 00 44 41 4d 6b b4 16 0a 07"
	print " *"
	print " * So signature[0..3] is the sign counter in LITTLE-endian order and"
	print " * signature[4..11] is out[7..0]: the most significant 8 CMAC octets,"
	print " * reversed.  The least significant 4 CMAC octets out[12..15] are"
	print " * discarded entirely."
	print " */"
	emit("sign_trunc_demo_sig", demo_sig, \
	    "DERIVED by hand from bt_extref_rfc4493_ex2_cmac; see comment above")
	print "#define BT_EXTREF_SIGN_TRUNC_DEMO_SIGN_CNT " sig_cnt
	print "#define BT_EXTREF_SIGN_TRUNC_DEMO_MAC_OFFSET 4"
	print "#define BT_EXTREF_SIGN_TRUNC_DEMO_MAC_LEN 8"
	print ""
	print "#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_SMP_VECTORS_H */"
}

function revhex(h,   i, r) {
	r = ""
	for (i = length(h) / 2 - 1; i >= 0; i--)
		r = r byte(h, i)
	return r
}

function emit(cname, hex, comment,   i, n, line) {
	n = length(hex) / 2
	print "/* " comment " */"
	printf("static const uint8_t bt_extref_%s[%d] = {", cname, n)
	for (i = 0; i < n; i++) {
		if (i % 8 == 0)
			printf("\n\t")
		else
			printf(" ")
		printf("0x%s,", byte(hex, i))
	}
	printf("\n};\n\n")
}
