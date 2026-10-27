/* SPDX-License-Identifier: BSD-2-Clause */
/* Native build qualification: text/wire round trips and truncated records. */
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
	static const char *records[] = {
	    "example.invalid. 300 IN A 192.0.2.1",
	    "example.invalid. 300 IN AAAA 2001:db8::1",
	    "example.invalid. 300 IN MX 10 mail.example.invalid.",
	    "example.invalid. 300 IN TXT \"a text record\""
	};
	ldns_rr *original, *decoded;
	uint8_t *wire;
	size_t i, length, position, cut;
	ldns_status status;

	for (i = 0; i < sizeof(records) / sizeof(records[0]); i++) {
		original = decoded = NULL;
		wire = NULL;
		if (ldns_rr_new_frm_str(&original, records[i], 0, NULL, NULL) !=
		    LDNS_STATUS_OK || ldns_rr2wire(&wire, original,
		    LDNS_SECTION_ANSWER, &length) != LDNS_STATUS_OK)
			return (1);
		position = 0;
		if (ldns_wire2rr(&decoded, wire, length, &position,
		    LDNS_SECTION_ANSWER) != LDNS_STATUS_OK || position != length ||
		    ldns_rr_compare(original, decoded) != 0 ||
		    ldns_rr_ttl(original) != ldns_rr_ttl(decoded))
			return (2);
		ldns_rr_free(decoded);
		for (cut = 0; cut < length; cut++) {
			position = 0;
			decoded = NULL;
			status = ldns_wire2rr(&decoded, wire, cut, &position,
			    LDNS_SECTION_ANSWER);
			ldns_rr_free(decoded);
			if (status == LDNS_STATUS_OK) {
				fprintf(stderr, "record %zu accepted truncation %zu/%zu\n",
				    i, cut, length);
				return (3);
			}
		}
		printf("record %zu: round trip and %zu truncations passed\n", i, length);
		ldns_rr_free(original);
		free(wire);
	}
	return (0);
}
