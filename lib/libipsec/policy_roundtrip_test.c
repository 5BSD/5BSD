/* SPDX-License-Identifier: BSD-2-Clause */
/* Pure policy conversion checks: no sockets or kernel policy mutations. */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

static void
roundtrip(const char *text)
{
	char *policy, *dump, *again, *dump_again;
	int length;

	policy = ipsec_set_policy(text, strlen(text));
	if (policy == NULL)
		errx(1, "parse %s: %s", text, ipsec_strerror());
	length = ipsec_get_policylen(policy);
	if (length <= 0)
		errx(1, "invalid policy length: %s", text);
	dump = ipsec_dump_policy(policy, " ");
	if (dump == NULL || dump[0] == '\0')
		errx(1, "dump %s: %s", text, ipsec_strerror());
	again = ipsec_set_policy(dump, strlen(dump));
	if (again == NULL || ipsec_get_policylen(again) != length ||
	    memcmp(policy, again, length) != 0)
		errx(1, "policy changed during round trip: %s", text);
	dump_again = ipsec_dump_policy(again, " ");
	if (dump_again == NULL || strcmp(dump, dump_again) != 0)
		errx(1, "unstable policy rendering: %s", text);
	free(dump_again);
	free(again);
	free(dump);
	free(policy);
}

int
main(void)
{
	static const char *invalid[] = {
		"must_error", "in ipsec must_error", "out ipsec esp/must_error",
		"in ipsec ah/tunnel", "out ipsec ah/transport esp/use"
	};
	static const char *valid[] = {
		"in entrust", "out entrust", "in ipsec ah/transport",
		"out ipsec esp/transport//require",
		"in ipsec esp/tunnel/192.0.2.1-192.0.2.2/require"
	};
	unsigned int i;
	char *policy;

	/* Interleave successes and failures to exercise parser state recovery. */
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		policy = ipsec_set_policy(invalid[i], strlen(invalid[i]));
		if (policy != NULL)
			errx(1, "accepted invalid policy: %s", invalid[i]);
		roundtrip(valid[i]);
	}
	/* Numeric address parsing is userland behavior, independent of whether
	 * the target kernel enables IPv6. The maintained parser has no INET6
	 * conditional around this conversion. */
	roundtrip("in ipsec esp/tunnel/2001:db8::1-2001:db8::2/require");
	return (0);
}
