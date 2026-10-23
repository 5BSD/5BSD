/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../../../usr.sbin/bhyve/smbiostbl.c"

uint16_t cpu_cores, cpu_sockets, cpu_threads;

void
set_config_value_if_unset(const char *path __unused,
    const char *value __unused)
{
}

const char *
get_config_value(const char *path __unused)
{
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(string_cannot_overrun_table);
ATF_TC_BODY(string_cannot_overrun_table, tc)
{
	char buffer[32];
	char *end;
	uint16_t count;
	struct smbios_structure header = {
		.type = SMBIOS_TYPE_OEM,
		.length = sizeof(struct smbios_structure),
	};
	const struct smbios_string strings[] = {
		{ NULL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		{ NULL, NULL },
	};

	memset(buffer, 0xa5, sizeof(buffer));
	smbios_limit = buffer + sizeof(buffer) - 1;
	count = 0;
	ATF_CHECK_EQ(smbios_generic_initializer(&header, strings, buffer,
	    &end, &count), EOVERFLOW);
	ATF_CHECK_EQ(buffer[31], (char)0xa5);
	ATF_CHECK_EQ(count, 0);
}

ATF_TC_WITHOUT_HEAD(empty_string_set_has_double_nul);
ATF_TC_BODY(empty_string_set_has_double_nul, tc)
{
	char buffer[8];
	char *end;
	uint16_t count;
	struct smbios_structure header = {
		.type = SMBIOS_TYPE_OEM,
		.length = sizeof(struct smbios_structure),
	};
	const struct smbios_string strings[] = { { NULL, NULL } };

	memset(buffer, 0xa5, sizeof(buffer));
	smbios_limit = buffer + sizeof(buffer);
	count = 0;
	ATF_REQUIRE_EQ(smbios_generic_initializer(&header, strings, buffer,
	    &end, &count), 0);
	ATF_CHECK_EQ(end, buffer + sizeof(header) + 2);
	ATF_CHECK_EQ(buffer[sizeof(header)], 0);
	ATF_CHECK_EQ(buffer[sizeof(header) + 1], 0);
	ATF_CHECK_EQ(count, 1);
}

ATF_TC_WITHOUT_HEAD(cpu_socket_name_is_bounded);
ATF_TC_BODY(cpu_socket_name_is_bounded, tc)
{
	char buffer[256];
	char *end;
	uint16_t count;

	memset(buffer, 0xa5, sizeof(buffer));
	smbios_limit = buffer + sizeof(buffer);
	count = 0;
	ATF_REQUIRE_EQ(smbios_generic_initializer(
	    (const struct smbios_structure *)&smbios_type4_template,
	    smbios_type4_strings, buffer, &end, &count), 0);

	smbios_limit = end + 2;
	ATF_REQUIRE(smbios_limit < buffer + sizeof(buffer));
	memset(buffer, 0xa5, sizeof(buffer));
	count = 0;
	cpu_sockets = cpu_cores = cpu_threads = 1;
	ATF_CHECK_EQ(smbios_type4_initializer(
	    (const struct smbios_structure *)&smbios_type4_template,
	    smbios_type4_strings, buffer, &end, &count), EOVERFLOW);
	ATF_CHECK_EQ(*smbios_limit, (char)0xa5);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, string_cannot_overrun_table);
	ATF_TP_ADD_TC(tp, empty_string_set_has_double_nul);
	ATF_TP_ADD_TC(tp, cpu_socket_name_is_bounded);
	return (atf_no_error());
}
