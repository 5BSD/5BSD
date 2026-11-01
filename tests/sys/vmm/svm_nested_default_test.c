/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The AMD nested-SVM host policy (hw.vmm.svm.nested) is on by default.  The
 * first case reads the initial value of the policy variable from the installed
 * vmm.ko without loading it, so it runs on any amd64 host, including emulators
 * without SVM.  The second checks the live tunable when vmm is loaded.  The
 * per-guest opt-in (VM_CAP_NESTED_SVM, bhyve x86.nested_svm) stays off by
 * default; vmm_run_live_test covers that on AMD hardware.
 */

#include <sys/param.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <kenv.h>
#include <libelf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VMM_MODULE "/boot/kernel/vmm.ko"
#define POLICY_SYMBOL "nested_svm_allowed"

/* Initial value of a 4-byte data object in a relocatable kernel module. */
static int
module_int_initializer(const char *path, const char *symbol, int32_t *value)
{
	Elf *elf;
	Elf_Scn *scn = NULL, *target;
	Elf_Data *data;
	GElf_Shdr shdr, tshdr;
	GElf_Sym sym;
	size_t i, count;
	int fd, found = 0;

	ATF_REQUIRE(elf_version(EV_CURRENT) != EV_NONE);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);
	elf = elf_begin(fd, ELF_C_READ, NULL);
	ATF_REQUIRE_MSG(elf != NULL, "%s: %s", path, elf_errmsg(-1));
	while (!found && (scn = elf_nextscn(elf, scn)) != NULL) {
		ATF_REQUIRE(gelf_getshdr(scn, &shdr) != NULL);
		if (shdr.sh_type != SHT_SYMTAB || shdr.sh_entsize == 0)
			continue;
		data = elf_getdata(scn, NULL);
		ATF_REQUIRE(data != NULL);
		count = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < count; i++) {
			const char *name;

			ATF_REQUIRE(gelf_getsym(data, (int)i, &sym) != NULL);
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (name == NULL || strcmp(name, symbol) != 0)
				continue;
			ATF_REQUIRE_EQ_MSG(GELF_ST_TYPE(sym.st_info), STT_OBJECT,
			    "%s is not a data object", symbol);
			ATF_REQUIRE_EQ(sym.st_size, sizeof(*value));
			target = elf_getscn(elf, sym.st_shndx);
			ATF_REQUIRE(target != NULL);
			ATF_REQUIRE(gelf_getshdr(target, &tshdr) != NULL);
			/* An all-zero initializer lives in .bss (no file data). */
			if (tshdr.sh_type == SHT_NOBITS) {
				*value = 0;
			} else {
				data = elf_getdata(target, NULL);
				ATF_REQUIRE(data != NULL);
				ATF_REQUIRE(sym.st_value + sizeof(*value) <=
				    data->d_size);
				memcpy(value, (char *)data->d_buf + sym.st_value,
				    sizeof(*value));
			}
			found = 1;
			break;
		}
	}
	elf_end(elf);
	close(fd);
	if (!found)
		return (errno = ENOENT, -1);
	return (0);
}

ATF_TC(module_default_on);
ATF_TC_HEAD(module_default_on, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The installed vmm.ko permits nested SVM unless the tunable is 0");
}
ATF_TC_BODY(module_default_on, tc)
{
	int32_t value = -1;

	if (module_int_initializer(VMM_MODULE, POLICY_SYMBOL, &value) == -1) {
		if (errno == ENOENT && access(VMM_MODULE, R_OK) == 0)
			atf_tc_fail("%s has no %s symbol", VMM_MODULE,
			    POLICY_SYMBOL);
		atf_tc_skip("no readable %s", VMM_MODULE);
	}
	ATF_CHECK_EQ_MSG(value, 1, "%s initial value is %d", POLICY_SYMBOL,
	    value);
}

ATF_TC(loaded_policy);
ATF_TC_HEAD(loaded_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A loaded vmm reports hw.vmm.svm.nested=1 unless the kernel "
	    "environment sets it");
}
ATF_TC_BODY(loaded_policy, tc)
{
	char env[32];
	int enabled, expected = 1;
	size_t len = sizeof(enabled);

	if (sysctlbyname("hw.vmm.svm.nested", &enabled, &len, NULL, 0) != 0)
		atf_tc_skip("vmm is not loaded (hw.vmm.svm.nested absent)");
	if (kenv(KENV_GET, "hw.vmm.svm.nested", env, sizeof(env)) > 0)
		expected = (int)strtol(env, NULL, 0);
	ATF_CHECK_EQ(enabled, expected);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, module_default_on);
	ATF_TP_ADD_TC(tp, loaded_policy);
	return (atf_no_error());
}
