#include <dt_elf.hh>
#include <dt_elf_bounds.hh>
#include <unordered_map>
#include <unordered_set>
#include <new>
#include <memory>
#include <algorithm>
#include <initializer_list>
#include <dt_hashmap.h>
#include <dt_impl.h>
#include <dt_printf.h>
#include <dt_program.h>
#include <dt_resolver.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <err.h>
#include <errno.h>

extern "C" {
char sec_strtab[] =
	"\0.shstrtab\0.dtrace_prog\0.dtrace_difo\0.dtrace_actdesc\0"
	".dtrace_ecbdesc\0.difo_strtab\0.difo_inttab\0"
	".difo_symtab\0.dtrace_stmtdesc\0.dtrace_predicate\0"
	".dtrace_opts\0.dtrace_vartab\0.dtrace_stmt_idname_table\0"
	".dtrace_ident\0.dtrace_fmtdata\0.dtrace_strdata\0.dtrace_pfv_argv";

static char g_saved_srcident[DT_PROG_IDENTLEN];

#define DTELF_MAXOPTNAME	 64
#define	DTELF_SHSTRTAB		  1
#define	DTELF_PROG		 11
#define	DTELF_DIFO		 24
#define	DTELF_ACTDESC		 37
#define	DTELF_ECBDESC		 53
#define	DTELF_DIFOSTRTAB	 69
#define	DTELF_DIFOINTTAB	 82
#define	DTELF_DIFOSYMTAB	 95
#define	DTELF_STMTDESC		108
#define	DTELF_PREDICATE		125
#define	DTELF_OPTS		143
#define	DTELF_DIFOVARTAB	156
#define	DTELF_IDNAMETAB		171
#define	DTELF_IDENT		197
#define	DTELF_FMTDATA		211
#define	DTELF_STRDATA		227
#define	DTELF_PFV_ARGV		243

#define	DTELF_VARIABLE_SIZE	  0

#define	DTELF_PROG_SECIDX	  2

dt_elf_opt_t dtelf_ctopts[] = {
	{ "aggpercpu", 0, NULL, DTRACE_A_PERCPU },
	{ "amin", 0, NULL, 0 },
	{ "argref", 0, NULL, DTRACE_C_ARGREF },
	{ "core", 0, NULL, 0 },
	{ "cpp", 0, NULL, DTRACE_C_CPP },
	{ "cpphdrs", 0, NULL, 0 },
	{ "cpppath", 0, NULL, 0 },
	{ "ctypes", 0, NULL, 0 },
	{ "defaultargs", 0, NULL, DTRACE_C_DEFARG },
	{ "dtypes", 0, NULL, 0 },
	{ "debug", 0, NULL, 0 },
	{ "define", 0, NULL, (uintptr_t)"-D" },
	{ "droptags", 0, NULL, 0 },
	{ "empty", 0, NULL, DTRACE_C_EMPTY },
	{ "encoding", 0, NULL, 0 },
	{ "errtags", 0, NULL, DTRACE_C_ETAGS },
	{ "evaltime", 0, NULL, 0 },
	{ "incdir", 0, NULL, (uintptr_t)"-I" },
	{ "iregs", 0, NULL, 0 },
	{ "kdefs", 0, NULL, DTRACE_C_KNODEF },
	{ "knodefs", 0, NULL, DTRACE_C_KNODEF },
	{ "late", 0, NULL, 0 },
	{ "lazyload", 0, NULL, 0 },
	{ "ldpath", 0, NULL, 0 },
	{ "libdir", 0, NULL, 0 },
	{ "linkmode", 0, NULL, 0 },
	{ "linktype", 0, NULL, 0 },
	{ "nolibs", 0, NULL, DTRACE_C_NOLIBS },
#ifdef __FreeBSD__
	{ "objcopypath", 0, NULL, 0 },
#endif
	{ "pgmax", 0, NULL, 0 },
	{ "pspec", 0, NULL, DTRACE_C_PSPEC },
	{ "setenv", 0, NULL, 1 },
	{ "stdc", 0, NULL, 0 },
	{ "strip", 0, NULL, DTRACE_D_STRIP },
	{ "syslibdir", 0, NULL, 0 },
	{ "tree", 0, NULL, 0 },
	{ "tregs", 0, NULL, 0 },
	{ "udefs", 0, NULL, DTRACE_C_UNODEF },
	{ "undef", 0, NULL, (uintptr_t)"-U" },
	{ "unodefs", 0, NULL, DTRACE_C_UNODEF },
	{ "unsetenv", 0, NULL, 0 },
	{ "verbose", 0, NULL, DTRACE_C_DIFV },
	{ "version", 0, NULL, 0 },
	{ "zdefs", 0, NULL, DTRACE_C_ZDEFS },
	{ NULL, 0, NULL, 0 }
};

dt_elf_opt_t dtelf_rtopts[] = {
	{ "aggsize", 0, NULL, DTRACEOPT_AGGSIZE },
	{ "bufsize", 0, NULL, DTRACEOPT_BUFSIZE },
	{ "bufpolicy", 0, NULL, DTRACEOPT_BUFPOLICY },
	{ "bufresize", 0, NULL, DTRACEOPT_BUFRESIZE },
	{ "cleanrate", 0, NULL, DTRACEOPT_CLEANRATE },
	{ "cpu", 0, NULL, DTRACEOPT_CPU },
	{ "destructive", 0, NULL, DTRACEOPT_DESTRUCTIVE },
	{ "dynvarsize", 0, NULL, DTRACEOPT_DYNVARSIZE },
	{ "grabanon", 0, NULL, DTRACEOPT_GRABANON },
	{ "jstackframes", 0, NULL, DTRACEOPT_JSTACKFRAMES },
	{ "ddtracearg", 0, NULL, DTRACEOPT_DDTRACEARG},
	{ "jstackstrsize", 0, NULL, DTRACEOPT_JSTACKSTRSIZE },
	{ "nspec", 0, NULL, DTRACEOPT_NSPEC },
	{ "specsize", 0, NULL, DTRACEOPT_SPECSIZE },
	{ "stackframes", 0, NULL, DTRACEOPT_STACKFRAMES },
	{ "statusrate", 0, NULL, DTRACEOPT_STATUSRATE },
	{ "strsize", 0, NULL, DTRACEOPT_STRSIZE },
	{ "ustackframes", 0, NULL, DTRACEOPT_USTACKFRAMES },
	{ "temporal", 0, NULL, DTRACEOPT_TEMPORAL },
	{ "immstackframes", 0, NULL, DTRACEOPT_IMMSTACKFRAMES },
	{ "immstackstrsize", 0, NULL, DTRACEOPT_IMMSTACKSTRSIZE },
	{ NULL, 0, NULL, 0 }
};

dt_elf_opt_t dtelf_drtopts[] = {
	{ "agghist", 0, NULL, DTRACEOPT_AGGHIST },
	{ "aggpack", 0, NULL, DTRACEOPT_AGGPACK },
	{ "aggrate", 0, NULL, DTRACEOPT_AGGRATE },
	{ "aggsortkey", 0, NULL, DTRACEOPT_AGGSORTKEY },
	{ "aggsortkeypos", 0, NULL, DTRACEOPT_AGGSORTKEYPOS },
	{ "aggsortpos", 0, NULL, DTRACEOPT_AGGSORTPOS },
	{ "aggsortrev", 0, NULL, DTRACEOPT_AGGSORTREV },
	{ "aggzoom", 0, NULL, DTRACEOPT_AGGZOOM },
	{ "flowindent", 0, NULL, DTRACEOPT_FLOWINDENT },
	{ "oformat", 0, NULL, DTRACEOPT_OFORMAT },
	{ "quiet", 0, NULL, DTRACEOPT_QUIET },
	{ "rawbytes", 0, NULL, DTRACEOPT_RAWBYTES },
	{ "stackindent", 0, NULL, DTRACEOPT_STACKINDENT },
	{ "switchrate", 0, NULL, DTRACEOPT_SWITCHRATE },
	{ NULL, 0, NULL, 0 }
};
} // extern "C"

namespace dtrace {
typedef struct _dt_elf_eopt {
	char		eo_name[DTELF_MAXOPTNAME];
	uint64_t	eo_option;
	size_t		eo_len;
	char		eo_arg[];
} _dt_elf_eopt_t;

const dt_elf_ref_t HyperTraceELFParser::kElfProgramSection = 2;

HyperTraceELFParser::HyperTraceELFParser(dtrace_hdl_t *_dtp, dtrace_prog_t *pgp,
    int _elfHandle, const char *_filename, bool _doResolve,
    uint32_t _resolverFlags)
    : elfHandle(_elfHandle)
    , elfPtr(nullptr)
    , filename(_filename)
    , idNameSize(1)
    , idNameOffset(0)
    , idNameTable(nullptr)
    , dtp(_dtp)
    , program(pgp)
    , errorMessage("")
    , firstActionSection(0)
    , lastActionSection(0)
    , previousActDesc(nullptr)
    , doResolve(_doResolve)
    , resolverFlags(_resolverFlags)
{
}

HyperTraceELFParser::~HyperTraceELFParser()
{
	if (elfPtr != nullptr)
		elf_end(elfPtr);
	if (checksumHandle != -1)
		close(checksumHandle);
	for (auto *ecb : parsedECBs)
		dt_ecbdesc_release(dtp, ecb);
	for (auto *buffer : writerBuffers)
		free(buffer);
	if (ownsIdNameTable)
		free(idNameTable);
}

void
HyperTraceELFParser::setErrorMessage(const char *fmt, ...)
{
	va_list va, va_cp;
	va_start(va, fmt);
	va_copy(va_cp, va);
	/* An unformattable message (vsnprintf < 0) is reported as empty
	 * rather than leaving a previous message in place. */
	auto len = vsnprintf(nullptr, 0, fmt, va);
	errorMessage.assign(len > 0 ? (size_t)len : 0, '\0');
	if (len > 0)
		vsnprintf(&errorMessage[0], len + 1, fmt, va_cp);
	va_end(va_cp);
	va_end(va);
}

Pair<size_t, int>
HyperTraceELFParser::createElfString(const char *name)
{
	size_t len = strlen(name) + 1;
	size_t offset = idNameOffset;

	/*
	 * Grow the identifier name table (doubling, starting from one byte)
	 * until the new string and a free byte fit; offsets stay valid.
	 */
	if (offset + len >= idNameSize) {
		size_t newSize = idNameSize;
		while (offset + len >= newSize)
			newSize <<= 1;
		auto *table = (char *)dt_alloc(dtp, newSize);
		if (table == nullptr) {
			setErrorMessage("identifier string table allocation failed");
			return (makeError(0ull, E_HYPERTRACE_SYS));
		}
		if (idNameTable != nullptr) {
			memcpy(table, idNameTable, idNameSize);
			dt_free(dtp, idNameTable);
		}
		idNameTable = table;
		idNameSize = newSize;
		ownsIdNameTable = true;
	}

	// Add the new string to the table and bump the offset.
	memcpy(idNameTable + offset, name, len);
	idNameOffset += len;
	// Return the old offset where the new string resides.
	return (makeSuccess(offset));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfIntTab(dtrace_difo_t *difo)
{
	if (difo->dtdo_inttab == NULL) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	auto *inttab = (uint64_t *)ownBuffer(dt_alloc(dtp,
	    sizeof(uint64_t) * difo->dtdo_intlen));
	if (inttab == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	memcpy(inttab, difo->dtdo_inttab, sizeof(uint64_t) * difo->dtdo_intlen);

	/*
	 * For the integer table, we require an alignment of 8 and specify it as
	 * a bunch of bytes (ELF_T_BYTE) because this is a 32-bit ELF file.
	 *
	 * In the case that this is parsed on a 32-bit machine, we deal with it
	 * in the same way that DTrace deals with 64-bit integers in the inttab
	 * on 32-bit machines.
	 */
	data->d_align = 8;
	data->d_buf = inttab;
	data->d_size = sizeof(uint64_t) * difo->dtdo_intlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * The entsize is set to sizeof(uint64_t) because each entry is a 64-bit
	 * integer, which is fixed-size. According to the ELF specification, we
	 * have to specify what the size of each entry is if it is fixed-size.
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOINTTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(uint64_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfStrTab(dtrace_difo_t *difo)
{
	/*
	 * If the string table is NULL, we return a NULL section,
	 * which will return section index 0 when passed into elf_ndxscn().
	 */
	if (difo->dtdo_strtab == NULL) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	auto *strtab = (char *)ownBuffer(dt_alloc(dtp, difo->dtdo_strlen));
	if (strtab == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	memcpy(strtab, difo->dtdo_strtab, difo->dtdo_strlen);

	/*
	 * We don't have any special alignment requirements. Treat this as an
	 * ordinary string table in ELF (apart from the specification in the
	 * section header).
	 */
	data->d_align = 1;
	data->d_buf = strtab;
	data->d_size = difo->dtdo_strlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}
	/*
	 * The strings in the string table are not fixed-size, so entsize is set to 0.
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOSTRTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

/*
 * A symbol table in DTrace is just a string table. This subroutine handles yet another
 * string table with minimal differences from the regular DIFO string table.
 */
Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfSymTab(dtrace_difo_t *difo)
{
	if (difo->dtdo_symtab == NULL) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_newscn(elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	auto *symtab = (char *)ownBuffer(dt_alloc(dtp, difo->dtdo_symlen));
	if (symtab == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	memcpy(symtab, difo->dtdo_symtab, difo->dtdo_symlen);

	data->d_align = 1;
	data->d_buf = symtab;
	data->d_size = difo->dtdo_symlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOSYMTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfVarTab(dtrace_difo_t *difo)
{
	if (difo->dtdo_vartab == NULL) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	auto *vartab = (dtrace_difv_t *)ownBuffer(dt_alloc(dtp,
	    sizeof(dtrace_difv_t) * difo->dtdo_varlen));
	if (vartab == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	/*
	 * Populate the temporary buffer that will contain our variable table.
	 */
	memcpy(vartab, difo->dtdo_vartab,
	    sizeof(dtrace_difv_t) * difo->dtdo_varlen);

	/* Compiler process addresses are never meaningful to an ELF consumer. */
	for (uint_t i = 0; i < difo->dtdo_varlen; i++) {
		vartab[i].dtdv_sym = nullptr;
		vartab[i].dtdv_ctfp = nullptr;
		vartab[i].dtdv_tf = nullptr;
		vartab[i].dtdv_stack = nullptr;
	}

	/*
	 * On both 32 and 64-bit architectures, dtrace_difv_t only requires
	 * an alignment of 4.
	 */
	data->d_align = 4;
	data->d_buf = vartab;
	data->d_size = difo->dtdo_varlen * sizeof(dtrace_difv_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * Each entry is of fixed size, so entsize is set to sizeof(dtrace_difv_t).
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOVARTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dtrace_difv_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}


Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfDifo(dtrace_difo_t *difo)
{
	/*
	 * If the difo is NULL, we return a NULL section,
	 * which will return section index 0 when passed into elf_ndxscn().
	 */
	if (difo == NULL)
		return (makeSuccess(nullptr));

	/*
	 * Each dt_elf_difo_t has a flexible array member at the end of it that
	 * contains all of the instructions associated with a DIFO. In order to
	 * avoid creating a separate section that contains the instructions, we
	 * simply put them at the end of the DIFO.
	 *
	 * Here, we allocate the edifo according to how many instructions are present
	 * in the current DIFO (dtdo_len).
	 */
	auto *edifo = (dt_elf_difo_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_difo_t) + (difo->dtdo_len * sizeof(dif_instr_t))));
	if (edifo == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * From each DIFO table (integer, string, symbol, variable), get the reference
	 * to the corresponding ELF section that contains it.
	 */
	auto rval1 = createElfIntTab(difo);
	if (rval1.second) {
		return makeError(nullptr, rval1.second);
	}
	edifo->dted_inttab = elf_ndxscn(rval1.first);
	auto rval2 = createElfStrTab(difo);
	if (rval2.second) {
		return makeError(nullptr, rval2.second);
	}
	edifo->dted_strtab = elf_ndxscn(rval2.first);
	auto rval3 = createElfSymTab(difo);
	if (rval3.second) {
		return makeError(nullptr, rval3.second);
	}
	edifo->dted_symtab = elf_ndxscn(rval3.first);
	auto rval4 = createElfVarTab(difo);
	if (rval4.second) {
		return makeError(nullptr, rval4.second);
	}
	edifo->dted_vartab = elf_ndxscn(rval4.first);
	edifo->dted_intlen = difo->dtdo_intlen;
	edifo->dted_strlen = difo->dtdo_strlen;
	edifo->dted_symlen = difo->dtdo_symlen;
	edifo->dted_varlen = difo->dtdo_varlen;
	edifo->dted_rtype = difo->dtdo_rtype;
	edifo->dted_destructive = difo->dtdo_destructive;
	edifo->dted_len = difo->dtdo_len;

	/*
	 * Fill in the DIF instructions.
	 */
	for (uint_t i = 0; i < difo->dtdo_len; i++)
		edifo->dted_buf[i] = difo->dtdo_buf[i];

	/*
	 * Because of intlen/strlen/symlen/varlen/etc, we require the section data to
	 * be 8-byte aligned.
	 */
	data->d_align = 8;
	data->d_buf = edifo;
	data->d_size = sizeof(dt_elf_difo_t) +
	    (difo->dtdo_len * sizeof(dif_instr_t));
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * This is a section containing just _one_ DIFO. Therefore its size is not
	 * variable and we specify entsize to be the size of the whole section.
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFO;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_difo_t) +
	    (difo->dtdo_len * sizeof(dif_instr_t));
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfEcbDesc(dtrace_stmtdesc_t *stmt)
{
	if (stmt->dtsd_ecbdesc == NULL) {
		return (makeSuccess(nullptr));
	}

	auto ecbKey = Var<dtrace_ecbdesc_t *, dt_elf_ref_t>(stmt->dtsd_ecbdesc);
	Elf_Scn *scn = Get<Elf_Scn *>(ecbMap[ecbKey]);
	if (scn != NULL) {
		return (makeSuccess(scn));
	}

	dt_elf_ecbdesc_t *eecb = (dt_elf_ecbdesc_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_ecbdesc_t)));
	if (eecb == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	dtrace_ecbdesc_t *ecb = stmt->dtsd_ecbdesc;
	auto actionKey = Var<dtrace_actdesc_t *, dt_elf_ref_t>(
	    ecb->dted_action);
	auto *actSection = Get<Elf_Scn *>(actionMap[actionKey]);
	/*
	 * It is possible that the ECB has no actions, e.g. BEGIN {}.
	 */
	if (actSection != NULL)
		eecb->dtee_action = elf_ndxscn(actSection);

	/*
	 * While the DTrace struct has a number of things associated with it
	 * that are not the DIFO, this is only useful in the context of the
	 * kernel. We do not need this in userspace, and therefore simply treat
	 * dtee_pred as a DIFO.
	 */
	auto rval5 = createElfDifo(ecb->dted_pred.dtpdd_difo);
	if (rval5.second) {
		return (makeError(nullptr, rval5.second));
	}
	eecb->dtee_pred = elf_ndxscn(rval5.first);
	eecb->dtee_probe.dtep_pdesc = ecb->dted_probe;
	eecb->dtee_uarg = ecb->dted_uarg;
	data->d_align = 8;
	data->d_buf = eecb;
	data->d_size = sizeof(dt_elf_ecbdesc_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * Since dt_elf_ecbdesc_t is of fixed size, we set entsize to its size.
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_ECBDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_ecbdesc_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	ecbKey = Var<dtrace_ecbdesc_t *, dt_elf_ref_t>(ecb);
	ecbMap[ecbKey] = scn;
	return (makeSuccess(scn));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfAction(dtrace_actdesc_t *ad, dt_elf_ref_t sscn)
{
	auto actionKey = Var<dtrace_actdesc_t *, dt_elf_ref_t>(ad);
	auto *scn = Get<Elf_Scn *>(actionMap[actionKey]);
	if (scn != NULL) {
		return (makeSuccess(scn));
	}

	dt_elf_actdesc_t *eact = (dt_elf_actdesc_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_actdesc_t)));
	if (eact == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	if (ad->dtad_difo != NULL) {
		auto rval = createElfDifo(ad->dtad_difo);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		eact->dtea_difo = elf_ndxscn(rval.first);
	} else
		eact->dtea_difo = 0;

	/*
	 * Fill in all of the simple struct members.
	 */
	eact->dtea_next = 0; /* Filled in later */
	eact->dtea_kind = ad->dtad_kind;
	eact->dtea_ntuple = ad->dtad_ntuple;
	eact->dtea_arg = ad->dtad_arg;
	eact->dtea_uarg = sscn;
	eact->dtea_return = ad->dtad_return;

	data->d_align = 8;
	data->d_buf = eact;
	data->d_size = sizeof(dt_elf_actdesc_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * Since actions are of fixed size (because they contain references to a DIFO)
	 * and other actions, instead of varying in size because they contain the DIFO
	 * itself, we set entsize to sizeof(dt_elf_actdesc_t). In the future, we may
	 * consider a section that contains all of the actions, rather than a separate
	 * section for each action, but this would require some re-engineering of the
	 * code around ECBs.
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_ACTDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_actdesc_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	actionKey = Var<dtrace_actdesc_t *, dt_elf_ref_t>(ad);
	actionMap[actionKey] = scn;
	return (makeSuccess(scn));
}

int
HyperTraceELFParser::createElfActions(dtrace_stmtdesc_t *stmt, dt_elf_ref_t sscn)
{
	Elf_Scn *scn;
	Elf_Data *data = NULL;
	dtrace_actdesc_t *ad;
	dtrace_ecbdesc_t *edp;

	if (stmt->dtsd_action == NULL) {
		firstActionSection = 0;
		lastActionSection = 0;
		return (0);
	}

	/*
	 * If we have the first action, then we better have the last action as well.
	 */
	if (stmt->dtsd_action_last == NULL) {
		setErrorMessage("%s (%d): action last is NULL, but first is not",
		    this->filename, this->elfHandle);
		return (E_HYPERTRACE_ELFCREATE);
	}

	/*
	 * We iterate through the actions, creating a new section with its data filled
	 * with an ELF representation for each DTrace action we iterate through. We then
	 * refer to the previous action we created in our list of actions and assign the
	 * next reference in the ELF file, which constructs the "action list" as known
	 * in DTrace, but in our ELF file.
	 */
	edp = stmt->dtsd_ecbdesc;
	for (ad = edp->dted_action; ad; ad = ad->dtad_next) {
		/* An action is linked to its predecessor only when this writer
		 * serializes it for the first time; shared actions keep the
		 * link of their first serialization. */
		bool fresh = Get<Elf_Scn *>(actionMap[
		    Var<dtrace_actdesc_t *, dt_elf_ref_t>(ad)]) == nullptr;
		auto rval = createElfAction(ad, sscn);
		if (rval.second != 0) {
			return (rval.second);
		}

		scn = rval.first;
		data = elf_getdata(scn, NULL);
		if (data == NULL) {
			setErrorMessage("elf_getdata(%s (%d)): failed: %s",
			    this->filename, this->elfHandle, elf_errmsg(-1));
			return (E_HYPERTRACE_ELFCREATE);
		}

		if (fresh && previousActDesc != NULL)
			previousActDesc->dtea_next = elf_ndxscn(scn);

		previousActDesc = (dt_elf_actdesc_t *)data->d_buf;

		/*
		 * If this is the first action, we will save it in order to fill in
		 * the necessary data in the ELF representation of a D program. It needs
		 * a reference to the first action. Same with last action.
		 */
		if (ad == stmt->dtsd_action)
			firstActionSection = elf_ndxscn(scn);
		if (ad == stmt->dtsd_action_last)
			lastActionSection = elf_ndxscn(scn);
	}

	/*
	 * We know that this is the last section that we could have
	 * created, so we simply set the state variable to it.
	 */
	previousActDesc = NULL;
	return (0);
}

/*
 * A statement's string data: the CTF type reference print() records
 * ("module`id", dt_cc.c), which the consumer uses to print the value by
 * type.  It is kept in the identifier name table; the reference is its
 * offset plus one (0: none).  Without it, a program that came back through
 * an ELF file (the host runs the guest-linked program) printed print()'s
 * value as raw bytes.
 */
Pair<dt_elf_ref_t, int>
HyperTraceELFParser::createElfStrData(void *strdata)
{
	if (strdata == NULL)
		return (makeSuccess(0));
	auto rval = createElfString((const char *)strdata);
	if (rval.second)
		return (makeError(0, rval.second));
	return (makeSuccess(rval.first + 1));
}

Pair<dt_elf_ref_t, int>
HyperTraceELFParser::createElfPfd(dt_pfargd_t *pfd)
{
	if (pfd == NULL) {
		return (makeSuccess(0));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}

	auto *epfd = (dt_elf_pfargd_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_pfargd_t)));
	if (epfd == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(0, E_HYPERTRACE_SYS));
	}

	if (pfd->pfd_prefix == NULL) {
		epfd->epfd_prefix = 0;
	} else {
		auto rval = createElfString(pfd->pfd_prefix);
		if (rval.second) {
			return (makeError(0, rval.second));
		}
		epfd->epfd_prefix = rval.first;
	}
	epfd->epfd_preflen = pfd->pfd_preflen;
	memcpy(epfd->epfd_fmt, pfd->pfd_fmt, 8);
	epfd->epfd_flags = pfd->pfd_flags;
	epfd->epfd_width = pfd->pfd_width;
	epfd->epfd_dynwidth = pfd->pfd_dynwidth;
	epfd->epfd_prec = pfd->pfd_prec;
	if (pfd->pfd_conv != NULL) {
		auto rval = createElfString(pfd->pfd_conv->pfc_name);
		if (rval.second)
			return (makeError(0, rval.second));
		if (rval.first >= UINT32_MAX) {
			setErrorMessage("format conversion offset exceeds ELF limit");
			return (makeError(0, E_HYPERTRACE_ELFCREATE));
		}
		epfd->epfd_conv = (dt_elf_ref_t)rval.first + 1;
	} else if (pfd->pfd_fmt[0] != '\0') {
		setErrorMessage("format conversion is missing");
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}
	auto rval6 = createElfPfd(pfd->pfd_next);
	if (rval6.second) {
		return (makeError(0, rval6.second));
	}
	epfd->epfd_next = rval6.first;
	data->d_buf = epfd;
	data->d_size = sizeof(dt_elf_pfargd_t);
	data->d_align = 8;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_PFV_ARGV;
	shdr->sh_flags = SHF_OS_NONCONFORMING;
	shdr->sh_entsize = sizeof(dt_elf_pfargd_t);
	(void)elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(elf_ndxscn(scn)));
}

Pair<dt_elf_ref_t, int>
HyperTraceELFParser::createElfFmtData(void *fmtdata)
{
	auto *pfv = (dt_pfargv_t *)fmtdata;
	if (pfv == NULL) {
		return (makeSuccess(0));
	}

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}

	auto *epfv = (dt_elf_pfargv_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_pfargv_t)));
	if (epfv == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(0, E_HYPERTRACE_SYS));
	}

	/*
	 * Fill out our fields
	 */
	auto rval7 = createElfString(pfv->pfv_format);
	if (rval7.second) {
		return (makeError(0, rval7.second));
	}
	epfv->epfv_format = rval7.first;
	auto rval8 = createElfPfd(pfv->pfv_argv);
	if (rval8.second) {
		return (makeError(0, rval8.second));
	}
	epfv->epfv_argv = rval8.first;
	epfv->epfv_argc = pfv->pfv_argc;
	epfv->epfv_flags = pfv->pfv_flags;
	data->d_buf = epfv;
	data->d_size = sizeof(dt_elf_pfargv_t);
	data->d_align = 8;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(0, E_HYPERTRACE_ELFCREATE));
	}
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_FMTDATA;
	shdr->sh_flags = SHF_OS_NONCONFORMING;
	shdr->sh_entsize = sizeof(dt_elf_pfargv_t);
	(void)elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void)elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(elf_ndxscn(scn)));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfStatement(dtrace_stmtdesc_t *stmt,
    dt_elf_stmt_t *pstmt)
{
	if (stmt == NULL)
		return (makeSuccess(nullptr));

	auto *estmt = (dt_elf_stmt_t *)ownBuffer(dt_zalloc(dtp,
	    sizeof(dt_elf_stmt_t)));
	if (estmt == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}
	int actionError = createElfActions(stmt, elf_ndxscn(scn));
	if (actionError != 0)
		return (makeError(nullptr, actionError));
	auto rval10 = createElfEcbDesc(stmt);
	if (rval10.second) {
		return (makeError(nullptr, rval10.second));
	}
	estmt->dtes_ecbdesc = elf_ndxscn(rval10.first);

	/*
	 * Fill in the first and last action for a statement that we've
	 * previously saved when creating actions.
	 */
	estmt->dtes_action = firstActionSection;
	estmt->dtes_action_last = lastActionSection;
	estmt->dtes_descattr.dtea_attr = stmt->dtsd_descattr;
	estmt->dtes_stmtattr.dtea_attr = stmt->dtsd_stmtattr;
	estmt->dtes_aggdata = 0;
	auto rval11 = createElfFmtData(stmt->dtsd_fmtdata);
	if (rval11.second) {
		return (makeError(nullptr, rval11.second));
	}
	estmt->dtes_fmtdata = rval11.first;
	auto rvalsd = createElfStrData(stmt->dtsd_strdata);
	if (rvalsd.second) {
		return (makeError(nullptr, rvalsd.second));
	}
	estmt->dtes_strdata = rvalsd.first;
	estmt->dtes_self = elf_ndxscn(scn);
	Elf32_Shdr *shdr;
	if (stmt->dtsd_aggdata != NULL) {
		auto *aid = (dt_ident_t *)stmt->dtsd_aggdata;
		Elf_Scn *aid_scn = elf_newscn(this->elfPtr);
		if (aid_scn == NULL) {
			setErrorMessage("elf_newscn(%s (%d)): failed: %s",
			    this->filename, this->elfHandle, elf_errmsg(-1));
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}
		Elf_Data *aid_data = elf_newdata(aid_scn);
		if (aid_data == NULL) {
			setErrorMessage("elf_newdata(%s (%d)): failed: %s",
			    this->filename, this->elfHandle, elf_errmsg(-1));
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}
		auto *eaid = (dt_elf_ident_t *)ownBuffer(dt_zalloc(dtp,
		    sizeof(dt_elf_ident_t)));
		if (eaid == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    this->filename, this->elfHandle, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}
		auto rval12 = createElfString(aid->di_name);
		if (rval12.second) {
			return (makeError(nullptr, rval12.second));
		}
		eaid->edi_name = rval12.first;
		eaid->edi_id = aid->di_id;
		eaid->edi_kind = aid->di_kind;
		eaid->edi_flags = aid->di_flags;
		eaid->edi_attr.dtea_attr = aid->di_attr;
		eaid->edi_vers = aid->di_vers;
		aid_data->d_buf = eaid;
		aid_data->d_size = sizeof(dt_elf_ident_t);
		aid_data->d_align = 8;
		aid_data->d_type = ELF_T_BYTE;
		aid_data->d_version = EV_CURRENT;
		shdr = elf32_getshdr(aid_scn);
		if (shdr == NULL) {
			setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
			    this->filename, this->elfHandle, elf_errmsg(-1));
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}
		shdr->sh_type = SHT_DTRACE_elf;
		shdr->sh_name = DTELF_IDENT;
		shdr->sh_flags = SHF_OS_NONCONFORMING;
		shdr->sh_entsize = sizeof(dt_elf_ident_t);
		(void) elf_flagshdr(aid_scn, ELF_C_SET, ELF_F_DIRTY);
		(void) elf_flagscn(aid_scn, ELF_C_SET, ELF_F_DIRTY);
		(void) elf_flagdata(aid_data, ELF_C_SET, ELF_F_DIRTY);
		estmt->dtes_aggdata = elf_ndxscn(aid_scn);
	}

	/*
	 * If this action is an aggregation, we save the aggregation ID
	 * and name.
	 */
	if (pstmt != NULL)
		pstmt->dtes_next = elf_ndxscn(scn);

	data->d_align = 4;
	data->d_buf = estmt;
	data->d_size = sizeof(dt_elf_stmt_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_STMTDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_stmt_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

Pair<Elf_Scn *, int>
HyperTraceELFParser::createElfOptions(void)
{
	size_t buflen = 0;	/* bytes of records written */
	size_t bufmaxlen = 0;	/* allocated record buffer size */
	/* Owns the growing record buffer until a section takes it. */
	std::unique_ptr<unsigned char, decltype(&free)> bufGuard(nullptr, &free);

	/*
	 * Every option set on the handle becomes one record: its name, the
	 * table's option value (for define/incdir/undef, the compiler flag
	 * string "-D"/"-I"/"-U"), and its NUL-terminated argument padded to
	 * eight bytes.  Names and flag strings are the constants of the tables
	 * above, all shorter than their fields.
	 */
	for (dt_elf_opt_t *table : { dtelf_ctopts, dtelf_rtopts, dtelf_drtopts }) {
		for (auto *op = table; op->dteo_name != NULL; op++) {
			if (op->dteo_set == 0)
				continue;

			size_t argsize = op->dteo_arg != NULL ?
			    strlen(op->dteo_arg) + 1 : 0;
			size_t arglen = (argsize + 7) & ~(size_t)7;
			size_t len = sizeof(_dt_elf_eopt_t) + arglen;
			if (buflen + len > bufmaxlen) {
				size_t newmax = std::max(bufmaxlen * 2, buflen + len);
				auto *nbuf = (unsigned char *)dt_alloc(dtp, newmax);
				if (nbuf == NULL) {
					setErrorMessage(
					    "%s (%d): allocation failed: %s",
					    this->filename, this->elfHandle,
					    strerror(errno));
					return (makeError(nullptr, E_HYPERTRACE_SYS));
				}
				if (buflen != 0)
					memcpy(nbuf, bufGuard.get(), buflen);
				bufGuard.reset(nbuf);
				bufmaxlen = newmax;
			}

			auto *eop = (_dt_elf_eopt_t *)(bufGuard.get() + buflen);
			memset(eop, 0, len);
			strlcpy(eop->eo_name, op->dteo_name, sizeof(eop->eo_name));
			eop->eo_len = arglen;
			if (argsize != 0)
				memcpy(eop->eo_arg, op->dteo_arg, argsize);
			if (strcmp("define", op->dteo_name) == 0 ||
			    strcmp("incdir", op->dteo_name) == 0 ||
			    strcmp("undef", op->dteo_name) == 0)
				strlcpy((char *)&eop->eo_option,
				    (const char *)op->dteo_option,
				    sizeof(eop->eo_option));
			else
				eop->eo_option = op->dteo_option;
			buflen += len;
		}
	}

	if (buflen == 0)
		return (makeSuccess(static_cast<Elf_Scn *>(nullptr)));

	Elf_Scn *scn = elf_newscn(this->elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}
	data->d_align = 8;
	data->d_buf = ownBuffer(bufGuard.release());
	data->d_size = buflen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
	}
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_OPTS;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	return (makeSuccess(scn));
}

int
HyperTraceELFParser::createElf(int endian)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		setErrorMessage("elf_version(EV_CURRENT) is EV_NONE: %s",
		    elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	elfPtr = elf_begin(this->elfHandle, ELF_C_WRITE, NULL);
	if (elfPtr == NULL) {
		setErrorMessage(
		    "elf_begin(%s (%d), ELF_C_WRITE, NULL): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	Elf32_Ehdr *ehdr = elf32_newehdr(elfPtr);
	if (ehdr == NULL) {
		setErrorMessage("elf32_newehdr(%s (%d): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	ehdr->e_ident[EI_DATA] = endian;
	ehdr->e_machine = EM_NONE;
	ehdr->e_type = ET_EXEC;
	ehdr->e_ident[EI_CLASS] = ELFCLASS32;

	/*
	 * Enable extended section numbering.
	 */
	ehdr->e_shstrndx = SHN_XINDEX;
	ehdr->e_shnum = 0;
	ehdr->e_shoff = 0;

	Elf32_Phdr *phdr = elf32_newphdr(elfPtr, 1);
	if (phdr == NULL) {
		setErrorMessage("elf_newphdr(%s (%d), 1): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	/*
	 * The very first section is a string table of section names.
	 */
	Elf_Scn *scn = elf_newscn(elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	data->d_align = 1;
	data->d_buf = sec_strtab;
	data->d_size = sizeof(sec_strtab);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	Elf32_Shdr *shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	shdr->sh_type = SHT_STRTAB;
	shdr->sh_name = DTELF_SHSTRTAB;
	shdr->sh_flags = SHF_STRINGS;
	shdr->sh_entsize = DTELF_VARIABLE_SIZE;
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

	/*
	 * For extended numbering
	 */
	Elf32_Shdr *s0hdr = elf32_getshdr(elf_getscn(this->elfPtr, 0));
	if (s0hdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	s0hdr->sh_size = 0; /* Number of sections -- filled in later! */
	s0hdr->sh_link = elf_ndxscn(scn); /* .shstrtab index */
	(void) elf_flagshdr(elf_getscn(this->elfPtr, 0), ELF_C_SET, ELF_F_DIRTY);

	/*
	 * Second section gives us the necessary information about a DTrace
	 * program. What DOF version we need, reference to the section that
	 * contains the first statement, etc.
	 */
	scn = elf_newscn(elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	auto progsize = sizeof(dt_elf_prog_t) +
	    (program->dp_neprobes * sizeof(dtrace_probedesc_t));
	auto *eprog = (dt_elf_prog *)ownBuffer(dt_zalloc(dtp, progsize));
	if (eprog == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (E_HYPERTRACE_SYS);
	}

	data->d_align = 4;
	data->d_buf = eprog;
	data->d_size = progsize;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	/*
	 * Currently we only have one program that put into the ELF file.
	 * However, at some point we may wish to have multiple programs. In any
	 * case, since dt_elf_prog_t is of fixed size, entsize is set to
	 * sizeof(dt_elf_prog_t).
	 */
	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_PROG;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_prog_t);
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

	eprog->dtep_haserror = program->dp_haserror;
	dt_stmt_t *stp;
	if (eprog->dtep_haserror) {
		memcpy(eprog->dtep_err, program->dp_err, DT_PROG_ERRLEN);
		goto finish;
	}
	eprog->dtep_neprobes = program->dp_neprobes;
	memcpy(eprog->dtep_eprobes, program->dp_eprobes,
	    program->dp_neprobes * sizeof(dtrace_probedesc_t));

	/*
	 * Get the first stmt.
	 */
	stp = (dt_stmt_t *)dt_list_next(&program->dp_stmts);
	dtrace_stmtdesc_t *stmt;
	dt_elf_stmt_t *p_stmt;
	Elf_Scn *f_scn;
	if (stp == NULL)
		goto skipstmt;
	stmt = (dtrace_stmtdesc_t *)stp->ds_desc;
	/*
	 * Create a section with the first statement.
	 */
	{
		/* Create a section with the first statement. */
		auto first = createElfStatement(stmt, NULL);
		if (first.second)
			return (first.second);
		f_scn = first.first;
	}
	data = elf_getdata(f_scn, NULL);
	if (data == NULL) {
		setErrorMessage("elf_getdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}
	p_stmt = (dt_elf_stmt_t *)data->d_buf;

	/*
	 * Here, we populate the DTrace program with a reference to the ELF
	 * section that contains the first statement and the DOF version
	 * required for this program.
	 */
	eprog->dtep_first_stmt = elf_ndxscn(f_scn);

	/*
	 * Iterate over the other statements and create ELF sections with them.
	 */
	for (stp = (dt_stmt_t *)dt_list_next(stp); stp != NULL;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		auto rval = createElfStatement(stp->ds_desc, p_stmt);
		if (rval.second) {
			return (rval.second);
		}
		scn = rval.first;
		data = elf_getdata(scn, NULL);
		if (data == NULL) {
			setErrorMessage("elf_getdata(%s (%d)): failed: %s",
			    this->filename, this->elfHandle, elf_errmsg(-1));
			return (E_HYPERTRACE_ELFCREATE);
		}
		p_stmt = (dt_elf_stmt_t *)data->d_buf;
	}

	{
		auto options = createElfOptions();
		if (options.second)
			return (options.second);
		scn = options.first;
	}
	/* No explicitly exported options is a valid program. */
	if (scn == NULL)
		goto skipstmt;
	eprog->dtep_options = elf_ndxscn(scn);

	shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_OPTS;
	shdr->sh_flags = SHF_OS_NONCONFORMING;
	shdr->sh_entsize = 0;

skipstmt:
	eprog->dtep_dofversion = program->dp_dofversion;
	eprog->dtep_rflags = program->dp_rflags;
	memcpy(eprog->dtep_ident, program->dp_ident, DT_PROG_IDENTLEN);
	memcpy(eprog->dtep_srcident, program->dp_srcident, DT_PROG_IDENTLEN);
	eprog->dtep_exec = program->dp_exec;
	/*
	 * FIXME: We should make sure that we don't leak host pids here, rather
	 * than just relying on the rest of the code being correct, but for now
	 * it will do.
	 */
	eprog->dtep_pid = program->dp_pid;
finish:
	/*
	 * Make the string table that will hold identifier names.
	 */
	scn = elf_newscn(elfPtr);
	if (scn == NULL) {
		setErrorMessage("elf_newscn(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	data = elf_newdata(scn);
	if (data == NULL) {
		setErrorMessage("elf_newdata(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	data->d_buf = idNameTable;
	data->d_size = idNameOffset;
	data->d_align = 1;
	data->d_version = EV_CURRENT;
	data->d_type = ELF_T_BYTE;
	shdr = elf32_getshdr(scn);
	if (shdr == NULL) {
		setErrorMessage("elf32_getshdr(%s (%d)): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	shdr->sh_type = SHT_STRTAB;
	shdr->sh_name = DTELF_IDNAMETAB;
	shdr->sh_flags = SHF_STRINGS;
	shdr->sh_entsize = DTELF_VARIABLE_SIZE;
	(void) elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	/*
	 * Update everything before writing.
	 */
	if (elf_update(elfPtr, ELF_C_NULL) < 0) {
		setErrorMessage("elf_update(%s (%d), ELF_C_NULL): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	s0hdr->sh_size = ehdr->e_shnum;
	(void) elf_flagshdr(elf_getscn(this->elfPtr, 0), ELF_C_SET, ELF_F_DIRTY);
	ehdr->e_shnum = 0;
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = gelf_fsize(elfPtr, ELF_T_PHDR, 1, EV_CURRENT);
	(void) elf_flagphdr(elfPtr, ELF_C_SET, ELF_F_DIRTY);
	(void) elf_flagehdr(elfPtr, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elfPtr, ELF_C_WRITE) < 0) {
		setErrorMessage("elf_update(%s (%d), ELF_C_WRITE): failed: %s",
		    this->filename, this->elfHandle, elf_errmsg(-1));
		return (E_HYPERTRACE_ELFCREATE);
	}

	(void) elf_end(elfPtr);
	elfPtr = nullptr;
	return (0);
}

Pair<dt_pfargd_t *, int>
HyperTraceELFParser::parseElfPfd(dt_elf_ref_t epfd_ref, int newFD,
    const String &newFilename)
{
	if (epfd_ref == 0)
		return (makeSuccess(nullptr));
	ElfDepthGuard depth(pfdParseDepth);
	if (pfdParseDepth > 128) {
		setErrorMessage("format descriptor chain is cyclic or too deep");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Scn *scn = elf_getscn(elfPtr, epfd_ref);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting fmtdata: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting fmtdata: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *epfd = elfBoundedRecord<dt_elf_pfargd_t>(data);
	if (epfd == NULL ||
	    !elfStringFits(idNameTable, idNameSize, epfd->epfd_prefix) ||
	    epfd->epfd_preflen > strlen(idNameTable + epfd->epfd_prefix) ||
	    memchr(epfd->epfd_fmt, 0, sizeof(epfd->epfd_fmt)) == nullptr) {
		setErrorMessage("invalid format argument record or string");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	/* The printf destructor frees each descriptor, not its prefix pointer. */
	/* Bounded by the identifier table, which is in memory. */
	size_t prefixSize = strlen(idNameTable + epfd->epfd_prefix) + 1;
	auto *pfd = (dt_pfargd_t *)dt_zalloc(dtp, sizeof(dt_pfargd_t) + prefixSize);
	if (pfd == NULL) {
		setErrorMessage("malloc for pfd failed: %s", strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	std::unique_ptr<dt_pfargd_t, decltype(&free)> owner(pfd, free);
	pfd->pfd_prefix = reinterpret_cast<char *>(pfd + 1);
	memcpy(pfd + 1, idNameTable + epfd->epfd_prefix, prefixSize);
	pfd->pfd_preflen = epfd->epfd_preflen;
	memcpy(pfd->pfd_fmt, epfd->epfd_fmt, 8);
	pfd->pfd_flags = epfd->epfd_flags;
	pfd->pfd_width = epfd->epfd_width;
	pfd->pfd_dynwidth = epfd->epfd_dynwidth;
	pfd->pfd_prec = epfd->epfd_prec;
	if (epfd->epfd_conv != 0) {
		size_t offset = (size_t)epfd->epfd_conv - 1;
		if (!elfStringFits(idNameTable, idNameSize, offset) ||
		    idNameTable[offset] == '\0' ||
		    (pfd->pfd_conv = dt_pfdict_lookup(dtp,
		    idNameTable + offset)) == NULL) {
			setErrorMessage("invalid format conversion");
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}
	} else if (pfd->pfd_fmt[0] != '\0') {
		setErrorMessage("missing format conversion");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	auto rval = parseElfPfd(epfd->epfd_next, newFD, newFilename);
	if (rval.second) {
		return (makeError(nullptr, rval.second));
	}
	pfd->pfd_next = rval.first;
	return (makeSuccess(owner.release()));
}

Pair<void *, int>
HyperTraceELFParser::parseFmtData(dt_elf_ref_t fmtdata_ref, int newFD,
    const String &newFilename)
{
	if (fmtdata_ref == 0) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_getscn(this->elfPtr, fmtdata_ref);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting fmtdata: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting fmtdata: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *elfFmtData = elfBoundedRecord<dt_elf_pfargv_t>(data);
	if (elfFmtData == NULL ||
	    !elfStringFits(idNameTable, idNameSize, elfFmtData->epfv_format)) {
		setErrorMessage("%s (%d): ELF fmtdata is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	if (elfFmtData->epfv_argc > 128 ||
	    (elfFmtData->epfv_flags &
	    ~(DT_PRINTF_EXACTLEN | DT_PRINTF_AGGREGATION)) != 0) {
		setErrorMessage("invalid format argument count or flags");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *fmtData = (dt_pfargv_t *)dt_zalloc(dtp, sizeof(dt_pfargv_t));
	if (fmtData == NULL) {
		setErrorMessage("format allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	std::unique_ptr<dt_pfargv_t, decltype(&dt_printf_destroy)>
	    owner(fmtData, dt_printf_destroy);
	fmtData->pfv_dtp = dtp;
	fmtData->pfv_format = strdup(idNameTable + elfFmtData->epfv_format);
	if (fmtData->pfv_format == nullptr) {
		setErrorMessage("format string allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	auto rval15 = parseElfPfd(elfFmtData->epfv_argv, newFD,
	    newFilename);
	if (rval15.second) {
		return (makeError(nullptr, rval15.second));
	}
	fmtData->pfv_argv = rval15.first;
	uint32_t count = 0;
	for (dt_pfargd_t *pfd = fmtData->pfv_argv; pfd != NULL;
	    pfd = pfd->pfd_next)
		++count;
	if (count != elfFmtData->epfv_argc) {
		setErrorMessage("format argument count mismatch");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	fmtData->pfv_argc = elfFmtData->epfv_argc;
	fmtData->pfv_flags = elfFmtData->epfv_flags;
	return (makeSuccess(static_cast<void *>(owner.release())));
}

Pair<void *, int>
HyperTraceELFParser::parseActionIdentifier(dt_elf_ref_t aidref, int newFD,
    const String &newFilename)
{
	if (aidref == 0) {
		return (makeSuccess(nullptr));
	}

	Elf_Scn *scn = elf_getscn(this->elfPtr, aidref);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting action id: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting action id: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *elfActionIdentifier = elfBoundedRecord<dt_elf_ident_t>(data);
	if (elfActionIdentifier == NULL || !elfStringFits(idNameTable, idNameSize, elfActionIdentifier->edi_name)) {
		setErrorMessage("%s (%d): ELF action identifier data is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *aid = (dt_ident_t *)dt_zalloc(dtp, sizeof(dt_ident_t));
	if (aid == NULL) {
		setErrorMessage("action identifier allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	auto destroyIdentifier = [](dt_ident_t *value) {
		free(value->di_name);
		free(value);
	};
	std::unique_ptr<dt_ident_t, decltype(destroyIdentifier)> owner(aid, destroyIdentifier);
	aid->di_name = strdup(idNameTable + elfActionIdentifier->edi_name);
	if (aid->di_name == NULL) {
		setErrorMessage("action identifier name allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	aid->di_id = elfActionIdentifier->edi_id;
	aid->di_kind = elfActionIdentifier->edi_kind;
	aid->di_flags = elfActionIdentifier->edi_flags;
	aid->di_attr = elfActionIdentifier->edi_attr.dtea_attr;
	aid->di_vers = elfActionIdentifier->edi_vers;
	_HYPERTRACE_LOG_ELF(
	    "action identifier %p: {id=%u, kind=%u, flags=%u, version=%u}\n",
	    (void *)aid, aid->di_id, aid->di_kind, aid->di_flags, aid->di_vers);
	auto *record = (dt_elf_ident_owner_t *)dt_zalloc(dtp, sizeof(dt_elf_ident_owner_t));
	if (record == nullptr) {
		setErrorMessage("aggregation identifier owner allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	record->deo_ident = aid;
	dt_list_append(&program->dp_elfidents, record);
	return (makeSuccess(static_cast<void *>(owner.release())));
}

int
HyperTraceELFParser::addStatementToProgram(dtrace_stmtdesc_t *sdp,
    dt_elf_stmt_t *estmt, int newFD, const String &newFilename)
{
	sdp->dtsd_descattr = estmt->dtes_descattr.dtea_attr;
	sdp->dtsd_stmtattr = estmt->dtes_stmtattr.dtea_attr;
	auto result = parseFmtData(estmt->dtes_fmtdata, newFD, newFilename);
	if (result.second != 0) {
		// Error message is set for us.
		return (result.second);
	}
	sdp->dtsd_fmtdata = result.first;
	if (estmt->dtes_strdata != 0) {
		/* createElfStrData(): an identifier table offset plus one. */
		uint64_t off = estmt->dtes_strdata - 1;
		if (!elfStringFits(idNameTable, idNameSize, off)) {
			setErrorMessage("%s (%d): invalid statement string data "
			    "reference %ju", newFilename.c_str(), newFD,
			    (uintmax_t)estmt->dtes_strdata);
			return (E_HYPERTRACE_ELFPARSE);
		}
		size_t len = strlen(idNameTable + off) + 1;
		char *sd = (char *)dt_alloc(dtp, len);
		if (sd == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    newFilename.c_str(), newFD, strerror(errno));
			return (E_HYPERTRACE_SYS);
		}
		memcpy(sd, idNameTable + off, len);
		sdp->dtsd_strdata = sd;
	}
	result = parseActionIdentifier(estmt->dtes_aggdata, newFD, newFilename);
	if (result.second != 0) {
		// Error message is set for us.
		return (result.second);
	}
	sdp->dtsd_aggdata = result.first;
	dt_stmt_t *stp = (dt_stmt_t *)dt_zalloc(dtp, sizeof(dt_stmt_t));
	if (stp == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (E_HYPERTRACE_SYS);
	}

	stp->ds_desc = sdp;
	_HYPERTRACE_LOG_ELF("append statement %p to program statements\n",
	    (void *)stp->ds_desc);
	dt_list_append(&program->dp_stmts, stp);
	return (E_HYPERTRACE_NONE);
}

/*
 * Whether a statement is for this machine (its probe's target matches,
 * dt_resolve()).  Sets *keep and returns 0; a statement for another target
 * is dropped.  When this machine's identity cannot be read
 * (DT_RESOLVE_ERROR), nothing can be decided: the parse fails with the
 * reason rather than dropping statements that may well be ours.
 */
int
HyperTraceELFParser::applyResolverFilter(dtrace_stmtdesc_t *sdp, bool *keep)
{
	*keep = true;
	if (!doResolve)
		return (E_HYPERTRACE_NONE);

	char *target = sdp->dtsd_ecbdesc->dted_probe.dtpd_target;
	_HYPERTRACE_LOG_ELF("resolving against %s\n", target);
	int r = dt_resolve(target, resolverFlags);
	if (r == DT_RESOLVE_ERROR) {
		setErrorMessage("cannot match target %s: this machine's "
		    "identity is unavailable: %s", target, strerror(errno));
		return (E_HYPERTRACE_SYS);
	}
	if (r != 0) {
		_HYPERTRACE_LOG_ELF("failed to resolve, deleting %p\n",
		    (void *)sdp);
		*keep = false;
		return (E_HYPERTRACE_NONE);
	}
	_HYPERTRACE_LOG_ELF("successfully resolved %p\n", (void *)sdp);
	return (E_HYPERTRACE_NONE);
}

Pair<void *, int>
HyperTraceELFParser::parseElfTable(dt_elf_ref_t tabref, int newFD,
    const String &newFilename)
{
	if (tabref == 0)
		return (makeSuccess(nullptr));

	Elf_Scn *scn = elf_getscn(this->elfPtr, tabref);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (data->d_size == 0) {
		return (makeSuccess(nullptr));
	}

	/* parseElfDifo() checked that a non-empty table has data. */
	auto *table = (uint64_t *)dt_alloc(dtp, data->d_size);
	if (table == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	memcpy(table, data->d_buf, data->d_size);
	return (makeSuccess(table));
}

Pair<dtrace_difo_t *, int>
HyperTraceELFParser::parseElfDifo(dt_elf_ref_t diforef, int newFD,
    const String &newFilename)
{
	if (diforef == 0) {
		return (makeSuccess(static_cast<dtrace_difo_t *>(nullptr)));
	}

	Elf_Scn *scn = elf_getscn(this->elfPtr, diforef);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *edifo = elfBoundedRecord<dt_elf_difo_t>(data);
	if (edifo == NULL || !elfArrayFits(data->d_size,
	    offsetof(dt_elf_difo_t, dted_buf), edifo->dted_len, sizeof(dif_instr_t))) {
		setErrorMessage("invalid DIF instruction array");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto tableFits = [&](dt_elf_ref_t ref, uint64_t count, size_t width,
	    bool strings) {
		if (ref == 0)
			return (count == 0);
		Elf_Scn *section = elf_getscn(this->elfPtr, ref);
		Elf_Data *table = section == nullptr ? nullptr : elf_getdata(section, nullptr);
		if (table == nullptr || !elfArrayFits(table->d_size, 0, count, width) ||
		    count * width != table->d_size ||
		    (table->d_size != 0 && table->d_buf == nullptr))
			return (false);
		return (!strings || table->d_size == 0 ||
		    static_cast<const char *>(table->d_buf)[table->d_size - 1] == '\0');
	};
	if (!tableFits(edifo->dted_inttab, edifo->dted_intlen, sizeof(uint64_t), false) ||
	    !tableFits(edifo->dted_vartab, edifo->dted_varlen, sizeof(dtrace_difv_t), false) ||
	    !tableFits(edifo->dted_strtab, edifo->dted_strlen, 1, true) ||
	    !tableFits(edifo->dted_symtab, edifo->dted_symlen, 1, true)) {
		setErrorMessage("DIF table size does not match its declared length");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *difo = (dtrace_difo_t *)dt_zalloc(dtp, sizeof(dtrace_difo_t));
	if (difo == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	auto destroyDifo = [this](dtrace_difo_t *value) {
		dt_difo_free(dtp, value);
	};
	std::unique_ptr<dtrace_difo_t, decltype(destroyDifo)> owner(difo, destroyDifo);

	difo->dtdo_buf = (dif_instr_t *)dt_zalloc(dtp,
	    edifo->dted_len * sizeof(dif_instr_t));
	if (difo->dtdo_buf == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	auto rval16 = parseElfTable(edifo->dted_inttab, newFD,
	    newFilename);
	if (rval16.second) {
		return (makeError(nullptr, rval16.second));
	}
	difo->dtdo_inttab = (uint64_t *)rval16.first;
	auto rval17 = parseElfTable(edifo->dted_strtab, newFD,
	    newFilename);
	if (rval17.second) {
		return (makeError(nullptr, rval17.second));
	}
	difo->dtdo_strtab = (char *)rval17.first;
	auto rval18 = parseElfTable(edifo->dted_vartab, newFD,
	    newFilename);
	if (rval18.second) {
		return (makeError(nullptr, rval18.second));
	}
	difo->dtdo_vartab = (dtrace_difv_t *)rval18.first;
	auto rval19 = parseElfTable(edifo->dted_symtab, newFD,
	    newFilename);
	if (rval19.second) {
		return (makeError(nullptr, rval19.second));
	}
	difo->dtdo_symtab = (char *)rval19.first;
	difo->dtdo_intlen = edifo->dted_intlen;
	difo->dtdo_strlen = edifo->dted_strlen;
	difo->dtdo_varlen = edifo->dted_varlen;
	difo->dtdo_symlen = edifo->dted_symlen;
	difo->dtdo_len = edifo->dted_len;
	difo->dtdo_rtype = edifo->dted_rtype;
	difo->dtdo_destructive = edifo->dted_destructive;
	if ((difo->dtdo_rtype.dtdt_kind != DIF_TYPE_CTF &&
	    difo->dtdo_rtype.dtdt_kind != DIF_TYPE_STRING &&
	    difo->dtdo_rtype.dtdt_kind != DIF_TYPE_NONE &&
	    difo->dtdo_rtype.dtdt_kind != DIF_TYPE_BOTTOM) ||
	    (difo->dtdo_rtype.dtdt_flags & ~DIF_TF_BMASK) != 0 ||
	    difo->dtdo_rtype.dtdt_pad != 0) {
		setErrorMessage("invalid DIF return type");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	for (uint64_t i = 0; i < edifo->dted_len; i++)
		difo->dtdo_buf[i] = edifo->dted_buf[i];
	/* Validate references before the userspace CFG/type passes inspect them. */
	for (uint_t i = 0; i < difo->dtdo_len; i++) {
		dif_instr_t instruction = difo->dtdo_buf[i];
		uint_t op = DIF_INSTR_OP(instruction);
		if (op < DIF_OP_OR || op > DIF_OP_TYPECAST ||
		    (op == DIF_OP_SETX && DIF_INSTR_INTEGER(instruction) >= difo->dtdo_intlen) ||
		    (op == DIF_OP_SETS && !elfStringFits(difo->dtdo_strtab,
		    difo->dtdo_strlen, DIF_INSTR_STRING(instruction))) ||
		    ((op == DIF_OP_USETX || op == DIF_OP_TYPECAST) &&
		    !elfStringFits(difo->dtdo_symtab, difo->dtdo_symlen,
		    DIF_INSTR_SYMBOL(instruction))) ||
		    (op >= DIF_OP_BA && op <= DIF_OP_BLEU &&
		    (DIF_INSTR_LABEL(instruction) <= i ||
		    DIF_INSTR_LABEL(instruction) >= difo->dtdo_len))) {
			setErrorMessage("invalid DIF instruction reference at %u", i);
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}
	}
	for (uint_t i = 0; i < difo->dtdo_varlen; i++) {
		auto &variable = difo->dtdo_vartab[i];
		if (!elfStringFits(difo->dtdo_strtab, difo->dtdo_strlen,
		    variable.dtdv_name) ||
		    memchr(variable.dtdv_object, 0, sizeof(variable.dtdv_object)) == nullptr) {
			setErrorMessage("invalid DIF variable string at %u", i);
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}
		if ((variable.dtdv_type.dtdt_kind != DIF_TYPE_CTF &&
		    variable.dtdv_type.dtdt_kind != DIF_TYPE_STRING &&
		    variable.dtdv_type.dtdt_kind != DIF_TYPE_NONE &&
		    variable.dtdv_type.dtdt_kind != DIF_TYPE_BOTTOM) ||
		    (variable.dtdv_type.dtdt_flags & ~DIF_TF_BMASK) != 0 ||
		    variable.dtdv_type.dtdt_pad != 0) {
			setErrorMessage("invalid DIF variable type at %u", i);
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}
		/* Reconstruct process-local type state locally, never from file bytes. */
		variable.dtdv_sym = nullptr;
		variable.dtdv_ctfp = nullptr;
		variable.dtdv_tf = nullptr;
		variable.dtdv_stack = nullptr;
	}

	_HYPERTRACE_LOG_ELF(
	    "allocated difo %p: {len=%ju, intlen=%ju, strlen=%ju, "
	    "varlen=%ju, symlen=%ju}\n",
	    (void *)difo, (uintmax_t)difo->dtdo_len,
	    (uintmax_t)difo->dtdo_intlen, (uintmax_t)difo->dtdo_strlen,
	    (uintmax_t)difo->dtdo_varlen, (uintmax_t)difo->dtdo_symlen);
	return (makeSuccess(owner.release()));
}

static bool
hypertraceActionKindValid(dtrace_actkind_t kind)
{
	switch (kind) {
	case DTRACEACT_DIFEXPR:
	case DTRACEACT_EXIT:
	case DTRACEACT_PRINTF:
	case DTRACEACT_PRINTA:
	case DTRACEACT_LIBACT:
	case DTRACEACT_TRACEMEM:
	case DTRACEACT_TRACEMEM_DYNSIZE:
	case DTRACEACT_PRINTM:
	case DTRACEACT_PRINTIMMSTACK:
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
	case DTRACEACT_STOP:
	case DTRACEACT_RAISE:
	case DTRACEACT_SYSTEM:
	case DTRACEACT_FREOPEN:
	case DTRACEACT_STACK:
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
	case DTRACEACT_IMMSTACK:
	case DTRACEACT_BREAKPOINT:
	case DTRACEACT_PANIC:
	case DTRACEACT_CHILL:
	case DTRACEACT_SPECULATE:
	case DTRACEACT_COMMIT:
	case DTRACEACT_DISCARD:
	case DTRACEAGG_COUNT:
	case DTRACEAGG_MIN:
	case DTRACEAGG_MAX:
	case DTRACEAGG_AVG:
	case DTRACEAGG_SUM:
	case DTRACEAGG_STDDEV:
	case DTRACEAGG_QUANTIZE:
	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE:
		return (true);
	default:
		return (false);
	}
}

Pair<dt_elf_actdesc_t *, int>
HyperTraceELFParser::allocAction(dtrace_stmtdesc_t *stmtDesc, dt_elf_ref_t ar,
    dt_elf_ref_t owner, int newFD, const String &newFilename)
{
	if (ar == 0)
		return (std::make_pair(nullptr, E_HYPERTRACE_ELFPARSE));

	Elf_Scn *scn = elf_getscn(this->elfPtr, ar);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed getting action: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	elfActionDesc = elfBoundedRecord<dt_elf_actdesc_t>(data);
	if (elfActionDesc == NULL) {
		setErrorMessage("%s (%d): ELF action section data is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	if (!hypertraceActionKindValid(elfActionDesc->dtea_kind) ||
	    elfActionDesc->dtea_ntuple > UINT32_MAX ||
	    (!DTRACEACT_ISAGG(elfActionDesc->dtea_kind) &&
	    elfActionDesc->dtea_ntuple != 0) ||
	    (elfActionDesc->dtea_return != 0 &&
	    elfActionDesc->dtea_return != 1)) {
		setErrorMessage("invalid serialized action fields");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	/* Actions can be shared by later statements. The recorded owner is the
	 * statement that first serialized the action, not necessarily this one.
	 * Serialization follows next links beyond the owner's declared last
	 * action, so require reachability from its first action instead. */
	if (elfActionDesc->dtea_uarg != owner) {
		bool owned = false;
		if (elfActionDesc->dtea_uarg != 0 &&
		    elfActionDesc->dtea_uarg <= UINT32_MAX) {
			dt_elf_ref_t owner_ref =
			    (dt_elf_ref_t)elfActionDesc->dtea_uarg;
			Elf_Scn *owner_scn = elf_getscn(this->elfPtr, owner_ref);
			/* elf_getdata() and elfBoundedRecord() pass NULL on. */
			auto *statement = elfBoundedRecord<dt_elf_stmt_t>(
			    elf_getdata(owner_scn, nullptr));
			if (statement != nullptr &&
			    statement->dtes_self == owner_ref) {
				std::unordered_set<dt_elf_ref_t> visited;
				for (dt_elf_ref_t next = statement->dtes_action;
				    next != 0 && visited.insert(next).second;) {
					if (next == ar) {
						owned = true;
						break;
					}
					Elf_Scn *action_scn =
					    elf_getscn(this->elfPtr, next);
					auto *action =
					    elfBoundedRecord<dt_elf_actdesc_t>(
					    elf_getdata(action_scn, nullptr));
					if (action == nullptr)
						break;
					next = action->dtea_next;
				}
			}
		}
		if (!owned) {
			setErrorMessage("action statement reference mismatch");
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}
	}

	dtrace_actdesc_t *actDesc = dtrace_stmt_action(dtp, stmtDesc);
	if (actDesc == NULL) {
		setErrorMessage("action description allocation failed");
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	auto rval20 = parseElfDifo(elfActionDesc->dtea_difo, newFD,
	    newFilename);
	if (rval20.second) {
		return (makeError(nullptr, rval20.second));
	}
	actDesc->dtad_difo = rval20.first;
	actDesc->dtad_kind = elfActionDesc->dtea_kind;
	actDesc->dtad_ntuple = elfActionDesc->dtea_ntuple;
	actDesc->dtad_arg = elfActionDesc->dtea_arg;
	actDesc->dtad_return = elfActionDesc->dtea_return;
	_HYPERTRACE_LOG_ELF(
	    "allocated action %p: {kind=%u, return=%d, arg=%p, ntuple=%u}\n",
	    (void *)actDesc, actDesc->dtad_kind, actDesc->dtad_return,
	    (void *)actDesc->dtad_arg, actDesc->dtad_ntuple);
	return (makeSuccess(elfActionDesc));
}

int
HyperTraceELFParser::allocActions(dtrace_stmtdesc_t *stmtDesc,
    dt_elf_stmt_t *estmt, int newFD, const String &newFilename)
{
	dt_elf_ref_t ar;
	std::unordered_set<dt_elf_ref_t> visited;
	if (estmt->dtes_action == 0)
		return (0);	/* validated: no actions at all */
	for (ar = estmt->dtes_action; ar != estmt->dtes_action_last;
	     ar = elfActionDesc->dtea_next) {
		if (!visited.insert(ar).second) {
			setErrorMessage("cyclic action chain");
			return (E_HYPERTRACE_ELFPARSE);
		}
		_HYPERTRACE_LOG_ELF("allocating action %u\n", ar);
		auto rv = allocAction(stmtDesc, ar, estmt->dtes_self,
		    newFD, newFilename);
		// rv.first is the pointer, but we don't need it here
		if (rv.second != 0) {
			return (rv.second);
		}
	}

	/* The loop stopped at the last action, which it never visited. */
	visited.insert(ar);
	auto terminal = allocAction(stmtDesc, ar, estmt->dtes_self,
	    newFD, newFilename);
	if (terminal.second != 0)
		return (terminal.second);
	/* A terminal link may lead to the next statement's actions in a shared
	 * ECB, but it cannot point back into this statement's own span. The
	 * verifier uses last->next as an end marker; reject a back-edge before
	 * constructing a program from this untrusted graph. */
	if (visited.find(terminal.first->dtea_next) != visited.end()) {
		setErrorMessage("cyclic action chain");
		return (E_HYPERTRACE_ELFPARSE);
	}
	return (0);
}

Pair<dtrace_ecbdesc_t *, int>
HyperTraceELFParser::parseElfEcbDesc(dt_elf_ref_t ecbref, int newFD,
    const String &newFilename)
{
	Elf_Scn *scn = elf_getscn(this->elfPtr, ecbref);
	if (scn == NULL) {
		setErrorMessage(
		    "elf_getscn(%s (%d)): failed parsing sections: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage(
		    "elf_getdata(%s (%d)): failed parsing sections: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	/* elfBoundedRecord() also rejects a section without data. */
	auto *eecb = elfBoundedRecord<dt_elf_ecbdesc_t>(data);
	if (eecb == nullptr) {
		setErrorMessage("truncated or misaligned ECB description");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	auto ecbKey = Var<dtrace_ecbdesc_t *, dt_elf_ref_t>(
	    static_cast<dt_elf_ref_t>(elf_ndxscn(scn)));
	dtrace_ecbdesc_t *ecb;
	if (!ecbMap.contains(ecbKey)) {
		ecb = (dtrace_ecbdesc_t *)dt_zalloc(dtp,
		    sizeof(dtrace_ecbdesc_t));
		if (ecb == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    newFilename.c_str(), newFD, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}
		_HYPERTRACE_LOG_ELF("ecb cache missed, allocated = %p\n",
		    (void *)ecb);
	} else {
		ecb = Get<dtrace_ecbdesc_t *>(ecbMap[ecbKey]);
		_HYPERTRACE_LOG_ELF("found cached ecb = %p\n", (void *)ecb);
		return (makeSuccess(ecb));
	}

	/* One cache reference, independent of any statement references. */
	dt_ecbdesc_hold(ecb);
	auto releaseECB = [this](dtrace_ecbdesc_t *value) {
		dt_ecbdesc_release(dtp, value);
	};
	std::unique_ptr<dtrace_ecbdesc_t, decltype(releaseECB)> owner(ecb, releaseECB);
	parsedECBs.push_back(ecb);
	owner.release();

	/* Actions are attached to the ECB as statements are allocated. */
	ecb->dted_action = NULL;
	ecb->dted_pred.dtpdd_predicate = NULL;
	auto rval21 = parseElfDifo(eecb->dtee_pred, newFD, newFilename);
	if (rval21.second) {
		return (makeError(nullptr, rval21.second));
	}
	ecb->dted_pred.dtpdd_difo = rval21.first;
	ecb->dted_probe = eecb->dtee_probe.dtep_pdesc;
	ecb->dted_probe.dtpd_target[DTRACE_TARGETNAMELEN - 1] = '\0';
	ecb->dted_probe.dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
	ecb->dted_probe.dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
	ecb->dted_probe.dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
	ecb->dted_probe.dtpd_name[DTRACE_NAMELEN - 1] = '\0';
	ecb->dted_uarg = eecb->dtee_uarg;
	_HYPERTRACE_LOG_ELF(
	    "ecb: {action=%p, spec=%s:%s:%s:%s:%s, predicate=%p}\n",
	    (void *)ecb->dted_action, ecb->dted_probe.dtpd_target,
	    ecb->dted_probe.dtpd_provider, ecb->dted_probe.dtpd_mod,
	    ecb->dted_probe.dtpd_func, ecb->dted_probe.dtpd_name,
	    (void *)ecb->dted_pred.dtpdd_predicate);
	ecbKey = Var<dtrace_ecbdesc_t *, dt_elf_ref_t>(ecbref);
	ecbMap[ecbKey] = ecb;
	_HYPERTRACE_LOG_ELF("cached ecb: [%u] ==> [%p]\n", ecbref, (void *)ecb);
	return (makeSuccess(ecb));
}

Pair<dtrace_stmtdesc_t *, int>
HyperTraceELFParser::allocStatement(dt_elf_stmt_t *estmt, int newFD,
    const String &newFilename)
{
	_HYPERTRACE_LOG_ELF("parse ECB description at %u\n",
	    estmt->dtes_ecbdesc);
	auto rval = parseElfEcbDesc(estmt->dtes_ecbdesc, newFD, newFilename);
	if (rval.second) {
		return (makeError(nullptr, rval.second));
	}
	dtrace_ecbdesc_t *edp = rval.first;
	return (makeSuccess(dtrace_stmt_create(dtp, edp)));
}


int
HyperTraceELFParser::parseStatements(dt_elf_ref_t first_stmt_scn, int newFD,
    const String &newFilename)
{
	dt_elf_stmt_t *estmt;
	std::unordered_map<dt_elf_ref_t, dt_elf_ref_t> successor;
	std::unordered_set<dt_elf_ref_t> seen_ecbs, graph_seen;
	/* A terminal action may continue only at the first action of the next
	 * statement using that ECB. Check the complete serialized graph before
	 * allocating any statement: otherwise a dangling or unrelated tail is
	 * silently discarded when the native action chain is rebuilt. */
	for (dt_elf_ref_t scnref = first_stmt_scn; scnref != 0;) {
		if (!graph_seen.insert(scnref).second) {
			setErrorMessage("cyclic statement chain");
			return (E_HYPERTRACE_ELFPARSE);
		}
		Elf_Scn *scn = elf_getscn(this->elfPtr, scnref);
		auto *stmt = elfBoundedRecord<dt_elf_stmt_t>(
		    elf_getdata(scn, nullptr));
		if (stmt == nullptr) {
			setErrorMessage("ELF statement section data is NULL");
			return (E_HYPERTRACE_ELFPARSE);
		}
		if (stmt->dtes_self != scnref) {
			setErrorMessage("statement self reference mismatch");
			return (E_HYPERTRACE_ELFPARSE);
		}
		/* A clause without actions (e.g. "BEGIN {}") is a statement
		 * with neither a first nor a last action. */
		if (stmt->dtes_ecbdesc == 0 ||
		    (stmt->dtes_action == 0) != (stmt->dtes_action_last == 0)) {
			setErrorMessage("invalid statement action graph");
			return (E_HYPERTRACE_ELFPARSE);
		}
		auto expected = successor.find(stmt->dtes_ecbdesc);
		if (seen_ecbs.find(stmt->dtes_ecbdesc) != seen_ecbs.end() &&
		    (expected == successor.end() ||
		    expected->second != stmt->dtes_action)) {
			setErrorMessage("action successor mismatch");
			return (E_HYPERTRACE_ELFPARSE);
		}
		if (expected != successor.end())
			successor.erase(expected);
		seen_ecbs.insert(stmt->dtes_ecbdesc);
		if (stmt->dtes_action == 0) {
			scnref = stmt->dtes_next;
			continue;
		}
		Elf_Scn *tail_scn = elf_getscn(this->elfPtr,
		    stmt->dtes_action_last);
		auto *tail = elfBoundedRecord<dt_elf_actdesc_t>(
		    elf_getdata(tail_scn, nullptr));
		if (tail == nullptr) {
			setErrorMessage("invalid terminal action reference");
			return (E_HYPERTRACE_ELFPARSE);
		}
		if (tail->dtea_next != 0)
			successor[stmt->dtes_ecbdesc] = tail->dtea_next;
		scnref = stmt->dtes_next;
	}
	if (!successor.empty()) {
		setErrorMessage("dangling action successor");
		return (E_HYPERTRACE_ELFPARSE);
	}
	/* The loop above accepted this chain: acyclic, readable records
	 * whose self references match.  Only libelf can fail here now. */
	for (dt_elf_ref_t scnref = first_stmt_scn; scnref != 0;
	     scnref = estmt->dtes_next) {
		_HYPERTRACE_LOG_ELF("parsing section reference %u\n", scnref);
		estmt = elfBoundedRecord<dt_elf_stmt_t>(elf_getdata(
		    elf_getscn(this->elfPtr, scnref), NULL));
		if (estmt == NULL) {
			setErrorMessage("%s (%d): statement section %u: %s",
			    newFilename.c_str(), newFD, scnref, elf_errmsg(-1));
			return (E_HYPERTRACE_ELFPARSE);
		}

		auto rval = allocStatement(estmt, newFD, newFilename);
		if (rval.second) {
			return (rval.second);
		}
		dtrace_stmtdesc_t *stmtDesc = rval.first;
		if (stmtDesc == NULL) {
			setErrorMessage("statement allocation failed");
			return (E_HYPERTRACE_SYS);
		}

		auto destroyStatement = [this](dtrace_stmtdesc_t *value) {
			dtrace_stmt_destroy(dtp, value);
		};
		std::unique_ptr<dtrace_stmtdesc_t, decltype(destroyStatement)>
		    owner(stmtDesc, destroyStatement);

		_HYPERTRACE_LOG_ELF("allocated statement = %p\n",
		    (void *)stmtDesc);
		bool keep;
		int rerr = applyResolverFilter(stmtDesc, &keep);
		if (rerr != E_HYPERTRACE_NONE)
			return (rerr);
		if (!keep)
			continue;

		int err = allocActions(stmtDesc, estmt, newFD, newFilename);
		if (err) {
			return (err);
		}

		err = addStatementToProgram(stmtDesc, estmt, newFD, newFilename);
		if (err != 0)
			return (err);
		owner.release();
	}

	return (E_HYPERTRACE_NONE);
}

int
HyperTraceELFParser::parseOptions(dt_elf_ref_t elfOptions, int newFD,
    const String &newFilename)
{
	if (elfOptions == 0)
		return (0);

	Elf_Scn *scn;
	Elf_Data *data;
	uintptr_t eop;
	_dt_elf_eopt_t *elfOpt;

	scn = elf_getscn(this->elfPtr, elfOptions);
	if (scn == NULL) {
		setErrorMessage("elf_getscn(%s (%d), %zu): failed: %s",
		    newFilename.c_str(), newFD, kElfProgramSection,
		    elf_errmsg(-1));
		return (E_HYPERTRACE_ELFPARSE);
	}

	if ((data = elf_getdata(scn, NULL)) == NULL) {
		setErrorMessage("elf_getdata(%s (%d), %zu): failed: %s",
		    newFilename.c_str(), newFD, kElfProgramSection,
		    elf_errmsg(-1));
		return (E_HYPERTRACE_ELFPARSE);
	}

	if (data->d_size != 0 && data->d_buf == nullptr) {
		setErrorMessage("missing option section data");
		return (E_HYPERTRACE_ELFPARSE);
	}
	for (size_t offset = 0; offset < data->d_size;) {
		eop = (uintptr_t)data->d_buf + offset;
		if (eop % alignof(_dt_elf_eopt_t) != 0 ||
		    data->d_size - offset < sizeof(_dt_elf_eopt_t)) {
			setErrorMessage("truncated or misaligned option record");
			return (E_HYPERTRACE_ELFPARSE);
		}
		elfOpt = (_dt_elf_eopt_t *)eop;
		if (!elfArrayFits(data->d_size - offset, sizeof(*elfOpt), elfOpt->eo_len, 1) ||
		    memchr(elfOpt->eo_name, 0, sizeof(elfOpt->eo_name)) == nullptr ||
		    (elfOpt->eo_len != 0 && !elfStringFits(elfOpt->eo_arg, elfOpt->eo_len, 0))) {
			setErrorMessage("invalid option name, length or argument");
			return (E_HYPERTRACE_ELFPARSE);
		}
		offset += sizeof(*elfOpt) + elfOpt->eo_len;
		if (elfOpt->eo_name[0] == '\0' || dtp->dt_is_guest == 0 || dtp->dt_active == 1)
			continue;
		int err = dtrace_setopt(dtp, elfOpt->eo_name,
		    elfOpt->eo_len != 0 ? elfOpt->eo_arg : nullptr);
		if (err != 0) {
			setErrorMessage("dtrace_setopt(%s): failed: %s",
			    elfOpt->eo_name, dtrace_errmsg(dtp, err));
			return (E_HYPERTRACE_LIBDTRACE);
		}
	}

	return (0);
}

/*
 * A section name from the section-name table.  elf_strptr() does not ensure
 * that the name is terminated inside the table, so check that here; a
 * malformed table yields NULL instead of a read past its data.
 */
static const char *
elfSectionName(Elf *elf, size_t shstrndx, size_t offset)
{
	Elf_Scn *strscn = elf_getscn(elf, shstrndx);
	Elf_Data *data = elf_getdata(strscn, NULL);	/* NULL scn: NULL */

	if (data == NULL || data->d_buf == NULL || offset >= data->d_size ||
	    memchr((const char *)data->d_buf + offset, '\0',
	    data->d_size - offset) == NULL)
		return (NULL);
	return ((const char *)data->d_buf + offset);
}

/* These descriptors are regular files, or the small daemon reply channel. */
static bool
elfReadExact(int fd, void *buffer, size_t size)
{
	auto *bytes = static_cast<char *>(buffer);
	while (size != 0) {
		ssize_t n = read(fd, bytes, size);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			return (false);
		}
		bytes += n;
		size -= n;
	}
	return (true);
}

static bool
elfWriteExact(int fd, const void *buffer, size_t size)
{
	auto *bytes = static_cast<const char *>(buffer);
	while (size != 0) {
		ssize_t n = write(fd, bytes, size);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			return (false);
		}
		bytes += n;
		size -= n;
	}
	return (true);
}

static inline const String
SHA256ToString(ChecksumArray checksum)
{
	static const char hex[] = "0123456789abcdef";
	String result(SHA256_DIGEST_LENGTH * 2, '0');
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		unsigned char byte = checksum[i];
		result[2 * i] = hex[byte >> 4];
		result[2 * i + 1] = hex[byte & 15];
	}
	return (result);
}

Pair<int, int>
HyperTraceELFParser::verifyChecksum(ChecksumArray checksum, String &newFilename)
{
	char temporaryFile[128] = "/tmp/ddtrace-elf.XXXXXXXX";
	struct stat st;
	if (fstat(elfHandle, &st) != 0) {
		setErrorMessage("fstat(%s (%d)): failed: %s",
		    filename, elfHandle, strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	/* Match the transport's bounded program size before allocating. */
	if (!S_ISREG(st.st_mode) || st.st_size < SHA256_DIGEST_LENGTH + 4 ||
	    st.st_size > 64 * 1024 * 1024) {
		setErrorMessage("%s (%d): invalid checksummed file size", filename,
		    elfHandle);
		return (makeError(-1, E_HYPERTRACE_CHECKSUM));
	}
	Vec<char> buf(st.st_size - SHA256_DIGEST_LENGTH);
	if (!elfReadExact(elfHandle, buf.data(), buf.size())) {
		setErrorMessage("%s (%d): read(%zu) failed: %s",
		    filename, elfHandle, buf.size(), strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	if (buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
		setErrorMessage("%s (%d): not an ELF file", filename, elfHandle);
		return (makeError(-1, E_HYPERTRACE_ELFPARSE));
	}

	ChecksumArray elfChecksum;
	memset(elfChecksum, 0, sizeof(elfChecksum));
	auto *ubuf = (unsigned char *)&buf[0];
	if (SHA256(ubuf, buf.size(), elfChecksum) == NULL) {
		setErrorMessage("%s (%d): SHA256(%zu) failed", filename,
		    elfHandle, buf.size());
		return (makeError(-1, E_HYPERTRACE_CHECKSUM));
	}

	if (memcmp(checksum, elfChecksum, SHA256_DIGEST_LENGTH) != 0) {
		auto checksumString = SHA256ToString(checksum);
		auto elfChecksumString = SHA256ToString(elfChecksum);
		setErrorMessage("%s (%d): SHA256 mismatch: %s != %s",
		    filename, elfHandle, checksumString.c_str(),
		    elfChecksumString.c_str());
		return (makeError(-1, E_HYPERTRACE_CHECKSUM));
	}

	/*
	 * Here we make a new (temporary) file which will contain our ELF
	 * contents that we will run through libelf.
	 */
	int elfFileHandle = mkstemp(temporaryFile);
	if (elfFileHandle == -1) {
		setErrorMessage("%s (%d): mkstemp(%s) failed: %s",
		    filename, elfHandle, temporaryFile,
		    strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	/* Own and unlink immediately: every return and exception cleans up. */
	checksumHandle = elfFileHandle;
	if (unlink(temporaryFile) != 0) {
		setErrorMessage("unlink(%s) failed: %s", temporaryFile, strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	if (!elfWriteExact(elfFileHandle, buf.data(), buf.size())) {
		setErrorMessage("%s (%d): write(%zu) failed: %s", temporaryFile,
		    elfFileHandle, buf.size(), strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	newFilename = String(temporaryFile);
	return (makeSuccess(elfFileHandle));
}

bool
HyperTraceELFParser::findIdentifierInCompileIdentifiers(
    ProgramIdentifier identToFind, bool &empty)
{
	auto *ident_entry = (dt_identlist_t *)dt_list_next(
	    &dtp->dt_compile_idents);
	empty = true;
	while (ident_entry) {
		empty = false;
		auto *ident = ident_entry->dtil_ident;
		if (memcmp(ident, identToFind, DT_PROG_IDENTLEN) == 0) {
			return (true);
		}
		ident_entry = (dt_identlist_t *)dt_list_next(ident_entry);
	}
	return (false);
}

Pair<dtrace_prog_t *, int>
HyperTraceELFParser::toProgram(dtrace_prog_t *oldpgp)
{
	GElf_Shdr shdr;
	GElf_Ehdr ehdr;
	char buf[5] = { 0 };
	char msg[] = "DEL ident";

	if (fstat(this->elfHandle, &this->elfFileStat) != 0) {
		setErrorMessage("fstat(%d): failed: %s", this->elfHandle,
		    strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	off_t off = lseek(this->elfHandle, 0, SEEK_SET);
	if (off == -1) {
		setErrorMessage("lseek(%d, 0 SEEK_SET): failed: %s",
		    this->elfHandle, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (!elfReadExact(this->elfHandle, buf, 4)) {
		setErrorMessage("read(%s (%d), %zu): failed: %s",
		    this->filename, this->elfHandle, 4, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	off = 0;
	buf[4] = '\0';

	int newFD = this->elfHandle;
	String newFilename = this->filename;
	if (buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
		_HYPERTRACE_LOG_ELF("detected presence of checksum\n");
		off = lseek(this->elfHandle, 0, SEEK_SET);
		if (off == -1) {
			setErrorMessage("lseek(%d, 0, SEEK_SET): failed: %s",
			    this->elfHandle, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_CHECKSUM));
		}

		ChecksumArray expectedChecksum;
		if (!elfReadExact(this->elfHandle, expectedChecksum,
		    SHA256_DIGEST_LENGTH)) {
			setErrorMessage("read(%s (%d), %zu): failed: %s",
			    this->filename, this->elfHandle,
			    SHA256_DIGEST_LENGTH, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_CHECKSUM));
		}

		off = lseek(this->elfHandle, SHA256_DIGEST_LENGTH, SEEK_SET);
		if (off == -1) {
			setErrorMessage("lseek(%d, %zu, SEEK_SET): failed: %s",
			    this->elfHandle, SHA256_DIGEST_LENGTH,
			    strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_CHECKSUM));
		}

		auto rval = verifyChecksum(expectedChecksum, newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		_HYPERTRACE_LOG_ELF("checksum successfully verified\n");
		newFD = rval.first;
	}

	off = lseek(newFD, 0, SEEK_SET);
	if (off == -1) {
		setErrorMessage("lseek(%d, 0, SEEK_SET): failed: %s", newFD,
		    strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		setErrorMessage("elf_version(EV_CURRENT) is EV_NONE: %s",
		    elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	elfPtr = elf_begin(newFD, ELF_C_READ, NULL);
	if (elfPtr == NULL) {
		setErrorMessage(
		    "elf_begin(%s (%d), ELF_C_READ, NULL): failed: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (elf_kind(elfPtr) != ELF_K_ELF) {
		setErrorMessage(
		    "elf_kind(%s (%d)) is %d (expected=ELF_K_ELF (%d))",
		    newFilename.c_str(), newFD, elf_kind(elfPtr), ELF_K_ELF);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (gelf_getehdr(elfPtr, &ehdr) == NULL) {
		setErrorMessage("gelf_getehdr(%s (%d)): failed: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	int elfClass = gelf_getclass(elfPtr);
	_HYPERTRACE_LOG_ELF("identified elfClass = %d\n", elfClass);
	if (elfClass != ELFCLASS32 && elfClass != ELFCLASS64) {
		setErrorMessage(
		    "gelf_getclass(%s (%d)): expected class 32 or 64, got %d",
		    newFilename.c_str(), newFD, elfClass);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	size_t shstrndx = 0, shnum = 0;
	if (elf_getshdrstrndx(elfPtr, &shstrndx) != 0) {
		setErrorMessage("elf_getshdrstrndx(%s (%d)): failed: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	_HYPERTRACE_LOG_ELF("found string table at index %zu\n", shstrndx);
	int rval = elf_getshdrnum(elfPtr, &shnum);
	if (rval != 0) {
		fprintf(stderr, "shnum = %zu, rval = %d\n", shnum, rval);
		setErrorMessage("elf_getshdrnum(%s (%d)): failed: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	/*
	 * Parse in the identifier name string table.
	 */
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elfPtr, scn)) != NULL) {
		static const char idTable[] = ".dtrace_stmt_idname_table";
		static const String sIdTable = String(idTable);
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			setErrorMessage("gelf_getshdr(%s (%d), %s): failed: %s",
			    newFilename.c_str(), newFD, idTable, elf_errmsg(-1));
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}

		const char *name = elfSectionName(elfPtr, shstrndx,
		    shdr.sh_name);
		if (name == NULL) {
			setErrorMessage("elf_strptr(%s (%d), %s): failed: %s",
			    newFilename.c_str(), newFD, idTable, elf_errmsg(-1));
			return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
		}

		auto sName = String(name);
		if (sName == sIdTable) {
			Elf_Data *data = elf_getdata(scn, NULL);
			if (data == NULL) {
				setErrorMessage(
				    "elf_getdata(%s (%d), %s): failed: %s",
				    newFilename.c_str(), newFD, idTable,
				    elf_errmsg(-1));
				return (makeError(nullptr,
				    E_HYPERTRACE_ELFPARSE));
			}

			/*
			 * We fill in the global state. We don't actually need
			 * to copy it over as we're only going to use it while
			 * parsing ELF, not afterwards.
			 */
			this->idNameTable = (char *)data->d_buf;
			this->idNameSize = data->d_size;
			_HYPERTRACE_LOG_ELF("found section %s, size = %zu\n",
			    name, this->idNameSize);
			break;
		}
	}

	/*
	 * Get the program description.
	 */
	scn = elf_getscn(elfPtr, kElfProgramSection);
	if (scn == NULL) {
		setErrorMessage("elf_getscn(%s (%d), %zu): failed: %s",
		    newFilename.c_str(), newFD, kElfProgramSection,
		    elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	if (gelf_getshdr(scn, &shdr) != &shdr) {
		setErrorMessage("elf_getshdr(%s (%d), %zu): failed: %s",
		    newFilename.c_str(), newFD, kElfProgramSection,
		    elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	const char *name = elfSectionName(elfPtr, shstrndx, shdr.sh_name);
	if (name == NULL) {
		setErrorMessage("elf_strptr(%s (%d), %zu): failed: %s",
		    newFilename.c_str(), newFD, kElfProgramSection,
		    elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto sName = String(name);
	if (sName != ".dtrace_prog") {
		setErrorMessage("expected section .dtrace_prog, got: %s", name);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		setErrorMessage("elf_getdata(%s (%d)): failed: %s",
		    newFilename.c_str(), newFD, elf_errmsg(-1));
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	/* elfBoundedRecord() also rejects a section without data. */
	_HYPERTRACE_LOG_ELF("found section %s\n", name);
	auto *eprog = elfBoundedRecord<dt_elf_prog_t>(data);
	if (eprog == nullptr || !elfArrayFits(data->d_size,
	    offsetof(dt_elf_prog_t, dtep_eprobes), eprog->dtep_neprobes,
	    sizeof(dtrace_probedesc_t)) ||
	    memchr(eprog->dtep_err, 0, sizeof(eprog->dtep_err)) == nullptr) {
		setErrorMessage("invalid program record, probe array or error string");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	/*
	 * We allow two kinds of programs:
	 *  (1) the program itself where the relocations were applied;
	 *  (2) a program that was created by this program as a source.
	 */
	if (oldpgp && !identsAreEqual(eprog->dtep_ident, oldpgp->dp_ident) &&
	    !identsAreEqual(eprog->dtep_srcident, oldpgp->dp_ident)) {
		static char msg[] = "FAIL FAIL";
		memcpy(g_saved_srcident, eprog->dtep_srcident,
		    DT_PROG_IDENTLEN);
		_HYPERTRACE_LOG_ELF(
		    "identifier mismatch (first three bytes): \n"
		    "\t%hhx %hhx %hhx != %hhx %hhx %hhx ||\n"
		    "\t%hhx %hhx %hhx != %hhx %hhx %hhx\n",
		    eprog->dtep_ident[0], eprog->dtep_ident[1],
		    eprog->dtep_ident[2], oldpgp->dp_ident[0],
		    oldpgp->dp_ident[1], oldpgp->dp_ident[2],
		    eprog->dtep_srcident[0], eprog->dtep_srcident[1],
		    eprog->dtep_srcident[2], oldpgp->dp_ident[0],
		    oldpgp->dp_ident[1], oldpgp->dp_ident[2]);
		if (dtp->dt_failmsg_needed)
			write(STDOUT_FILENO, msg, sizeof(msg));
		return (makeError(nullptr, E_HYPERTRACE_AGAIN));
	}

	if (eprog->dtep_haserror) {
		_HYPERTRACE_LOG_ELF("the program has an error set\n");
		setErrorMessage("%s", eprog->dtep_err);
		return (makeError(nullptr, E_HYPERTRACE_PROPAGATED));
	}

	bool empty;
	bool found = findIdentifierInCompileIdentifiers(eprog->dtep_srcident,
	    empty);
	if (!found && !empty) {
		static char msg[] = "FAIL FAIL";
		if (dtp->dt_failmsg_needed)
			write(STDOUT_FILENO, msg, sizeof(msg));
		return (makeError(nullptr, E_HYPERTRACE_IDENT_NOTFOUND));
	}

	_HYPERTRACE_LOG_ELF("found program identifier\n");
	this->resolverFlags = eprog->dtep_rflags;
	this->program = dt_program_create(dtp);
	if (this->program == NULL) {
		setErrorMessage("%s (%d): failed to create program: %s",
		    newFilename.c_str(), newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_LIBDTRACE));
	}

	auto destroyProgram = [this](dtrace_prog_t *value) {
		dt_program_destroy(dtp, value);
	};
	std::unique_ptr<dtrace_prog_t, decltype(destroyProgram)>
	    programOwner(program, destroyProgram);

	this->program->dp_dofversion = eprog->dtep_dofversion;
	_HYPERTRACE_LOG_ELF("program DOF version: %u\n",
	    program->dp_dofversion);
	_HYPERTRACE_LOG_ELF("begin parsing statements\n");
	int err = parseStatements(eprog->dtep_first_stmt, newFD, newFilename);
	if (err != 0)
		return (makeError(nullptr, err));
	_HYPERTRACE_LOG_ELF("finish parsing statements\n");
	if (dt_list_next(&program->dp_stmts) == NULL) {
		setErrorMessage("%s (%d): has no statements",
		    newFilename.c_str(), newFD);
		elf_end(this->elfPtr);
		this->elfPtr = nullptr;
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	_HYPERTRACE_LOG_ELF("begin parsing options\n");
	err = parseOptions(eprog->dtep_options, newFD, newFilename);
	_HYPERTRACE_LOG_ELF("finish parsing options\n");
	if (err) {
		// setErrorMessage will be called in the function itself.
		elf_end(this->elfPtr);
		this->elfPtr = nullptr;
		return (makeError(nullptr, err));
	}

	memcpy(program->dp_ident, eprog->dtep_ident, DT_PROG_IDENTLEN);
	memcpy(program->dp_srcident, eprog->dtep_srcident, DT_PROG_IDENTLEN);
	program->dp_rflags = eprog->dtep_rflags;
	program->dp_exec = eprog->dtep_exec;
	program->dp_pid = eprog->dtep_pid;
	program->dp_neprobes = eprog->dtep_neprobes;
	if (program->dp_neprobes) {
		auto size = program->dp_neprobes * sizeof(dtrace_probedesc_t);
		program->dp_eprobes = (dtrace_probedesc_t *)dt_alloc(dtp, size);
		if (program->dp_eprobes == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    newFilename.c_str(), newFD, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}
		memcpy(program->dp_eprobes, eprog->dtep_eprobes, size);
	}
	_HYPERTRACE_LOG_ELF("program %p: {exec=%d, pid=%d, neprobes=%u}\n",
	    (void *)program, program->dp_exec, program->dp_pid,
	    program->dp_neprobes);

	elf_end(this->elfPtr);
	this->elfPtr = nullptr;
	/* Acknowledge only after the complete program has been accepted. */
	if (found && (!elfWriteExact(STDOUT_FILENO, msg, sizeof(msg)) ||
	    !elfWriteExact(STDOUT_FILENO, program->dp_srcident, DT_PROG_IDENTLEN))) {
		setErrorMessage("program identifier acknowledgement failed: %s",
		    strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	return (makeSuccess(programOwner.release()));
}
} // namespace dtrace

// C interface
extern "C" dtrace_prog_t *
dtrace_elf_parse(dtrace_hdl_t *dtp, int fd, const char *filename, int rslv,
    int *err, hypertrace_errmsg_t errmsg, dtrace_prog_t *oldpgp)
try {
	using namespace dtrace;
	// Noteworthy arguments:
	//   - program = nullptr    The program gets allocated in toProgram().
	//   - resolver flags == 0  Use defaults.
	HyperTraceELFParser elfParser(dtp, nullptr, fd, filename, rslv != 0, 0);
	auto rval = elfParser.toProgram(oldpgp);
	const String &errorMessage = elfParser.getErrorMessage();
	strlcpy(errmsg, errorMessage.c_str(), HYPERTRACE_ERRMSGLEN);
	*err = rval.second;
	return (rval.first);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	*err = E_HYPERTRACE_SYS;
	strlcpy(errmsg, "ELF parser allocation failed", HYPERTRACE_ERRMSGLEN);
	return (nullptr);
}

extern "C" int
dtrace_elf_create(dtrace_hdl_t *dtp, dtrace_prog_t *prog, int endian, int fd,
    const char *filename, hypertrace_errmsg_t errmsg)
try {
	using namespace dtrace;
	// Don't resolve in the case of creating ELF files. We shouldn't ever
	// need to use it.
	HyperTraceELFParser elfParser(dtp, prog, fd, filename, false, 0);
	int rval = elfParser.createElf(endian);
	const String &errorMessage = elfParser.getErrorMessage();
	strlcpy(errmsg, errorMessage.c_str(), HYPERTRACE_ERRMSGLEN);
	return (rval);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	strlcpy(errmsg, "ELF writer allocation failed", HYPERTRACE_ERRMSGLEN);
	return (E_HYPERTRACE_SYS);
}

extern "C" char *
dtrace_get_srcident(char *buf)
{

	memcpy(buf, g_saved_srcident, DT_PROG_IDENTLEN);
	return (buf);
}
