#include <dt_elf.hh>
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
}

void
HyperTraceELFParser::setErrorMessage(const char *fmt, ...)
{
	va_list va, va_cp;
	va_start(va, fmt);
	va_copy(va_cp, va);
	auto len = vsnprintf(nullptr, 0, fmt, va);
	if (len < 0)
		abort();
	if (len > 0) {
		errorMessage.resize(len);
		vsnprintf(&errorMessage[0], len + 1, fmt, va_cp);
	}
	va_end(va_cp);
	va_end(va);
}

Pair<size_t, int>
HyperTraceELFParser::createElfString(const char *name)
{
	size_t offset, len, osize;
	int needs_realloc;
	char *otab;

	len = strlen(name) + 1;
	offset = idNameOffset;

	/*
	 * This makes no sense, so hard fail on it.
	 */
	if (offset > idNameSize) {
		setErrorMessage("%s (%d): offset > idNameSize [%zu > %zu]",
		    this->filename, this->elfHandle, offset, idNameSize);
		return (makeError(0ull, E_HYPERTRACE_ELFCREATE));
	}

	/*
	 * Save the old size in case we need to realloc;
	 */
	osize = idNameSize;

	/*
	 * If we are at the boundary, we have to reallocate the identifier
	 * name string table in order to add a new entry. We first make sure
	 * that the size of the table is large enough to accommodate the new
	 * string we are putting in it. Thus, we increase the size of the
	 * table over and over (shifting it to the left by 1) until we satisfy
	 * the condition where the current offset (the next entry to be added)
	 * added to the length of the string we want to add is less than the
	 * size of the table.
	 */
	while ((offset + len) >= idNameSize) {
		/*
		 * Save the flag that we need to actually realloc the table.
		 */
		needs_realloc = 1;

		/*
		 * XXX: Need a better way to check this...
		 */
		if ((idNameSize << 1) <= idNameSize) {
			setErrorMessage(
			    "idname string table at max size: %zu",
			    idNameSize);
			return (makeError(0ull, E_HYPERTRACE_ELFCREATE));
		}

		/*
		 * Increase the size of the identifier name string table by
		 * shifting it left by 1
		 */
		idNameSize <<= 1;
	}

	if (needs_realloc) {
		otab = idNameTable;
		idNameTable = (char *)dt_alloc(dtp, idNameSize);
		if (otab) {
			memcpy(idNameTable, otab, osize);
			dt_free(dtp, otab);
		}
	}

	// Add the new string to the table and bump the offset.
	memcpy(idNameTable + offset, name, len);
	idNameTable[offset + len - 1] = '\0';
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

	auto *inttab = (uint64_t *)dt_alloc(dtp,
	    sizeof(uint64_t) * difo->dtdo_intlen);
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

	auto *strtab = (char *)dt_alloc(dtp, difo->dtdo_strlen);
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

	auto *symtab = (char *)dt_alloc(dtp, difo->dtdo_symlen);
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

	auto *vartab = (dtrace_difv_t *)dt_alloc(dtp,
	    sizeof(dtrace_difv_t) * difo->dtdo_varlen);
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
	auto *edifo = (dt_elf_difo_t *)dt_zalloc(dtp,
	    sizeof(dt_elf_difo_t) + (difo->dtdo_len * sizeof(dif_instr_t)));
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
	{
		auto rval = createElfIntTab(difo);
		if (rval.second) {
			return makeError(nullptr, rval.second);
		}
		edifo->dted_inttab = elf_ndxscn(rval.first);
	}
	{
		auto rval = createElfStrTab(difo);
		if (rval.second) {
			return makeError(nullptr, rval.second);
		}
		edifo->dted_strtab = elf_ndxscn(rval.first);
	}
	{
		auto rval = createElfSymTab(difo);
		if (rval.second) {
			return makeError(nullptr, rval.second);
		}
		edifo->dted_symtab = elf_ndxscn(rval.first);
	}
	{
		auto rval = createElfVarTab(difo);
		if (rval.second) {
			return makeError(nullptr, rval.second);
		}
		edifo->dted_vartab = elf_ndxscn(rval.first);
	}
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

	dt_elf_ecbdesc_t *eecb = (dt_elf_ecbdesc_t *)dt_zalloc(dtp,
	    sizeof(dt_elf_ecbdesc_t));
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
	{
		auto rval = createElfDifo(ecb->dted_pred.dtpdd_difo);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		eecb->dtee_pred = elf_ndxscn(rval.first);
	}
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

	dt_elf_actdesc_t *eact = (dt_elf_actdesc_t *)dt_zalloc(dtp,
	    sizeof(dt_elf_actdesc_t));
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
		setErrorMessage("%s (%d): action last is NULL, but first is not");
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

		if (data->d_buf == NULL) {
			setErrorMessage("%s %d: data buffer is NULL",
			    this->filename, this->elfHandle);
			return (E_HYPERTRACE_ELFCREATE);
		}

		if (ad->dtad_elfact == NULL && previousActDesc != NULL)
			previousActDesc->dtea_next = elf_ndxscn(scn);

		ad->dtad_elfact = data->d_buf;
		previousActDesc = (dt_elf_actdesc_t *)ad->dtad_elfact;

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

Pair<dt_elf_ref_t, int>
HyperTraceELFParser::createElfStrData([[maybe_unused]] void *strdata)
{

	return (makeSuccess(0));
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

	auto *epfd = (dt_elf_pfargd_t *)dt_zalloc(dtp, sizeof(dt_elf_pfargd_t));
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
	/* TODO: this has to do with type conversion (%s, %d, ...) */
	epfd->epfd_conv = 0;
	{
		auto rval = createElfPfd(pfd->pfd_next);
		if (rval.second) {
			return (makeError(0, rval.second));
		}
		epfd->epfd_next = rval.first;
	}
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

	auto *epfv = (dt_elf_pfargv_t *)dt_zalloc(dtp, sizeof(dt_elf_pfargv_t));
	if (epfv == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", this->filename,
		    this->elfHandle, strerror(errno));
		return (makeError(0, E_HYPERTRACE_SYS));
	}

	/*
	 * Fill out our fields
	 */
	{
		auto rval = createElfString(pfv->pfv_format);
		if (rval.second) {
			return (makeError(0, rval.second));
		}
		epfv->epfv_format = rval.first;
	}
	{
		auto rval = createElfPfd(pfv->pfv_argv);
		if (rval.second) {
			return (makeError(0, rval.second));
		}
		epfv->epfv_argv = rval.first;
	}
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

	auto *estmt = (dt_elf_stmt_t *)dt_zalloc(dtp, sizeof(dt_elf_stmt_t));
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
	createElfActions(stmt, elf_ndxscn(scn));
	{
		auto rval = createElfEcbDesc(stmt);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		estmt->dtes_ecbdesc = elf_ndxscn(rval.first);
	}

	/*
	 * Fill in the first and last action for a statement that we've
	 * previously saved when creating actions.
	 */
	estmt->dtes_action = firstActionSection;
	estmt->dtes_action_last = lastActionSection;
	estmt->dtes_descattr.dtea_attr = stmt->dtsd_descattr;
	estmt->dtes_stmtattr.dtea_attr = stmt->dtsd_stmtattr;
	estmt->dtes_aggdata = 0;
	{
		auto rval = createElfFmtData(stmt->dtsd_fmtdata);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		estmt->dtes_fmtdata = rval.first;
	}
	{
		auto rval = createElfStrData(stmt->dtsd_strdata);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		estmt->dtes_strdata = rval.first;
	}
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
		auto *eaid = (dt_elf_ident_t *)dt_zalloc(dtp,
		    sizeof(dt_elf_ident_t));
		if (eaid == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    this->filename, this->elfHandle, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}
		{
			auto rval = createElfString(aid->di_name);
			if (rval.second) {
				return (makeError(nullptr, rval.second));
			}
			eaid->edi_name = rval.first;
		}
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
		(void) elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
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
	size_t buflen = 0; /* Current buffer length */
	size_t bufmaxlen = 0; /* Maximum buffer length */
	size_t l;
	unsigned char *buf = NULL, *obuf = NULL;
	bool needs_realloc = false;

	/*
	 * Go over the compile-time options and fill them in.
	 *
	 * XXX: This may not be necessary for ctopts.
	 */
	for (auto *op = dtelf_ctopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		size_t arglen;
		if (op->dteo_arg != NULL) {
			arglen = strlen(op->dteo_arg) + 1;
			arglen = (arglen + 7) & (-8);
		} else
			arglen = 0;

		size_t len = sizeof(_dt_elf_eopt_t) + arglen;
		auto *eop = (_dt_elf_eopt_t *)dt_zalloc(dtp, len);
		if (eop == NULL) {
			setErrorMessage("%s (%d): allocation failed: %s",
			    this->filename, this->elfHandle, strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}
		l = strlcpy(eop->eo_name, op->dteo_name, sizeof(eop->eo_name));
		if (l >= sizeof(eop->eo_name)) {
			setErrorMessage("%s (%d): %s is too long to be copied",
			    this->filename, this->elfHandle, op->dteo_name);
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}

		eop->eo_len = arglen;

		if (op->dteo_arg != NULL) {
			l = strlcpy(eop->eo_arg, op->dteo_arg, eop->eo_len);
			if (l >= eop->eo_len) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		}

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0) {
			l = strlcpy((char *)eop->eo_option,
			    (char *)op->dteo_option, sizeof(eop->eo_option));
			if (l >= sizeof(eop->eo_option)) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		} else
			eop->eo_option = op->dteo_option;

		/*
		 * Have we run out of space in our buffer?
		 */
		while (buflen + len >= bufmaxlen) {
			if (bufmaxlen == 0)
				bufmaxlen = 1;

			needs_realloc = true;
			/*
			 * Check for overflow. Not great, but will have to do.
			 */
			if ((bufmaxlen << 1) <= bufmaxlen) {
				setErrorMessage("%s (%d): bufmaxlen overflow",
				    this->filename, this->elfHandle);
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			bufmaxlen <<= 1;
		}

		if (buf == NULL || needs_realloc) {
			/*
			 * Save the old buffer.
			 */
			obuf = buf;
			buf = (unsigned char *)dt_alloc(dtp, bufmaxlen);
			if (buf == NULL) {
				setErrorMessage(
				    "%s (%d): allocation failed: %s",
				    this->filename, this->elfHandle,
				    strerror(errno));
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
			needs_realloc = false;
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	/*
	 * Go over runtime options. If they are set, we add them to our data
	 * buffer which will be in the section that contains all of the options.
	 */
	for (auto *op = dtelf_rtopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		size_t arglen;
		if (op->dteo_arg != NULL) {
			arglen = strlen(op->dteo_arg) + 1;
			arglen = (arglen + 7) & (-8);
		} else
			arglen = 0;

		size_t len = sizeof(_dt_elf_eopt_t) + arglen;
		auto *eop = (_dt_elf_eopt_t *)malloc(len);
		if (eop == NULL) {
			setErrorMessage("malloc for eop failed: %s",
			    strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}

		auto l = strlcpy(eop->eo_name, op->dteo_name, sizeof(eop->eo_name));
		if (l >= sizeof(eop->eo_name)) {
			setErrorMessage("%s is too long to be copied",
			    op->dteo_arg);
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}

		eop->eo_len = arglen;

		if (op->dteo_arg != NULL) {
			l = strlcpy(eop->eo_arg, op->dteo_arg, eop->eo_len);
			if (l >= eop->eo_len) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (
				    makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		}

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0) {
			l = strlcpy((char *)eop->eo_option,
			    (char *)op->dteo_option, sizeof(eop->eo_option));
			if (l >= sizeof(eop->eo_option)) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (
				    makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		} else
			eop->eo_option = op->dteo_option;

		/*
		 * Have we run out of space in our buffer?
		 */
		while (buflen + len >= bufmaxlen) {
			if (bufmaxlen == 0)
				bufmaxlen = 1;

			needs_realloc = true;
			/*
			 * Check for overflow. Not great, but will have to do.
			 */
			if ((bufmaxlen << 1) <= bufmaxlen) {
				setErrorMessage("%s (%d): bufmaxlen overflow",
				    this->filename, this->elfHandle);
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			bufmaxlen <<= 1;
		}

		if (buf == NULL || needs_realloc) {
			/*
			 * Save the old buffer.
			 */
			obuf = buf;
			buf = (unsigned char *)dt_alloc(dtp, bufmaxlen);
			if (buf == NULL) {
				setErrorMessage(
				    "%s (%d): allocation failed: %s",
				    this->filename, this->elfHandle,
				    strerror(errno));
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
			needs_realloc = false;
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	/*
	 * Go over dynamic runtime options. If they are set, we add them to our data
	 * buffer which will be in the section that contains all of the options.
	 */
	for (auto *op = dtelf_drtopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		size_t arglen;
		if (op->dteo_arg != NULL) {
			arglen = strlen(op->dteo_arg) + 1;
			arglen = (arglen + 7) & (-8);
		} else
			arglen = 0;

		size_t len = sizeof(_dt_elf_eopt_t) + arglen;
		auto *eop = (_dt_elf_eopt_t *)malloc(len);
		if (eop == NULL) {
			setErrorMessage("malloc for eop failed: %s",
			    strerror(errno));
			return (makeError(nullptr, E_HYPERTRACE_SYS));
		}

		auto l = strlcpy(eop->eo_name, op->dteo_name,
		    sizeof(eop->eo_name));
		if (l >= sizeof(eop->eo_name)) {
			setErrorMessage("%s is too long to be copied",
			    op->dteo_arg);
			return (makeError(nullptr, E_HYPERTRACE_ELFCREATE));
		}


		eop->eo_len = arglen;

		if (op->dteo_arg != NULL) {
			l = strlcpy(eop->eo_arg, op->dteo_arg, eop->eo_len);
			if (l >= eop->eo_len) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (
				    makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		}

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0) {
			l = strlcpy((char *)eop->eo_option,
			    (char *)op->dteo_option, sizeof(eop->eo_option));
			if (l >= sizeof(eop->eo_option)) {
				setErrorMessage("%s is too long to be copied",
				    op->dteo_arg);
				return (
				    makeError(nullptr, E_HYPERTRACE_ELFCREATE));
			}
		} else
			eop->eo_option = op->dteo_option;

		/*
		 * Have we run out of space in our buffer?
		 */
		while (buflen + len >= bufmaxlen) {
			if (bufmaxlen == 0)
				bufmaxlen = 1;

			needs_realloc = true;
			/*
			 * Check for overflow. Not great, but will have to do.
			 */
			if ((bufmaxlen << 1) <= bufmaxlen) {
				setErrorMessage("%s (%d): bufmaxlen overflow",
				    this->filename, this->elfHandle);
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			bufmaxlen <<= 1;
		}

		if (buf == NULL || needs_realloc) {
			/*
			 * Save the old buffer.
			 */
			obuf = buf;
			buf = (unsigned char *)dt_alloc(dtp, bufmaxlen);
			if (buf == NULL) {
				setErrorMessage(
				    "%s (%d): allocation failed: %s",
				    this->filename, this->elfHandle,
				    strerror(errno));
				return (makeError(nullptr, E_HYPERTRACE_SYS));
			}
			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
			needs_realloc = false;
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	if (buflen == 0)
		return (makeSuccess(NULL));

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
	data->d_buf = buf;
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
	auto *eprog = (dt_elf_prog *)dt_zalloc(dtp, progsize);
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
	{
		/*
		 * Create a section with the first statement.
		 */
		auto rval = createElfStatement(stmt, NULL);
		if (rval.second)
			return (rval.second);
		f_scn = rval.first;
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
		auto rval = createElfOptions();
		if (rval.second) {
			return (rval.second);
		}
		scn = rval.first;
	}
	if (scn == NULL)
		return (E_HYPERTRACE_ELFCREATE);

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
	/*
	 * Save the options for this program.
	 */
	eprog->dtep_options = elf_ndxscn(scn);
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
	if (data == NULL) {
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
	return (0);
}

Pair<dt_pfargd_t *, int>
HyperTraceELFParser::parseElfPfd(dt_elf_ref_t epfd_ref, int newFD,
    const String &newFilename)
{
	if (epfd_ref == 0)
		return (makeSuccess(nullptr));

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

	auto *epfd = (dt_elf_pfargd_t *)data->d_buf;
	if (epfd == NULL) {
		setErrorMessage("%s (%d): epfd is NULL");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *pfd = (dt_pfargd_t *)dt_zalloc(dtp, sizeof(dt_pfargd_t));
	if (pfd == NULL) {
		setErrorMessage("malloc for pfd failed: %s", strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}
	pfd->pfd_prefix = strdup(idNameTable + epfd->epfd_prefix);
	pfd->pfd_preflen = epfd->epfd_preflen;
	memcpy(pfd->pfd_fmt, epfd->epfd_fmt, 8);
	pfd->pfd_flags = epfd->epfd_flags;
	pfd->pfd_width = epfd->epfd_width;
	pfd->pfd_dynwidth = epfd->epfd_dynwidth;
	pfd->pfd_prec = epfd->epfd_prec;
	pfd->pfd_conv = NULL;
	auto rval = parseElfPfd(epfd->epfd_next, newFD, newFilename);
	if (rval.second) {
		return (makeError(nullptr, rval.second));
	}
	pfd->pfd_next = rval.first;
	return (makeSuccess(pfd));
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

	auto *elfFmtData = (dt_elf_pfargv_t *)data->d_buf;
	if (elfFmtData == NULL) {
		setErrorMessage("%s (%d): ELF fmtdata is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *fmtData = (dt_pfargv_t *)dt_zalloc(dtp, sizeof(dt_pfargv_t));
	if (fmtData == NULL)
		abort();
	fmtData->pfv_dtp = dtp;
	fmtData->pfv_format = strdup(idNameTable + elfFmtData->epfv_format);
	{
		auto rval = parseElfPfd(elfFmtData->epfv_argv, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		fmtData->pfv_argv = rval.first;
	}
	fmtData->pfv_argc = elfFmtData->epfv_argc;
	fmtData->pfv_flags = elfFmtData->epfv_flags;
	return (makeSuccess(fmtData));
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

	auto *elfActionIdentifier = (dt_elf_ident_t *)data->d_buf;
	if (elfActionIdentifier == NULL) {
		setErrorMessage("%s (%d): ELF action identifier data is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *aid = (dt_ident_t *)dt_alloc(dtp, sizeof(dt_ident_t));
	if (aid == NULL)
		abort();

	aid->di_name = strdup(idNameTable + elfActionIdentifier->edi_name);
	if (aid->di_name == NULL)
		abort();
	aid->di_id = elfActionIdentifier->edi_id;
	aid->di_kind = elfActionIdentifier->edi_kind;
	aid->di_flags = elfActionIdentifier->edi_flags;
	aid->di_attr = elfActionIdentifier->edi_attr.dtea_attr;
	aid->di_vers = elfActionIdentifier->edi_vers;
	_HYPERTRACE_LOG_ELF(
	    "action identifier %p: {id=%u, kind=%u, flags=%u, version=%u}\n",
	    (void *)aid, aid->di_id, aid->di_kind, aid->di_flags, aid->di_vers);
	return (makeSuccess(aid));
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

void
HyperTraceELFParser::freeECB(dtrace_ecbdesc_t *ecb)
{
	if (ecb == NULL)
		return;

	if (ecb->dted_pred.dtpdd_difo != NULL)
		dt_free(dtp, ecb->dted_pred.dtpdd_difo);
	dt_free(dtp, ecb);
}

dtrace_stmtdesc_t *
HyperTraceELFParser::applyResolverFilter(dtrace_stmtdesc_t *sdp,
    dt_elf_stmt_t *estmt)
{
	if (!doResolve)
		return (sdp);

	char *target = sdp->dtsd_ecbdesc->dted_probe.dtpd_target;
	_HYPERTRACE_LOG_ELF("resolving against %s\n", target);
	if (dt_resolve(target, resolverFlags) != 0) {
		_HYPERTRACE_LOG_ELF("failed to resolve, deleting %p\n",
		    (void *)sdp);
		auto ecbKey = Var<dtrace_ecbdesc_t *, dt_elf_ref_t>(
		    estmt->dtes_ecbdesc);
		auto it = ecbMap.find(ecbKey);
		ecbMap.erase(it);
		freeECB(sdp->dtsd_ecbdesc);
		dt_free(dtp, sdp);
		return (nullptr);
	}
	_HYPERTRACE_LOG_ELF("successfully resolved %p\n", (void *)sdp);
	return (sdp);
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

	assert(data->d_buf != NULL);
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
		return (makeSuccess(NULL));
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

	auto *edifo = (dt_elf_difo_t *)data->d_buf;
	if (edifo == NULL) {
		setErrorMessage("%s (%d): edifo is NULL");
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *difo = (dtrace_difo_t *)dt_zalloc(dtp, sizeof(dtrace_difo_t));
	if (difo == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	difo->dtdo_buf = (dif_instr_t *)dt_zalloc(dtp,
	    edifo->dted_len * sizeof(dif_instr_t));
	if (difo->dtdo_buf == NULL) {
		setErrorMessage("%s (%d): allocation failed: %s", newFilename.c_str(),
		    newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_SYS));
	}

	{
		auto rval = parseElfTable(edifo->dted_inttab, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		difo->dtdo_inttab = (uint64_t *)rval.first;
	}
	{
		auto rval = parseElfTable(edifo->dted_strtab, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		difo->dtdo_strtab = (char *)rval.first;
	}
	{
		auto rval = parseElfTable(edifo->dted_vartab, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		difo->dtdo_vartab = (dtrace_difv_t *)rval.first;
	}
	{
		auto rval = parseElfTable(edifo->dted_symtab, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		difo->dtdo_symtab = (char *)rval.first;
	}
	difo->dtdo_intlen = edifo->dted_intlen;
	difo->dtdo_strlen = edifo->dted_strlen;
	difo->dtdo_varlen = edifo->dted_varlen;
	difo->dtdo_symlen = edifo->dted_symlen;
	difo->dtdo_len = edifo->dted_len;
	difo->dtdo_rtype = edifo->dted_rtype;
	difo->dtdo_destructive = edifo->dted_destructive;
	for (uint64_t i = 0; i < edifo->dted_len; i++)
		difo->dtdo_buf[i] = edifo->dted_buf[i];
	_HYPERTRACE_LOG_ELF(
	    "allocated difo %p: {len=%ju, intlen=%ju, strlen=%ju, "
	    "varlen=%ju, symlen=%ju}\n",
	    (void *)difo, (uintmax_t)difo->dtdo_len,
	    (uintmax_t)difo->dtdo_intlen, (uintmax_t)difo->dtdo_strlen,
	    (uintmax_t)difo->dtdo_varlen, (uintmax_t)difo->dtdo_symlen);
	return (makeSuccess(difo));
}

Pair<dt_elf_actdesc_t *, int>
HyperTraceELFParser::allocAction(dtrace_stmtdesc_t *stmtDesc, dt_elf_ref_t ar,
    int newFD, const String &newFilename)
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

	elfActionDesc = (dt_elf_actdesc_t *)data->d_buf;
	if (elfActionDesc == NULL) {
		setErrorMessage("%s (%d): ELF action section data is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	dtrace_actdesc_t *actDesc = dtrace_stmt_action(dtp, stmtDesc);
	if (actDesc == NULL)
		abort();

	{
		auto rval = parseElfDifo(elfActionDesc->dtea_difo, newFD,
		    newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		actDesc->dtad_difo = rval.first;
	}
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
	for (ar = estmt->dtes_action; ar != estmt->dtes_action_last;
	     ar = elfActionDesc->dtea_next) {
		_HYPERTRACE_LOG_ELF("allocating action %u\n", ar);
		auto rv = allocAction(stmtDesc, ar, newFD, newFilename);
		// rv.first is the pointer, but we don't need it here
		if (rv.second != 0) {
			return (rv.second);
		}
	}

	return (allocAction(stmtDesc, ar, newFD, newFilename).second);
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
	if (data->d_buf == NULL) {
		setErrorMessage("%s (%d): d_buf is NULL", newFilename.c_str(),
		    newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	auto *eecb = (dt_elf_ecbdesc_t *)data->d_buf;
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

	auto actionKey = Var<dtrace_actdesc_t *, dt_elf_ref_t>(
	    eecb->dtee_action);
	if (actionMap.contains(actionKey)) {
		ecb->dted_action = Get<dtrace_actdesc_t *>(
		    actionMap[actionKey]);
	} else {
		ecb->dted_action = NULL;
	}
	ecb->dted_pred.dtpdd_predicate = NULL;
	{
		auto rval = parseElfDifo(eecb->dtee_pred, newFD, newFilename);
		if (rval.second) {
			return (makeError(nullptr, rval.second));
		}
		ecb->dted_pred.dtpdd_difo = rval.first;
	}
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
	if (estmt == NULL) {
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}
	_HYPERTRACE_LOG_ELF("parse ECB description at %u\n",
	    estmt->dtes_ecbdesc);
	auto rval = parseElfEcbDesc(estmt->dtes_ecbdesc, newFD, newFilename);
	if (rval.second) {
		return (makeError(nullptr, rval.second));
	}
	dtrace_ecbdesc_t *edp = rval.first;
	dt_ecbdesc_hold(edp);
	return (makeSuccess(dtrace_stmt_create(dtp, edp)));
}


int
HyperTraceELFParser::parseStatements(dt_elf_ref_t first_stmt_scn, int newFD,
    const String &newFilename)
{
	dt_elf_stmt_t *estmt;
	for (dt_elf_ref_t scnref = first_stmt_scn; scnref != 0;
	     scnref = estmt->dtes_next) {
		_HYPERTRACE_LOG_ELF("parsing section reference %u\n", scnref);
		Elf_Scn *scn = elf_getscn(this->elfPtr, scnref);
		if (scn == NULL) {
			setErrorMessage(
			    "elf_getscn(%s (%d)): failed parsing sections: %s",
			    newFilename.c_str(), newFD, elf_errmsg(-1));
			return (E_HYPERTRACE_ELFPARSE);
		}

		Elf_Data *data = elf_getdata(scn, NULL);
		if (data == NULL) {
			setErrorMessage(
			    "elf_getdata(%s (%d)): failed parsing sections: %s",
			    newFilename.c_str(), newFD, elf_errmsg(-1));
			return (E_HYPERTRACE_ELFPARSE);
		}

		estmt = (dt_elf_stmt_t *)data->d_buf;
		if (estmt == NULL) {
			setErrorMessage(
			    "%s (%d): ELF statement section data is NULL",
			    newFilename.c_str(), newFD);
			return (E_HYPERTRACE_ELFPARSE);
		}

		auto rval = allocStatement(estmt, newFD, newFilename);
		if (rval.second) {
			return (rval.second);
		}
		dtrace_stmtdesc_t *stmtDesc = rval.first;
		if (stmtDesc == NULL)
			abort();

		_HYPERTRACE_LOG_ELF("allocated statement = %p\n",
		    (void *)stmtDesc);
		stmtDesc = applyResolverFilter(stmtDesc, estmt);
		if (stmtDesc == NULL)
			continue;

		int err = allocActions(stmtDesc, estmt, newFD, newFilename);
		if (err) {
			return (err);
		}

		addStatementToProgram(stmtDesc, estmt, newFD, newFilename);
	}

	return (E_HYPERTRACE_NONE);
}

int
HyperTraceELFParser::parseOptions(dt_elf_ref_t elfOptions, int newFD,
    const String &newFilename)
{
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

	for (eop = (uintptr_t)data->d_buf;
	     eop < ((uintptr_t)data->d_buf) + data->d_size;
	     eop = eop + elfOpt->eo_len + sizeof(_dt_elf_eopt_t)) {
		// Make sure we are 8-byte aligned here
		assert((eop & 7) == 0);
		elfOpt = (_dt_elf_eopt_t *)eop;
		assert(elfOpt != NULL);

		if (elfOpt->eo_name[0] == '\0')
			continue;

		if (dtp->dt_is_guest == 0)
			continue;

		if (dtp->dt_active == 1)
			continue;

		// Set the options only if we are a guest, if the option has
		// a name and if we're not actively tracing.
		char *arg = elfOpt->eo_len > 0 ? strdup(elfOpt->eo_arg) : NULL;
		int err = dtrace_setopt(dtp, elfOpt->eo_name, arg);
		if (err != 0) {
			setErrorMessage("dtrace_setopt(%s): failed: %s",
			    elfOpt->eo_name, dtrace_errmsg(dtp, err));
			return (E_HYPERTRACE_LIBDTRACE);
		}
	}

	return (0);
}

static inline const String
SHA256ToString(ChecksumArray checksum)
{
	String checksumString;
	checksumString.resize(512);
	for (auto i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		char c = checksum[i];
		sprintf(&checksumString[0], "%02x", c);
	}
	return (checksumString);
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
	if (st.st_size == 0) {
		setErrorMessage("%s (%d): file size is 0", filename,
		    elfHandle);
		return (makeError(-1, E_HYPERTRACE_CHECKSUM));
	}
	Vec<char> buf(st.st_size - SHA256_DIGEST_LENGTH);
	if (read(elfHandle, &buf[0], buf.size()) < 0) {
		setErrorMessage("%s (%d): read(%zu) failed: %s",
		    filename, elfHandle, buf.size(), strerror(errno));
		return (makeError(-1, E_HYPERTRACE_SYS));
	}
	if (buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
		setErrorMessage("%s (%d): not an ELF file");
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
	if (write(elfFileHandle, &buf[0], buf.size()) < 0) {
		setErrorMessage("%s (%d): write(%zu) failed: %s", temporaryFile,
		    elfFileHandle, buf.size(), strerror(errno));
		close(elfFileHandle);
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

	if (read(this->elfHandle, buf, 4) < 0) {
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
		if (read(this->elfHandle, expectedChecksum,
		    SHA256_DIGEST_LENGTH) < 0) {
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
		assert(newFD != -1);
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
		    newFilename.c_str(), newFD, ELF_K_ELF);
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

		char *name = elf_strptr(elfPtr, shstrndx, shdr.sh_name);
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

	char *name = elf_strptr(elfPtr, shstrndx, shdr.sh_name);
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

	if (data->d_buf == NULL) {
		setErrorMessage("%s (%d): data buffer is NULL",
		    newFilename.c_str(), newFD);
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	_HYPERTRACE_LOG_ELF("found section %s\n", name);
	auto *eprog = (dt_elf_prog_t *)data->d_buf;
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

	/*
	 * Write the srcident to stdout. This is necessary for dtraced to get
	 * the information it needs. This should only ever happen when dtraced
	 * calls us -- command line users have no reason to pass '-N'.
	 */
	if (found) {
		write(STDOUT_FILENO, msg, sizeof(msg));
		write(STDOUT_FILENO, eprog->dtep_srcident, DT_PROG_IDENTLEN);
		fsync(STDOUT_FILENO);
	}
	_HYPERTRACE_LOG_ELF("found program identifier\n");
	this->resolverFlags = eprog->dtep_rflags;
	this->program = dt_program_create(dtp);
	if (this->program == NULL) {
		setErrorMessage("%s (%d): failed to create program: %s",
		    newFilename.c_str(), newFD, strerror(errno));
		return (makeError(nullptr, E_HYPERTRACE_LIBDTRACE));
	}

	this->program->dp_dofversion = eprog->dtep_dofversion;
	_HYPERTRACE_LOG_ELF("program DOF version: %u\n",
	    program->dp_dofversion);
	_HYPERTRACE_LOG_ELF("begin parsing statements\n");
	parseStatements(eprog->dtep_first_stmt, newFD, newFilename);
	_HYPERTRACE_LOG_ELF("finish parsing statements\n");
	if (dt_list_next(&program->dp_stmts) == NULL) {
		setErrorMessage("%s (%d): has no statements",
		    newFilename.c_str(), newFD);
		// NOTE: We don't free the program here because it will be
		// handled in dtrace_close(), as we've created it with
		// dt_program_create().
		elf_end(this->elfPtr);
		if (this->elfHandle != newFD) {
			// Don't unlink the file because we want to be able to
			// analyze it since it caused an error.
			close(newFD);
		}
		return (makeError(nullptr, E_HYPERTRACE_ELFPARSE));
	}

	_HYPERTRACE_LOG_ELF("begin parsing options\n");
	int err = parseOptions(eprog->dtep_options, newFD, newFilename);
	_HYPERTRACE_LOG_ELF("finish parsing options\n");
	if (err) {
		// setErrorMessage will be called in the function itself.
		elf_end(this->elfPtr);
		if (this->elfHandle != newFD) {
			// Don't unlink the file because we want to be able to
			// analyze it since it caused an error.
			close(newFD);
		}
		return (makeError(nullptr, err));
	}

	memcpy(program->dp_ident, eprog->dtep_ident, DT_PROG_IDENTLEN);
	memcpy(program->dp_srcident, eprog->dtep_srcident, DT_PROG_IDENTLEN);
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
		assert(program->dp_eprobes != NULL);
		memcpy(program->dp_eprobes, eprog->dtep_eprobes, size);
	}
	_HYPERTRACE_LOG_ELF("program %p: {exec=%d, pid=%d, neprobes=%u}\n",
	    (void *)program, program->dp_exec, program->dp_pid,
	    program->dp_neprobes);

	elf_end(this->elfPtr);
	if (this->elfHandle != newFD) {
		if (errorMessage != "") {
			unlink(newFilename.c_str());
		}
		close(newFD);
	}
	return (makeSuccess(program));
}
} // namespace dtrace

// C interface
extern "C" dtrace_prog_t *
dtrace_elf_parse(dtrace_hdl_t *dtp, int fd, const char *filename, int rslv,
    int *err, hypertrace_errmsg_t errmsg, dtrace_prog_t *oldpgp)
{
	using namespace dtrace;
	// Noteworthy arguments:
	//   - program = nullptr    The program gets allocated in toProgram().
	//   - resolver flags == 0  Use defaults.
	HyperTraceELFParser elfParser(dtp, nullptr, fd, filename, rslv != 0, 0);
	auto rval = elfParser.toProgram(oldpgp);
	const String &errorMessage = elfParser.getErrorMessage();
	assert(errorMessage.size() < HYPERTRACE_ERRMSGLEN);
	strcpy(errmsg, errorMessage.c_str());
	*err = rval.second;
	return (rval.first);
}

extern "C" int
dtrace_elf_create(dtrace_hdl_t *dtp, dtrace_prog_t *prog, int endian, int fd,
    const char *filename, hypertrace_errmsg_t errmsg)
{
	using namespace dtrace;
	// Don't resolve in the case of creating ELF files. We shouldn't ever
	// need to use it.
	HyperTraceELFParser elfParser(dtp, prog, fd, filename, false, 0);
	int rval = elfParser.createElf(endian);
	const String &errorMessage = elfParser.getErrorMessage();
	assert(errorMessage.size() < HYPERTRACE_ERRMSGLEN);
	strcpy(errmsg, errorMessage.c_str());
	return (rval);
}

extern "C" char *
dtrace_get_srcident(char *buf)
{

	memcpy(buf, g_saved_srcident, DT_PROG_IDENTLEN);
	return (buf);
}

