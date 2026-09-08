/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * Register the Bluetooth specification-traceability gates as ATF cases so they
 * run with the suite.
 *
 * Before this file the traceability audit, the generated-oracle freshness
 * check, and the case manifest audit ran only from hand-invoked
 * "make spec-traceability" targets.  None of them was a Kyua case, so a
 * hand-edited oracle constant, a silently dropped requirement row, or a
 * stale generated header left the entire suite green.  Every case here is
 * therefore a gate, not a report.
 *
 * The official SIG documents are local review inputs and are not redistributed
 * with the source tree.  Each case that needs one skips cleanly when it is
 * absent, so builders without the specifications still get a green,
 * honestly-labelled run instead of a spurious failure.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	SPEC_EXIT_MISSING_INPUT	66	/* EX_NOINPUT, used by the scripts */

/*
 * Coverage floors.  These are the numbers the checked-in generated catalogue
 * currently reports.  They are deliberately equality-free lower bounds: adding
 * tests may only raise COVERED, and deleting requirement rows or weakening an
 * oracle lowers it, which fails here rather than passing silently.
 *
 * Update them in the same change that legitimately moves coverage, and say why
 * in the commit message.
 */
#define	SPEC_CONF_MIN_REQUIREMENTS	2200
#define	SPEC_CONF_MIN_COVERED		800

static const char *
spec_dir(const atf_tc_t *tc)
{

	return (atf_tc_get_config_var(tc, "srcdir"));
}

static char *
spec_path(const atf_tc_t *tc, const char *name)
{
	char *p;

	ATF_REQUIRE(asprintf(&p, "%s/%s", spec_dir(tc), name) > 0);
	return (p);
}

static bool
spec_exists(const atf_tc_t *tc, const char *name)
{
	char *p = spec_path(tc, name);
	struct stat sb;
	bool ok;

	ok = (stat(p, &sb) == 0);
	free(p);
	return (ok);
}

/*
 * Locate the SIG source documents.  They live outside the test directory in a
 * source checkout and are absent from an installed tests package.
 */
static bool
spec_sources_present(const atf_tc_t *tc)
{
	char *core, *assigned;
	struct stat sb;
	bool ok;

	ATF_REQUIRE(asprintf(&core,
	    "%s/../../../../bluetooth-specs/Core_Specification_6_3.txt",
	    spec_dir(tc)) > 0);
	ATF_REQUIRE(asprintf(&assigned,
	    "%s/../../../../bluetooth-specs/Assigned_Numbers.html",
	    spec_dir(tc)) > 0);
	ok = (stat(core, &sb) == 0 && stat(assigned, &sb) == 0);
	free(core);
	free(assigned);
	return (ok);
}

/*
 * Run a helper script from the test directory.  Returns its exit status, or
 * -1 if it could not be executed at all.
 */
static int
spec_run(const atf_tc_t *tc, const char *script, const char *args)
{
	char *cmd, *path;
	int status;

	path = spec_path(tc, script);
	ATF_REQUIRE(asprintf(&cmd, "%s %s", path, args == NULL ? "" : args) >
	    0);
	status = system(cmd);
	free(path);
	free(cmd);
	if (status == -1 || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static bool
have_kyua(void)
{

	return (system("kyua --version >/dev/null 2>&1") == 0);
}

/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(requirements_matrix_wellformed);
ATF_TC_BODY(requirements_matrix_wellformed, tc)
{
	char *path, *line = NULL;
	size_t cap = 0;
	ssize_t len;
	FILE *fp;
	unsigned long rows = 0, normative = 0, implementation = 0, mixed = 0;
	unsigned long countable = 0, absent_source = 0;

	if (!spec_exists(tc, "spec_conf_requirements_proposed.tsv"))
		atf_tc_skip("classified requirement matrix not installed");
	path = spec_path(tc, "spec_conf_requirements_proposed.tsv");
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));

	while ((len = getline(&line, &cap, fp)) > 0) {
		char *f[8], *p = line, *tok;
		int nf = 0;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		while (nf < 8 && (tok = strsep(&p, "\t")) != NULL)
			f[nf++] = tok;
		if (nf > 0 && strcmp(f[0], "requirement_id") == 0)
			continue;

		ATF_REQUIRE_MSG(nf == 7,
		    "row %lu has %d fields, expected 7", rows + 1, nf);
		rows++;

		/* Column 5: authority. */
		if (strcmp(f[4], "normative") == 0)
			normative++;
		else if (strcmp(f[4], "implementation") == 0)
			implementation++;
		else if (strcmp(f[4], "mixed") == 0)
			mixed++;
		else
			atf_tc_fail("%s: invalid authority '%s'", f[0], f[4]);

		/* Column 6: oracle class. */
		ATF_REQUIRE_MSG(strcmp(f[5], "external") == 0 ||
		    strcmp(f[5], "internal") == 0 ||
		    strcmp(f[5], "mixed") == 0,
		    "%s: invalid oracle_class '%s'", f[0], f[5]);

		/* Column 7: is the cited document in the tree? */
		ATF_REQUIRE_MSG(strcmp(f[6], "in-tree") == 0 ||
		    strcmp(f[6], "n/a") == 0 ||
		    strncmp(f[6], "absent:", 7) == 0,
		    "%s: invalid spec_source '%s'", f[0], f[6]);
		if (strncmp(f[6], "absent:", 7) == 0)
			absent_source++;

		/*
		 * An implementation contract must never claim an in-tree
		 * specification source: that is exactly the mislabelling this
		 * classification exists to prevent.
		 */
		if (strcmp(f[4], "implementation") == 0)
			ATF_REQUIRE_MSG(strcmp(f[6], "n/a") == 0,
			    "%s is an implementation contract but claims "
			    "spec_source '%s'", f[0], f[6]);

		/*
		 * A normative row must carry a narrow locator, the same rule
		 * spec_traceability_audit.sh enforces.
		 */
		if (strcmp(f[4], "normative") == 0 ||
		    strcmp(f[4], "mixed") == 0)
			ATF_REQUIRE_MSG(strstr(f[1], "§") != NULL ||
			    strstr(f[1], "Appendix") != NULL ||
			    strstr(f[1], "Table") != NULL ||
			    strstr(f[1], "Figure") != NULL,
			    "%s: normative row lacks a narrow locator", f[0]);

		/* Column 3 must name at least one Kyua selector. */
		ATF_REQUIRE_MSG(f[2][0] != '\0',
		    "%s: no Kyua selector", f[0]);

		if (strcmp(f[4], "normative") == 0 &&
		    strcmp(f[5], "external") == 0 &&
		    strcmp(f[6], "in-tree") == 0)
			countable++;
	}
	free(line);
	fclose(fp);
	free(path);

	ATF_REQUIRE_MSG(rows > 0, "classified matrix is empty");
	printf("rows=%lu normative=%lu mixed=%lu implementation=%lu\n",
	    rows, normative, mixed, implementation);
	printf("countable-as-conformance=%lu rows-citing-absent-documents=%lu\n",
	    countable, absent_source);

	/*
	 * Guard the honest headline: the number of rows that are simultaneously
	 * normative, externally oracled, and backed by a document in the tree.
	 * Relabelling a row to hide a gap now fails here.
	 */
	ATF_REQUIRE_MSG(countable >= 120,
	    "conformance-countable rows fell to %lu", countable);
}

ATF_TC_WITHOUT_HEAD(generated_requirements_catalogue_fresh);
ATF_TC_BODY(generated_requirements_catalogue_fresh, tc)
{
	int rc;

	if (!spec_exists(tc, "spec_conf_generate.sh"))
		atf_tc_skip("spec_conf_generate.sh not installed");
	if (!spec_sources_present(tc))
		atf_tc_skip("local SIG source documents absent; "
		    "generated requirement catalogue cannot be rechecked");

	rc = spec_run(tc, "spec_conf_generate.sh", "--check");
	if (rc == SPEC_EXIT_MISSING_INPUT)
		atf_tc_skip("generator reported missing inputs");
	ATF_REQUIRE_MSG(rc == 0,
	    "spec_conf_generate.sh --check failed (%d): the extracted "
	    "requirement catalogue, its coverage classification, or the "
	    "ranked gap list is stale", rc);
}

ATF_TC_WITHOUT_HEAD(generated_profile_catalogue_fresh);
ATF_TC_BODY(generated_profile_catalogue_fresh, tc)
{
	int rc;

	if (!spec_exists(tc, "spec_conf_generate_profile.sh"))
		atf_tc_skip("spec_conf_generate_profile.sh not installed");

	/*
	 * The profile generator reports its own missing inputs with
	 * SPEC_EXIT_MISSING_INPUT, so the Core-source probe used by
	 * generated_requirements_catalogue_fresh is not needed here.
	 */
	rc = spec_run(tc, "spec_conf_generate_profile.sh", "--check");
	if (rc == SPEC_EXIT_MISSING_INPUT)
		atf_tc_skip("generator reported missing inputs");
	ATF_REQUIRE_MSG(rc == 0,
	    "spec_conf_generate_profile.sh --check failed (%d): the extracted "
	    "Mesh Protocol, Mesh Model, Core Specification Supplement, HOGP or "
	    "HID Service catalogue, its coverage classification, or the ranked "
	    "gap list is stale", rc);
}

ATF_TC_WITHOUT_HEAD(generated_oracles_fresh);
ATF_TC_BODY(generated_oracles_fresh, tc)
{
	char *args;
	int rc;

	if (!spec_exists(tc, "check_generated_oracles.sh"))
		atf_tc_skip("check_generated_oracles.sh not installed");
	if (!spec_sources_present(tc))
		atf_tc_skip("local SIG source documents absent; "
		    "generated oracle headers cannot be rechecked");

	ATF_REQUIRE(asprintf(&args,
	    "%s/../../../../bluetooth-specs/Core_Specification_6_3.txt "
	    "%s/../../../../bluetooth-specs/Assigned_Numbers.html",
	    spec_dir(tc), spec_dir(tc)) > 0);
	rc = spec_run(tc, "check_generated_oracles.sh", args);
	free(args);
	ATF_REQUIRE_MSG(rc == 0,
	    "generated oracle headers do not match the specification text "
	    "(%d): an oracle constant was hand-edited or the header is stale",
	    rc);
}

/*
 * True when "gen" is a Core version later than the generation this stack
 * targets.  The target is duplicated from spec_conf_generate.sh on purpose:
 * if one moves without the other, the counts stop agreeing and
 * generation_map_accounts_for_every_requirement fails loudly.
 */
#define	SPEC_CONF_TARGET_MAJOR	5
#define	SPEC_CONF_TARGET_MINOR	2

static bool
spec_generation_after_target(const char *gen)
{
	unsigned major = 0, minor = 0;

	if (sscanf(gen, "%u.%u", &major, &minor) != 2)
		return (false);
	if (major != SPEC_CONF_TARGET_MAJOR)
		return (major > SPEC_CONF_TARGET_MAJOR);
	return (minor > SPEC_CONF_TARGET_MINOR);
}

ATF_TC_WITHOUT_HEAD(coverage_floor_not_regressed);
ATF_TC_BODY(coverage_floor_not_regressed, tc)
{
	char *path, *line = NULL;
	size_t cap = 0;
	ssize_t len;
	FILE *fp;
	unsigned long total = 0, covered = 0, uncovered = 0, na = 0;

	if (!spec_exists(tc, "spec_conf_coverage_generated.tsv"))
		atf_tc_skip("generated coverage classification not installed");
	path = spec_path(tc, "spec_conf_coverage_generated.tsv");
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));

	while ((len = getline(&line, &cap, fp)) > 0) {
		char *f[8], *p = line, *tok;
		int nf = 0;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		while (nf < 8 && (tok = strsep(&p, "\t")) != NULL)
			f[nf++] = tok;
		if (nf < 4 || strcmp(f[0], "requirement_id") == 0)
			continue;
		total++;
		if (strcmp(f[3], "COVERED") == 0)
			covered++;
		else if (strcmp(f[3], "UNCOVERED") == 0)
			uncovered++;
		else if (strcmp(f[3], "NOT-APPLICABLE") == 0)
			na++;
		else
			atf_tc_fail("%s: invalid status '%s'", f[0], f[3]);
	}
	free(line);
	fclose(fp);
	free(path);

	printf("normative requirements=%lu covered=%lu uncovered=%lu "
	    "not-applicable=%lu\n", total, covered, uncovered, na);

	ATF_REQUIRE_MSG(total >= SPEC_CONF_MIN_REQUIREMENTS,
	    "extracted requirement count fell to %lu (floor %d): requirements "
	    "were dropped from the catalogue", total, SPEC_CONF_MIN_REQUIREMENTS);
	ATF_REQUIRE_MSG(covered >= SPEC_CONF_MIN_COVERED,
	    "section-level covered requirements fell to %lu (floor %d)",
	    covered, SPEC_CONF_MIN_COVERED);
	ATF_REQUIRE_MSG(covered + uncovered + na == total,
	    "coverage classification does not partition the catalogue");
}

/*
 * The generation map must account for every extracted requirement, and every
 * scope exclusion it drives must be visible as a reason in the coverage file.
 *
 * This is the gate on the claim that nothing was silently dropped when the
 * catalogue was scoped from "all of Core 6.3" down to "the generation this
 * stack targets".  It checks the two directions separately:
 *
 *   forward   every requirement classified NOT-APPLICABLE for generation
 *             reasons names a generation in its reason text;
 *   backward  every requirement the map attributes to a post-target
 *             generation is NOT-APPLICABLE, so an exclusion cannot be
 *             attributed and then quietly not applied.
 *
 * The UNKNOWN count is printed rather than bounded.  It is the honest measure
 * of how much of Core the map cannot attribute, and it is expected to be
 * large: most baseline L2CAP/ATT/GATT/SMP text names no feature at all.
 */
ATF_TC_WITHOUT_HEAD(generation_map_accounts_for_every_requirement);
ATF_TC_BODY(generation_map_accounts_for_every_requirement, tc)
{
	char *path, *line = NULL;
	size_t cap = 0;
	ssize_t len;
	FILE *fp;
	unsigned long rows = 0, unknown = 0, post_target = 0, extras = 0;
	unsigned long na_generation = 0, matched = 0;

	if (!spec_exists(tc, "spec_conf_generation_generated.tsv"))
		atf_tc_skip("generated generation map not installed");
	if (!spec_exists(tc, "spec_conf_coverage_generated.tsv"))
		atf_tc_skip("generated coverage classification not installed");

	/*
	 * Pass 1: the map itself.  Record which requirements it places after
	 * the target, keyed by id, in a simple growable string set - the file
	 * is a few thousand short rows, so a linear structure is fine and
	 * keeps the test free of any dependency on the daemon.
	 */
	path = spec_path(tc, "spec_conf_generation_generated.tsv");
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));
	while ((len = getline(&line, &cap, fp)) > 0) {
		char *f[6], *p = line, *tok;
		int nf = 0;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		while (nf < 6 && (tok = strsep(&p, "\t")) != NULL)
			f[nf++] = tok;
		if (nf < 6 || strcmp(f[0], "requirement_id") == 0)
			continue;
		rows++;
		if (strcmp(f[3], "UNKNOWN") == 0) {
			unknown++;
			ATF_REQUIRE_MSG(strcmp(f[4], "") == 0,
			    "%s: UNKNOWN generation must name no feature",
			    f[0]);
			continue;
		}
		ATF_REQUIRE_MSG(f[3][0] >= '1' && f[3][0] <= '9' &&
		    strchr(f[3], '.') != NULL,
		    "%s: '%s' is not a Core version", f[0], f[3]);
		ATF_REQUIRE_MSG(f[4][0] != '\0',
		    "%s: attributed generation %s names no feature", f[0],
		    f[3]);
		ATF_REQUIRE_MSG(f[5][0] != '\0',
		    "%s: attributed generation %s cites no evidence", f[0],
		    f[3]);
		if (spec_generation_after_target(f[3])) {
			if (strstr(f[5], "[in-scope-extra]") != NULL)
				extras++;
			else
				post_target++;
		}
	}
	free(line);
	line = NULL;
	cap = 0;
	fclose(fp);
	free(path);

	ATF_REQUIRE_MSG(rows > 0, "generation map is empty");

	/*
	 * Pass 2: the coverage file.  Count generation exclusions and require
	 * that each carries the attributed generation in its reason.
	 */
	path = spec_path(tc, "spec_conf_coverage_generated.tsv");
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));
	while ((len = getline(&line, &cap, fp)) > 0) {
		char *f[8], *p = line, *tok;
		int nf = 0;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		while (nf < 8 && (tok = strsep(&p, "\t")) != NULL)
			f[nf++] = tok;
		if (nf < 5 || strcmp(f[0], "requirement_id") == 0)
			continue;
		if (strcmp(f[3], "NOT-APPLICABLE") != 0)
			continue;
		if (strncmp(f[4], "feature generation ", 19) != 0)
			continue;
		na_generation++;
		ATF_REQUIRE_MSG(strstr(f[4], "target is") != NULL,
		    "%s: generation exclusion '%s' does not state the target",
		    f[0], f[4]);
		ATF_REQUIRE_MSG(strchr(f[4], '(') != NULL,
		    "%s: generation exclusion '%s' does not name the feature",
		    f[0], f[4]);
		matched++;
	}
	free(line);
	fclose(fp);
	free(path);

	printf("generation map rows=%lu unknown=%lu post-target=%lu "
	    "in-scope-extras=%lu; coverage generation exclusions=%lu\n",
	    rows, unknown, post_target, extras, na_generation);

	ATF_REQUIRE_MSG(na_generation == post_target,
	    "the map attributes %lu requirements to a post-target generation "
	    "but the coverage file excludes %lu: an exclusion was attributed "
	    "and then not applied, or applied without attribution",
	    post_target, na_generation);
	ATF_REQUIRE_MSG(matched == na_generation,
	    "%lu of %lu generation exclusions carry an incomplete reason",
	    na_generation - matched, na_generation);
}

ATF_TC_WITHOUT_HEAD(traceability_audit_gate);
ATF_TC_BODY(traceability_audit_gate, tc)
{
	char *kyuafile, *args;
	struct stat sb;
	int rc;

	if (!spec_exists(tc, "spec_traceability_audit.sh"))
		atf_tc_skip("spec_traceability_audit.sh not installed");
	if (!have_kyua())
		atf_tc_skip("kyua(1) unavailable; case inventory cannot be "
		    "enumerated");
	kyuafile = spec_path(tc, "Kyuafile");
	if (stat(kyuafile, &sb) != 0) {
		free(kyuafile);
		atf_tc_skip("Kyuafile not present next to the test program");
	}
	ATF_REQUIRE(asprintf(&args, "-q %s", kyuafile) > 0);
	rc = spec_run(tc, "spec_traceability_audit.sh", args);
	free(args);
	free(kyuafile);
	if (rc == SPEC_EXIT_MISSING_INPUT)
		atf_tc_skip("traceability inputs absent");
	ATF_REQUIRE_MSG(rc == 0,
	    "spec_traceability_audit.sh failed (%d): a case is unclassified, "
	    "a requirement has no matching test, or an oracle is not "
	    "independent", rc);
}

ATF_TC_WITHOUT_HEAD(case_manifest_gate);
ATF_TC_BODY(case_manifest_gate, tc)
{
	char *kyuafile, *args;
	struct stat sb;
	int rc;

	if (!spec_exists(tc, "spec_case_manifest_audit.sh"))
		atf_tc_skip("spec_case_manifest_audit.sh not installed");
	if (!have_kyua())
		atf_tc_skip("kyua(1) unavailable; case inventory cannot be "
		    "enumerated");
	kyuafile = spec_path(tc, "Kyuafile");
	if (stat(kyuafile, &sb) != 0) {
		free(kyuafile);
		atf_tc_skip("Kyuafile not present next to the test program");
	}
	ATF_REQUIRE(asprintf(&args, "-q %s", kyuafile) > 0);
	rc = spec_run(tc, "spec_case_manifest_audit.sh", args);
	free(args);
	free(kyuafile);
	if (rc == SPEC_EXIT_MISSING_INPUT)
		atf_tc_skip("case manifest inputs absent");
	ATF_REQUIRE_MSG(rc == 0,
	    "spec_case_manifest_audit.sh failed (%d): the Kyua inventory and "
	    "spec_test_references.tsv disagree", rc);
}

/*
 * Every document the matrix cites must either be present under
 * bluetooth-specs or be recorded as a known gap here.  A new citation of a
 * document nobody has fails, so "we have no normative source for this layer"
 * cannot be introduced silently.
 */
ATF_TC_WITHOUT_HEAD(cited_documents_are_accounted_for);
ATF_TC_BODY(cited_documents_are_accounted_for, tc)
{
	static const char *known_absent[] = {
		"Mesh Protocol",
		"Mesh Model",
		"Mesh Remote Provisioning",
		"Core Specification Supplement",
		"HID over GATT Profile",
		"HID Service",
		NULL
	};
	char *path, *line = NULL;
	size_t cap = 0;
	ssize_t len;
	FILE *fp;
	unsigned long absent_rows = 0;

	if (!spec_exists(tc, "spec_conf_requirements_proposed.tsv"))
		atf_tc_skip("classified requirement matrix not installed");
	path = spec_path(tc, "spec_conf_requirements_proposed.tsv");
	fp = fopen(path, "r");
	ATF_REQUIRE_MSG(fp != NULL, "%s: %s", path, strerror(errno));

	while ((len = getline(&line, &cap, fp)) > 0) {
		char *f[8], *p = line, *tok, *doc, *rest;
		int nf = 0, i;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		while (nf < 8 && (tok = strsep(&p, "\t")) != NULL)
			f[nf++] = tok;
		if (nf != 7 || strcmp(f[0], "requirement_id") == 0)
			continue;
		if (strncmp(f[6], "absent:", 7) != 0)
			continue;
		absent_rows++;
		rest = f[6] + 7;
		while ((doc = strsep(&rest, ";")) != NULL) {
			bool known = false;

			if (doc[0] == '\0')
				continue;
			for (i = 0; known_absent[i] != NULL; i++)
				if (strcmp(doc, known_absent[i]) == 0) {
					known = true;
					break;
				}
			ATF_REQUIRE_MSG(known,
			    "%s cites '%s', which is neither present under "
			    "bluetooth-specs nor a recorded specification gap",
			    f[0], doc);
		}
	}
	free(line);
	fclose(fp);
	free(path);

	printf("rows whose normative source is missing from the tree: %lu\n",
	    absent_rows);
	/*
	 * This is a reported gap, not a failure: meshd and the HID-over-GATT
	 * profile have no normative source in the tree at all, so their
	 * oracles cannot be drift-checked.  See docs/bluetooth-conformance.md.
	 */
	ATF_REQUIRE_MSG(absent_rows > 0,
	    "no rows are flagged as missing a normative source; the "
	    "classification is probably broken");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, requirements_matrix_wellformed);
	ATF_TP_ADD_TC(tp, generated_requirements_catalogue_fresh);
	ATF_TP_ADD_TC(tp, generated_profile_catalogue_fresh);
	ATF_TP_ADD_TC(tp, generated_oracles_fresh);
	ATF_TP_ADD_TC(tp, coverage_floor_not_regressed);
	ATF_TP_ADD_TC(tp, generation_map_accounts_for_every_requirement);
	ATF_TP_ADD_TC(tp, traceability_audit_gate);
	ATF_TP_ADD_TC(tp, case_manifest_gate);
	ATF_TP_ADD_TC(tp, cited_documents_are_accounted_for);

	return (atf_no_error());
}
