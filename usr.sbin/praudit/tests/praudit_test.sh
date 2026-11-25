#
# Copyright (c) 2018 Aniket Pandey
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#


atf_test_case praudit_delim_comma
praudit_delim_comma_head()
{
	atf_set "descr" "Verify that comma delimiter is present with -d ',' cmd"
	atf_set "require.progs" praudit
}

praudit_delim_comma_body()
{
	atf_check -o file:$(atf_get_srcdir)/del_comma \
		praudit -d "," $(atf_get_srcdir)/trail
}


atf_test_case praudit_delim_underscore
praudit_delim_underscore_head()
{
	atf_set "descr" "Verify that underscore delimiter is present with -d _"
	atf_set "require.progs" praudit
}

praudit_delim_underscore_body()
{
	atf_check -o file:$(atf_get_srcdir)/del_underscore \
		praudit -d "_" $(atf_get_srcdir)/trail
}


atf_test_case praudit_no_args
praudit_no_args_head()
{
	atf_set "descr" "Verify that praudit outputs default form without " \
			"any arguments"
	atf_set "require.progs" praudit
}

praudit_no_args_body()
{
	atf_check -o file:$(atf_get_srcdir)/no_args \
		praudit $(atf_get_srcdir)/trail
}


atf_test_case praudit_numeric_form
praudit_numeric_form_head()
{
	atf_set "descr" "Verify that praudit outputs the numeric form " \
			"with -n flag"
	atf_set "require.progs" praudit
}

praudit_numeric_form_body()
{
	atf_check -o file:$(atf_get_srcdir)/numeric_form \
		praudit -n $(atf_get_srcdir)/trail
}


atf_test_case praudit_raw_form
praudit_raw_form_head()
{
	atf_set "descr" "Verify that praudit outputs the raw form with -r flag"
	atf_set "require.progs" praudit
}

praudit_raw_form_body()
{
	atf_check -o file:$(atf_get_srcdir)/raw_form \
		praudit -r $(atf_get_srcdir)/trail
}


atf_test_case praudit_same_line
praudit_same_line_head()
{
	atf_set "descr" "Verify that praudit outputs the trail in the same " \
			"line  with -l flag"
	atf_set "require.progs" praudit
}

praudit_same_line_body()
{
	atf_check -o file:$(atf_get_srcdir)/same_line \
		praudit -l $(atf_get_srcdir)/trail
}


atf_test_case praudit_short_form
praudit_short_form_head()
{
	atf_set "descr" "Verify that praudit outputs the short form " \
			"with -s flag"
	atf_set "require.progs" praudit
}

praudit_short_form_body()
{
	atf_check -o file:$(atf_get_srcdir)/short_form \
		praudit -s $(atf_get_srcdir)/trail
}


atf_test_case praudit_xml_form
praudit_xml_form_head()
{
	atf_set "descr" "Verify that praudit outputs the XML file with -x flag"
	atf_set "require.progs" praudit
}

praudit_xml_form_body()
{
	atf_check -o file:$(atf_get_srcdir)/xml_form \
		praudit -x $(atf_get_srcdir)/trail
}


atf_test_case praudit_sync_to_next_record
praudit_sync_to_next_record_head()
{
	atf_set "descr" "Verify that praudit(1) outputs the last few audit " \
			"records when the initial part of the trail is " \
			"corrputed."
	atf_set "require.progs" praudit
}

praudit_sync_to_next_record_body()
{
	# The 'corrupted' binary file contains some redundant
	# binary symbols before the actual audit record.
	# Since 'praudit -p' syncs to the next legitimate record,
	# it would skip the corrupted part and print the desired
	# audit record to STDOUT.
	atf_check -o file:$(atf_get_srcdir)/no_args \
		praudit -p $(atf_get_srcdir)/corrupted
}


atf_test_case praudit_raw_short_exclusive
praudit_raw_short_exclusive_head()
{
	atf_set "descr" "Verify that praudit outputs usage message on stderr " \
			"when both raw and short options are specified"
	atf_set "require.progs" praudit
}

praudit_raw_short_exclusive_body()
{
	atf_check -s exit:1 -e match:"usage: praudit" \
		praudit -rs $(atf_get_srcdir)/trail
}


# Every token type a program can make (input/golden_tokens, written by
# mkgolden.c), printed as the praudit of the tree before the procident
# token printed it.  Numeric forms only, so that no name database is read.
atf_test_case praudit_golden_tokens
praudit_golden_tokens_head()
{
	atf_set "descr" "Verify that every existing token type prints as " \
			"before (numeric, raw, short, one-line and XML forms)"
	atf_set "require.progs" praudit
}

praudit_golden_tokens_body()
{
	local in=$(atf_get_srcdir)/golden_tokens

	export TZ=UTC
	atf_check -o file:$(atf_get_srcdir)/golden_numeric praudit -n $in
	atf_check -o file:$(atf_get_srcdir)/golden_raw praudit -rn $in
	atf_check -o file:$(atf_get_srcdir)/golden_short praudit -sn $in
	atf_check -o file:$(atf_get_srcdir)/golden_oneline praudit -ln $in
	# From standard input praudit does not fork (praudit.c), so the
	# XML header is printed once; it then exits 1 without the footer.
	atf_check -s exit:1 -o file:$(atf_get_srcdir)/golden_xml \
		praudit -xn < $in
}

# A record whose procident token (0xc0) is read by a praudit that does not
# know it: header, subject and return print as before, the token alone is
# "unknown" (fetch_invalid_tok() takes the bytes up to the trailer), and
# the XML form drops it.  The XML of praudit -x is completed with the
# footer praudit leaves out when it reads standard input, then parsed.
# config: old_praudit, a praudit built before the token (default: the
# system's, when it does not know the token).
atf_test_case praudit_procident_old_reader
praudit_procident_old_reader_head()
{
	atf_set "descr" "Verify that a praudit without the procident " \
			"token still prints the rest of the record"
	atf_set "require.progs" praudit python3
}

praudit_procident_old_reader_body()
{
	local in=$(atf_get_srcdir)/procident_trail
	local pr=$(atf_config_get old_praudit praudit)

	export TZ=UTC
	if ! atf_config_has old_praudit &&
	    praudit -n $in | grep -q '^procident,'; then
		atf_skip "praudit knows the procident token; set old_praudit" \
		    "to a praudit built before it"
	fi
	atf_check -o file:$(atf_get_srcdir)/procident_old_numeric $pr -n $in
	atf_check -o file:$(atf_get_srcdir)/procident_old_raw $pr -rn $in
	atf_check -s exit:1 -o save:old.xml $pr -xn < $in
	atf_check -o file:$(atf_get_srcdir)/procident_old_xml cat old.xml
	echo '</audit>' >> old.xml
	atf_check python3 -I -c 'import sys, xml.dom.minidom; \
	    xml.dom.minidom.parse(sys.argv[1])' old.xml
}

# The same record read by a praudit that knows the token.
atf_test_case praudit_procident
praudit_procident_head()
{
	atf_set "descr" "Verify that praudit prints the procident token"
	atf_set "require.progs" praudit python3
}

praudit_procident_body()
{
	local in=$(atf_get_srcdir)/procident_trail

	export TZ=UTC
	atf_check -o file:$(atf_get_srcdir)/procident_new_numeric praudit -n $in
	atf_check -o file:$(atf_get_srcdir)/procident_new_raw praudit -rn $in
	atf_check -s exit:1 -o save:new.xml praudit -xn < $in
	atf_check -o file:$(atf_get_srcdir)/procident_new_xml cat new.xml
	echo '</audit>' >> new.xml
	atf_check python3 -I -c 'import sys, xml.dom.minidom; \
	    xml.dom.minidom.parse(sys.argv[1])' new.xml
}


# FreeBSD's capability rights token (AUT_RIGHTS, 0x83), which libbsm did
# not parse: the tokens after it were swallowed as "unknown".
atf_test_case praudit_rights
praudit_rights_head()
{
	atf_set "descr" "Verify that praudit prints the rights token and " \
			"the tokens after it"
	atf_set "require.progs" praudit
}

praudit_rights_body()
{
	export TZ=UTC
	atf_check -o file:$(atf_get_srcdir)/rights_numeric \
		praudit -n $(atf_get_srcdir)/rights_trail
}

atf_init_test_cases()
{
	atf_add_test_case praudit_delim_comma
	atf_add_test_case praudit_delim_underscore
	atf_add_test_case praudit_no_args
	atf_add_test_case praudit_numeric_form
	atf_add_test_case praudit_raw_form
	atf_add_test_case praudit_same_line
	atf_add_test_case praudit_short_form
	atf_add_test_case praudit_xml_form
	atf_add_test_case praudit_sync_to_next_record
	atf_add_test_case praudit_raw_short_exclusive
	atf_add_test_case praudit_golden_tokens
	atf_add_test_case praudit_procident_old_reader
	atf_add_test_case praudit_procident
	atf_add_test_case praudit_rights
}
