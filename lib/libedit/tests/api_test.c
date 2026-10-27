/* SPDX-License-Identifier: BSD-2-Clause */
#include <histedit.h>
#include <edit/readline/history.h>
#include <edit/readline/tilde.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
		return (1); \
	} \
} while (0)

int
main(void)
{
	Tokenizer *t;
	TokenizerW *tw;
	History *h;
	HistoryW *hw;
	HistEvent e;
	HistEventW ew;
	const char **args;
	const wchar_t **wargs;
	int count;
	HIST_ENTRY *entry;
	char *expanded;

	t = tok_init(NULL);
	CHECK(t != NULL);
	CHECK(tok_str(t, "first 'two words' last\n", &count, &args) == 0);
	CHECK(count == 3 && strcmp(args[0], "first") == 0 &&
	    strcmp(args[1], "two words") == 0 && strcmp(args[2], "last") == 0);
	tok_reset(t);
	CHECK(tok_str(t, "unfinished 'quote", &count, &args) != 0);
	tok_end(t);
	tw = tok_winit(NULL);
	CHECK(tw != NULL);
	CHECK(tok_wstr(tw, L"first 'two words' last\n", &count, &wargs) == 0);
	CHECK(count == 3 && wcscmp(wargs[1], L"two words") == 0);
	tok_wend(tw);
	h = history_init();
	CHECK(h != NULL);
	CHECK(history(h, &e, H_SETSIZE, 10) >= 0);
	CHECK(history(h, &e, H_ENTER, "first") >= 0);
	CHECK(history(h, &e, H_ENTER, "second") >= 0);
	CHECK(history(h, &e, H_FIRST) >= 0 && strcmp(e.str, "second") == 0);
	CHECK(history(h, &e, H_NEXT) >= 0 && strcmp(e.str, "first") == 0);
	history_end(h);
	hw = history_winit();
	CHECK(hw != NULL);
	CHECK(history_w(hw, &ew, H_SETSIZE, 10) >= 0);
	CHECK(history_w(hw, &ew, H_ENTER, L"wide entry") >= 0);
	CHECK(history_w(hw, &ew, H_FIRST) >= 0 &&
	    wcscmp(ew.str, L"wide entry") == 0);
	history_wend(hw);
	using_history();
	clear_history();
	CHECK(add_history("compatibility entry") == 0);
	CHECK(history_length == 1);
	entry = history_get(history_base);
	CHECK(entry != NULL && strcmp(entry->line, "compatibility entry") == 0);
	clear_history();
	CHECK(history_length == 0);
	expanded = tilde_expand("plain/path");
	CHECK(expanded != NULL && strcmp(expanded, "plain/path") == 0);
	free(expanded);
	return (0);
}
