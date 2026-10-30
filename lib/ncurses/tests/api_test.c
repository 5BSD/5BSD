/* SPDX-License-Identifier: BSD-2-Clause */
/* Noninteractive public API integration across native curses/menu/form/tinfo. */
#define _XOPEN_SOURCE_EXTENDED
#include <curses.h>
#include <form.h>
#include <menu.h>
#include <panel.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); return (1); \
} } while (0)

int
main(void)
{
    ITEM *items[3];
    MENU *menu;
    FIELD *fields[3];
    FORM *form;
    cchar_t cell;
    wchar_t text[CCHARW_MAX];
    attr_t attrs;
    short pair;
    int marker = 7;
    FILE *input, *output;
    SCREEN *screen;
    WINDOW *window;
    PANEL *panel;

    CHECK(setenv("TERM", "5bsd-api-test", 1) == 0);
    CHECK(setenv("TERMCAP", "5bsd-api-test|API test terminal:co#80:li#24:cl=\\E[H\\E[2J:cm=\\E[%i%d;%dH:", 1) == 0);
    input = tmpfile();
    output = tmpfile();
    CHECK(input != NULL && output != NULL);
    screen = newterm("5bsd-api-test", output, input);
    CHECK(screen != NULL);
    window = newwin(3, 10, 1, 1);
    CHECK(window != NULL);
    panel = new_panel(window);
    CHECK(panel != NULL && panel_window(panel) == window);
    CHECK(hide_panel(panel) == OK && panel_hidden(panel));
    CHECK(show_panel(panel) == OK && !panel_hidden(panel));
    CHECK(move_panel(panel, 2, 2) == OK);
    CHECK(del_panel(panel) == OK && delwin(window) == OK);

    CHECK(strcmp(tparm("%p1%{2}%*%d", 21L), "42") == 0);
    CHECK(strcmp(keyname(KEY_DOWN), "KEY_DOWN") == 0);
    CHECK(setcchar(&cell, L"A", A_BOLD, 0, NULL) == OK);
    CHECK(getcchar(&cell, text, &attrs, &pair, NULL) == OK);
    CHECK(wcscmp(text, L"A") == 0 && (attrs & A_BOLD) != 0 && pair == 0);

    items[0] = new_item("alpha", "first");
    items[1] = new_item("beta", "second");
    items[2] = NULL;
    CHECK(items[0] != NULL && items[1] != NULL);
    menu = new_menu(items);
    CHECK(menu != NULL && item_count(menu) == 2);
    CHECK(free_item(items[0]) == E_CONNECTED);
    CHECK(set_current_item(menu, items[1]) == E_OK);
    CHECK(current_item(menu) == items[1] && item_index(items[1]) == 1);
    CHECK(set_item_userptr(items[1], &marker) == E_OK);
    CHECK(item_userptr(items[1]) == &marker);
    CHECK(menu_request_by_name(menu_request_name(REQ_NEXT_ITEM)) == REQ_NEXT_ITEM);
    CHECK(free_menu(menu) == E_OK);
    CHECK(free_item(items[0]) == E_OK && free_item(items[1]) == E_OK);

    fields[0] = new_field(1, 12, 0, 0, 0, 0);
    fields[1] = new_field(1, 12, 1, 0, 0, 0);
    fields[2] = NULL;
    CHECK(fields[0] != NULL && fields[1] != NULL);
    CHECK(set_field_buffer(fields[0], 0, "value") == E_OK);
    CHECK(strncmp(field_buffer(fields[0], 0), "value", 5) == 0);
    form = new_form(fields);
    CHECK(form != NULL && field_count(form) == 2);
    CHECK(free_field(fields[0]) == E_CONNECTED);
    CHECK(set_current_field(form, fields[1]) == E_OK);
    CHECK(current_field(form) == fields[1] && field_index(fields[1]) == 1);
    CHECK(set_field_userptr(fields[1], &marker) == E_OK);
    CHECK(field_userptr(fields[1]) == &marker);
    CHECK(form_request_by_name(form_request_name(REQ_NEXT_FIELD)) == REQ_NEXT_FIELD);
    CHECK(free_form(form) == E_OK);
    CHECK(free_field(fields[0]) == E_OK && free_field(fields[1]) == E_OK);
    (void)endwin();
    delscreen(screen);
    CHECK(fclose(input) == 0 && fclose(output) == 0);
    return (0);
}
