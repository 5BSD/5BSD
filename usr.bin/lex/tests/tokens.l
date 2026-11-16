/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

%option noinput nounput
%{
#include <stdio.h>
%}
%%
[0-9]+          printf("number:%s\n", yytext);
[A-Za-z_][A-Za-z_0-9]* printf("word:%s\n", yytext);
[ \t\r\n]+  ;
.               printf("punct:%s\n", yytext);
%%
