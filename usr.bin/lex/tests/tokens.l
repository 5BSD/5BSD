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
