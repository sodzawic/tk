%{
    #include "packet-asdftest.h"
%}

%option prefix="asdftest_yy"

%option nounput
%option noinput
%option noyywrap
%%
[a-z] {return TOK;}
%%

void asdftest_yy_delete_current_buffer(void) {
    asdftest_yy_delete_buffer(YY_CURRENT_BUFFER);
}
