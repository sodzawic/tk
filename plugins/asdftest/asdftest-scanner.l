%{
    #include "packet-asdftest.h"
%}

%option nounput
%option noinput
%option noyywrap
%%
. {return TOK;}
%%


void asdftest_scanner_scan_bytes(const char *bytes, int len) {
    yy_scan_bytes(bytes, len);
}

void asdftest_scnner_delete_buffer(void) {
    yy_delete_buffer(YY_CURRENT_BUFFER);
}
