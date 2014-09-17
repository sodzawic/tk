%{

#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdio.h>
#include "packet-asdftest.h"


int asdftest_yylex(void);
int asdftest_yyparse(void);
void asdftest_yy_scan_bytes(const char *bytes, int len);
void asdftest_yy_delete_current_buffer(void);

static void asdftest_yyerror(const char *s);

void proto_register_asdftest(void);
void proto_reg_handoff_asdftest(void);
static void dissect_asdftest(tvbuff_t *tvb, packet_info *pinfo, 
        proto_tree *tree, void *data _U_);

static int proto_asdftest = -1;

%}

%token TOK

%%

packet: /* empty */
    | TOK {printf(" ------------------> TOK\n");} packet
    ;

%%

static void asdftest_yyerror(const char *s) 
{
    printf(" ERROR: %s\n", s);
}

static void dissect_asdftest(tvbuff_t *tvb, packet_info *pinfo, 
        proto_tree *tree, void *data _U_)
{
    (void) tvb;
    (void) tree;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "asdftest");
    col_clear(pinfo->cinfo, COL_INFO);

    asdftest_yy_scan_bytes("asdf", 4);
    asdftest_yyparse();
    asdftest_yy_delete_current_buffer();
}

void proto_register_asdftest(void)
{
    proto_asdftest = proto_register_protocol(
            "asdftest protocol",
            "asdftest",
            "asdftest");
}

void proto_reg_handoff_asdftest(void)
{
    dissector_handle_t asdftest_handle;

    asdftest_handle = new_create_dissector_handle((new_dissector_t) dissect_asdftest, proto_asdftest);
    dissector_add_uint("tcp.port", 5555, asdftest_handle);
}
