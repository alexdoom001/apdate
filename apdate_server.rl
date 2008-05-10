#include <stdio.h>
#include <endiano.h>

%%{
	machine apdate_client;
	include apdate_defs "apdate_defs.rl";

	main := proto_ident_pack . prod_ident_pack . upd_req_info**;
	write init;
}%%

int main() {
	%%write exec;
}
