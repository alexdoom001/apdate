#include <stdio.h>
#include <endian.h>

%%{
	machine apdate_client;
	include apdate_defs "apdate_defs.rl";

	main := ((upd_push_guard & cl_cert_up_guard) | (upd_push_pack | cl_cert_up_pack))**;
	write init;
}%%

int main() {
	%%write exec;
}
