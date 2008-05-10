#include <stdio.h>
#include <endiano.h>

%%{
	machine apdate_client;
	include apdate_defs "apdate_defs.rl";

	main := (error_machine* :> upd_push)**;
	write init;
}%%

int main() {
	%%write exec;
}
