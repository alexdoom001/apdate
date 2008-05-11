#include <endian.h>
#include <gnutls.h>
#include <gcrypt.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;

%%{
	machine apdate_server;
	include apdate_defs "apdate_defs.rl";

	main := proto_ident_guard | (proto_ident_pack . (prod_ident_guard | (prod_ident_pack . ((upd_req_guard | upd_req_pack)**))));
}%%

int client_thread() {
	%%write init;
}

int main() {

	// libgcrypt init
	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gnutls_global_init();

	%%write exec;
}
