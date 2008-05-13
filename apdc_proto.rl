#include <endian.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "apdc_main.h"
#include "apdc_proto.h"

%%{
	machine apdate_client;
	include apdate_defs "apdate_defs.rl";

	main := ((upd_push_guard & cl_cert_up_guard) | (upd_push_pack |
							cl_cert_up_pack))**;
}%%

int apdc_proto(gnutls_session_t sess) {
	int err, ret, cs, i, apdate_client_start = 0;
	unsigned char *p, *pe, *eof, *buffer;

	uint32_t i32, pk_byte_count, pk_length;

	%%write init;
	%%write exec;

	return 0;
out_bye:
	return 1;
}
