#include <endian.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "apds_main.h"
#include "apds_proto.h"

%%{
	machine apdate_server;
	include apdate_defs "apdate_defs.rl";

	main := proto_ident_guard | (proto_ident_pack . (prod_ident_guard |
							 (prod_ident_pack . 
							  ((upd_req_guard | 
							    upd_req_pack)**))));
}%%

void *apds_proto_thread(void *ssd) {
	int err, ret, cs, i, sd, apdate_server_start = 0;
	unsigned char *p, *pe, *eof, *buffer;
	char *upd_dir;
	gnutls_session_t sess;
	struct sess_sd *tsd = (struct sess_sd *) ssd;
	uint32_t i32, product_tag;
	uint64_t i64, upd_req_version;

	eof = NULL;
	sd = tsd->sd;
	sess = tsd->sess;
	upd_dir = tsd->upd_dir_path;
	free(tsd);

	%%write init;

	gnutls_transport_set_ptr(sess, (gnutls_transport_ptr_t) (long) sd);
	ret = gnutls_handshake(sess);
	if (ret < 0)
		goto out;

	i = 0;
	for (;;) {
		ret = gnutls_record_recv (sess, buffer, MAX_BUF);
		if (ret <= 0)
			break;
		else {
			p = buffer;
			pe = buffer + ret;

			%%write exec;
		}
	}

out_bye:
	gnutls_bye(sess, GNUTLS_SHUT_WR);
out:
	close(sd);
	gnutls_deinit(sess);
	return;
}
