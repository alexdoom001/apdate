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

int mk_version_pk(char *buffer) {
	FILE *vf;
	int i;
	uint64_t version;

	buffer[0] = 2;
	vf = fopen(verfile, "r");
	if (vf == NULL) {
		fprintf(stderr, "Error: can't open version file (%s)", verfile);
		return 0;
	}

	i = fscanf(vf, "%llu", (long long unsigned int *) &version);
	if (i == 0) {
		fprintf(stderr, "Error: garbage in version file (%s)", verfile);
		i = -1;
		goto mkvpk_out;
	}
	*((uint64_t *) (buffer + 1)) = htobe64(version);
	i = 0;
mkvpk_out:
	fclose(vf);
	return i;
}

int send_version_pk(gnutls_session_t session) {
	char buffer[9];

	if (mk_version_pk(buffer) != 0)
		return APDC_UNRECOVERABLE_ERROR;

	return gnutls_record_send(session, buffer, 9);
}

int send_product_pk(gnutls_session_t session) {
	char buffer[5];
	int32_t pc_be;

	buffer[0] = 1;
	pc_be = htobe32(product_code);
	memcpy(buffer + 1, &pc_be, 4);
	return gnutls_record_send(session, buffer, 5);
}

int send_proto_pk(gnutls_session_t session) {
	char buffer[2];

	buffer[0] = 0;
	buffer[1] = PROTO_VERSION;

	return gnutls_record_send(session, buffer, 2);
}

int apdc_proto(gnutls_session_t session) {
	int err, ret, cs, i, upfile, intcnt, apdate_client_start = 13;
	unsigned char *p, *pe, *eof;
	char *tname = malloc(strlen(TMP_FILE_PATTERN));
	char buffer[MAX_BUF + 1];
	uint32_t i32, pk_byte_count, pk_length;

	%%write init;

	ret = gnutls_handshake(session);
	if (ret < 0) {
		fprintf(stderr, "TLS Handshake failed\n");
		gnutls_perror (ret);
		goto out_bye;
	}
	ret = send_proto_pk(session);
	HANDLE_TLS_ERR;
	ret = send_product_pk(session);
	HANDLE_TLS_ERR;
	ret = send_version_pk(session);
	if (ret == APDC_UNRECOVERABLE_ERROR)
		return APDC_UNRECOVERABLE_ERROR;
	HANDLE_TLS_ERR;

	while (1) {
		ret = gnutls_record_recv (session, buffer, MAX_BUF);
		if (ret == 0) {
			fprintf(stderr, "Peer has closed the TLS connection\n");
			goto out;
		} else HANDLE_TLS_ERR;

		p = buffer;
		pe = buffer + ret;

		%%write exec;
	}
out:
	return 0;
out_bye:
	return 1;
}
