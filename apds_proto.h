#ifndef APDS_PROTO_H

#define APDS_PROTO_H 1
#include <gnutls/gnutls.h>
#include <netinet/in.h>

#define MAX_BUF 1024

struct sess_sd {
	gnutls_session_t sess;
	int sd;
	struct sockaddr_in sa;
	char *upd_dir_path;
};

void *apds_proto_thread(void *ssd);

#endif
