#ifndef APDS_PROTO_H

#define APDS_PROTO_H 1

#include <glib.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>

#define MAX_BUF 1024
#define INOTIFY_BUF 1024

struct sess_sd {
	gnutls_session_t sess;
	int sd;
	struct sockaddr_in sa;
};

struct apds_session {
	gnutls_session_t sess;
	GArray *reqs;
	int i_wfd;
	int i_rfd;
	GArray *types;
	char *serial;
	char *product;
	int got_ready_to_roll;
};

extern pthread_key_t apds_key;

void *apds_proto_thread(void *ssd);
void apds_init_pthread_keys(void);
void apds_deinit_pthread_keys(void);

#endif
