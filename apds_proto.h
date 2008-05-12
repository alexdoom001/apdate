#include <gnutls/gnutls.h>

#define MAX_BUF 1024

struct sess_sd {
	gnutls_session_t sess;
	int sd;
	char *upd_dir_path;
};

void *apds_proto_thread(void *ssd);
