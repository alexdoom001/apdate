/*
 * TLS/connection management is done there
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "apds_main.h"
#include "apds_proto.h"
#include "apds_cache_db.h"

GCRY_THREAD_OPTION_PTHREAD_IMPL;

gnutls_certificate_credentials_t cert_cred;

static gnutls_dh_params_t dh_params;
static int generate_dh_params (void)
{
/* Generate Diffie-Hellman parameters - for use with DHE
 * kx algorithms. When short bit length is used, it might
 * be wise to regenerate parameters.
 *
 * Check the ex-serv-export.c example for using static
 * parameters.
 */
	gnutls_dh_params_init (&dh_params);
	gnutls_dh_params_generate2 (dh_params, DH_BITS);
	return 0;
}

/* Export-grade cipher suites require temporary RSA
 * keys.
 */
gnutls_rsa_params_t rsa_params;

static int generate_rsa_params (void)
{
	gnutls_rsa_params_init (&rsa_params);
/* Generate RSA parameters - for use with RSA-export
 * cipher suites. This is an RSA private key and should be
 * discarded and regenerated once a day, once every 500
 * transactions etc. Depends on the security requirements
 */
	gnutls_rsa_params_generate2 (rsa_params, 1024);
	return 0;
}

int main() {
	int err, listen_sd, i, ret;
	struct sockaddr_in sa_serv, sa_cli;
	int client_len;
	char topbuf[512];
	char buffer[MAX_BUF + 1];
	int optval = 1;
	char name[256];

	// libgcrypt init, pthread init and /dev/random disallowance
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	gnutls_global_init();
	gnutls_certificate_allocate_credentials (&cert_cred);
	gnutls_certificate_set_x509_trust_file (cert_cred, CAFILE,
						GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_crl_file (cert_cred, CRLFILE,
					      GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_key_file (cert_cred, CERTFILE, KEYFILE,
					      GNUTLS_X509_FMT_PEM);
	generate_dh_params ();
	generate_rsa_params ();
	gnutls_certificate_set_dh_params (cert_cred, dh_params);
	gnutls_certificate_set_rsa_export_params (cert_cred, rsa_params);
	cache_db_global_init();
/* Socket operations
 */
	listen_sd = socket (AF_INET, SOCK_STREAM, 0);
	SOCKET_ERR (listen_sd, "socket");
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons (APDS_PORT);
/* Server Port number */
	setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof (int));
	err = bind (listen_sd, (struct sockaddr *) & sa_serv, sizeof (sa_serv));
	SOCKET_ERR (err, "bind");
	err = listen (listen_sd, 1024);
	SOCKET_ERR (err, "listen");
	pthread_t thread;
	for (;;)
	{
		struct sess_sd *ssd;
		ssd = malloc(sizeof(struct sess_sd));

		ssd->up_dir_path = NULL;
		gnutls_init (&ssd->sess, GNUTLS_SERVER);
		gnutls_priority_set_direct (ssd->sess, "EXPORT", NULL);
		gnutls_credentials_set (ssd->sess, GNUTLS_CRD_CERTIFICATE, cert_cred);
		gnutls_certificate_server_set_request(ssd->sess, GNUTLS_CERT_REQUIRE);
		gnutls_dh_set_prime_bits (ssd->sess, DH_BITS);
		cache_db_session_init(&ssd->sess);

		ssd->sd = accept (listen_sd, (struct sockaddr *) & sa_cli, &client_len);
		pthread_create(&thread, NULL, apds_proto_thread, (void *) ssd);
	}
	close (listen_sd);
	cache_db_deinit();
	gnutls_certificate_free_credentials (cert_cred);
	gnutls_global_deinit ();
	return 0;
}
