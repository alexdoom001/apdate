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

char *upddb, *port, *keyfile, *certfile, *cafile, *crlfile;

int main(int argc, char **argv) {
	int err, listen_sd, i, ret, client_len;
	struct sockaddr_in sa_serv;
	char topbuf[512];
	char *conffile_name;
	int optval = 1;
	char name[256];

	if (argc == 2)
		conffile_name = argv[1];
	else if (argc == 1)
		conffile_name = APDSCONF;
	else {
		printf("Usage: apds [conffile]\n");
		exit(1);
	}
	
	if (conf_parse(conffile_name) != 0) {
		printf("Can't read config file '%s'\n", conffile_name);
		exit(2);
	}

	// libgcrypt init, pthread init and /dev/random disallowance
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	gnutls_global_init();
	gnutls_certificate_allocate_credentials (&cert_cred);
	if (gnutls_certificate_set_x509_trust_file(cert_cred, cafile,
						   GNUTLS_X509_FMT_PEM) < 0) {
		fprintf(stderr, "Can't load CA file (%s)\n", cafile);
		exit(3);
	}
	if (gnutls_certificate_set_x509_crl_file(cert_cred, crlfile,
						 GNUTLS_X509_FMT_PEM) < 0) {
		fprintf(stderr, "Can't load CRL file (%s)\n", crlfile);
		exit(4);
	}
	if (gnutls_certificate_set_x509_key_file(cert_cred, certfile, keyfile,
				 GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Can't load server key/cert (%s/%s)\n", keyfile,
			certfile);
		exit(5);
	}
	generate_dh_params ();
	generate_rsa_params ();
	gnutls_certificate_set_dh_params (cert_cred, dh_params);
	gnutls_certificate_set_rsa_export_params (cert_cred, rsa_params);
	cache_db_global_init();

	listen_sd = socket (AF_INET, SOCK_STREAM, 0);
	SOCKET_ERR (listen_sd, "socket");
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(atoi(port));

	setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof (int));
	err = bind (listen_sd, (struct sockaddr *) & sa_serv, sizeof (sa_serv));
	SOCKET_ERR (err, "bind");
	err = listen (listen_sd, 1024);
	SOCKET_ERR (err, "listen");

	for (;;) {
		struct sess_sd *ssd;
		pthread_t *thread;

		ssd = malloc(sizeof(struct sess_sd));
		thread = malloc(sizeof(pthread_t));
		client_len = sizeof(ssd->sa);

		ssd->upd_dir_path = upddb;
		gnutls_init (&ssd->sess, GNUTLS_SERVER);
		gnutls_priority_set_direct (ssd->sess, "EXPORT", NULL);
		gnutls_credentials_set (ssd->sess, GNUTLS_CRD_CERTIFICATE, cert_cred);
		gnutls_certificate_server_set_request(ssd->sess, GNUTLS_CERT_REQUIRE);
		gnutls_dh_set_prime_bits (ssd->sess, DH_BITS);
		cache_db_session_init(&ssd->sess);

		ssd->sd = accept(listen_sd, (struct sockaddr *) &ssd->sa, &client_len);
		pthread_create(thread, NULL, apds_proto_thread, (void *) ssd);
	}
	close (listen_sd);
	cache_db_deinit();
	gnutls_certificate_free_credentials (cert_cred);
	gnutls_global_deinit ();
	return 0;
}
