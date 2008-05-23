/*
 * TLS/connection management is done there
 */

#include <arpa/inet.h>
#include <errno.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "apds_file_cache.h"
#include "apds_inotify.h"
#include "apds_main.h"
#include "apds_proto.h"
#include "apds_cache_db.h"
#include "apds_config.h"

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

char *upddb, *port, *keyfile, *certfile, *cafile, *crlfile, *prodsfile;
int debug_print = 0;
unsigned int calist_size = 0;
long int nr_cpus;
gnutls_x509_crt_t *calist;
gnutls_x509_crl_t *crl;
pthread_barrier_t initbarrier;

int main(int argc, char **argv) {
	int err, listen_sd;
	unsigned int client_len;
	struct sockaddr_in sa_serv;
	char *conffile_name;
	int optval = 1;
	pthread_t inotify_thread, fcache_thread;
	pthread_attr_t pth_attr;
	gnutls_datum_t fdata;
	pid_t pid, sid;
	FILE *pidf;

	if (argc == 2)
		conffile_name = argv[1];
	else if (argc == 1)
		conffile_name = APDSCONF;
	else {
		fprintf(stderr, "Usage: apds [conffile]\n");
		exit(1);
	}
	
	openlog("apds", 0, LOG_LOCAL1);
	if (conf_parse(conffile_name) != 0) {
		fprintf(stderr, "Can't read config file '%s'\n", conffile_name);
		syslog(LOG_ERR, "Can't read config file '%s'", conffile_name);
		exit(2);
	}

	setlinebuf(stdout);

	// libgcrypt init, pthread init and /dev/random disallowance
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	gnutls_global_init();
	gnutls_certificate_allocate_credentials (&cert_cred);
	if (gnutls_certificate_set_x509_trust_file(cert_cred, cafile,
						   GNUTLS_X509_FMT_PEM) < 0) {
		fprintf(stderr, "Can't load CA file (%s)\n", cafile);
		syslog(LOG_ERR, "Can't load CA file (%s)", cafile);
		exit(3);
	}
	if (gnutls_certificate_set_x509_crl_file(cert_cred, crlfile,
						 GNUTLS_X509_FMT_PEM) < 0) {
		fprintf(stderr, "Can't load CRL file (%s)\n", crlfile);
		syslog(LOG_ERR, "Can't load CRL file (%s)", crlfile);
		exit(4);
	}
	if (gnutls_certificate_set_x509_key_file(cert_cred, certfile, keyfile,
				 GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Can't load server key/cert (%s/%s)\n", keyfile,
			certfile);
		syslog(LOG_ERR, "Can't load server key/cert (%s/%s)\n", keyfile,
			certfile);
		exit(5);
	}
	calist = load_calist(cafile, &calist_size);
	if (calist == NULL) {
		fprintf(stderr, "Error loading CA list\n");
		syslog(LOG_ERR, "Error loading CA list");
		exit(98);
	}
	crl = load_crl(crlfile);
	if (crl == NULL) {
		syslog(LOG_ERR, "Error loading CRL");
		fprintf(stderr, "Error loading CRL\n");
		exit(99);
	}

        /* Daemonize */
        pid = fork();
        if (pid < 0) {
		fprintf(stderr, "Failed to fork()");
		syslog(LOG_ERR, "Failed to fork()");
                exit(11);
        }
	/* Parent */
        if (pid > 0) {
                exit(0);
        }
        sid = setsid();
        if (sid < 0) {
		fprintf(stderr, "Failed to setsid()");
		syslog(LOG_ERR, "Failed to setsid()");
                exit(22);
        }
        if ((chdir("/")) < 0) {
		fprintf(stderr, "Failed to chdir to root");
		syslog(LOG_ERR, "Failed to chdir to root");
                exit(33);
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

	generate_dh_params();
	generate_rsa_params();
	gnutls_certificate_set_dh_params(cert_cred, dh_params);
	gnutls_certificate_set_rsa_export_params(cert_cred, rsa_params);
	cache_db_global_init();
	apds_init_pthread_keys();

	/*
	 * Disable SIGPIPE, no other way to handle connection breakages
	 */
	signal(SIGPIPE, SIG_IGN);

	if ((pthread_attr_init(&pth_attr) != 0) || pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED) != 0) {
		fprintf(stderr, "Failed to init pthread attributes\n");
		syslog(LOG_ERR, "Failed to init pthread attributes");
		exit(34);
	}
	pthread_barrier_init(&initbarrier, NULL, 3);
	pthread_create(&inotify_thread, &pth_attr, apds_inotify_thread, NULL);
	pthread_create(&fcache_thread, &pth_attr, apds_fcache_thread, NULL);

	pthread_barrier_wait(&initbarrier);
	pthread_barrier_destroy(&initbarrier);
	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	/*
	 * If the system fails to give the number of cpu's fallback to something
	 * large enough to effectively disable load throttling
	 */
	if (nr_cpus <= 0)
		nr_cpus = 1024;

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

	pidf = fopen("/var/run/apds.pid", "w");
	if (pidf == NULL) {
		syslog(LOG_ERR, "Can't open pid file");
	} else {
		pid = getpid();
		if (fprintf(pidf, "%llu\n", (unsigned long long int) pid) < 0)
			syslog(LOG_ERR, "Can't write to pid file");
		if (fclose(pidf) != 0)
			syslog(LOG_ERR, "Can't close pid file");
	}
	for (;;) {
		struct sess_sd *ssd;
		pthread_t thread;
		int perr;

		ssd = malloc(sizeof(struct sess_sd));
		client_len = sizeof(ssd->sa);

		gnutls_init (&ssd->sess, GNUTLS_SERVER);
		gnutls_priority_set_direct (ssd->sess, "EXPORT", NULL);
		gnutls_credentials_set (ssd->sess, GNUTLS_CRD_CERTIFICATE, cert_cred);
		gnutls_certificate_server_set_request(ssd->sess, GNUTLS_CERT_REQUIRE);
		gnutls_dh_set_prime_bits (ssd->sess, DH_BITS);
		cache_db_session_init(&ssd->sess);

		ssd->sd = accept(listen_sd, (struct sockaddr *) &ssd->sa, &client_len);
		perr = pthread_create(&thread, &pth_attr, apds_proto_thread, (void *) ssd);
		if (perr != 0) {
			syslog(LOG_ERR, "Can't create thread to serve client: %s", strerror(perr));
			close(ssd->sd);
		}
	}
	close (listen_sd);
	cache_db_deinit();
	apds_deinit_pthread_keys();
	gnutls_certificate_free_credentials (cert_cred);
	gnutls_global_deinit();
	return 0;
}
