#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#include "apdc_main.h"
#include "apdc_proto.h"
#include "apdc_config.h"

char *cafile, *dbpath, *verfile, *certfile, *keyfile, *product_string;
char *patch_queue_path, *crlfile, *libexec_path;
char *apds_list[APDC_MAX_LIST];
uint32_t product_code;

/*
 * Connects to the peer and returns a socket
 * descriptor.
 */
int tcp_connect(char *server)
{
	char *servname, *ppos;
     	int sd, i, port, err = -1;
	struct sockaddr_in sa;
	struct hostent *shost;

	ppos = strrchr(server, ':');
	if (ppos == NULL) {
		port = APDS_DEF_PORT;
		servname = server;
	}
	else {
		port = atoi(strdup(ppos+1));
		i = (int) (ppos - server);
		servname = malloc(i+1);
		servname = strncpy(servname, server, i);
		*(servname+i) = '\0';
	}

	shost = gethostbyname(servname);
	if (shost == NULL) {
		fprintf(stderr, "Can't resolve %s\n", servname);
		return -1;
	}

	sd = socket (AF_INET, SOCK_STREAM, 0);
	memset (&sa, '\0', sizeof (sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	for (i = 0; shost->h_addr_list[i] != NULL; i++) {
		memcpy(&sa.sin_addr, shost->h_addr_list[i], 4);
		err = connect (sd, (struct sockaddr *) & sa, sizeof (sa));
		if (err >= 0)
			break;
	}
	if (err < 0) {
		fprintf(stderr, "Connection error (%s:%d)\n", servname, port);
		return -2;
	}
	return sd;
}

/* Closes the given socket descriptor */
void tcp_close (int sd)
{
	shutdown (sd, SHUT_RDWR);
	close (sd);
}

/* This callback should be associated with a session by calling
 * gnutls_certificate_client_set_retrieve_function( session, cert_callback),
 * before a handshake.
 */
static int cert_callback (gnutls_session_t session,
	       const gnutls_datum_t * req_ca_rdn, int nreqs,
	       const gnutls_pk_algorithm_t * sign_algos,
	       int sign_algos_length, gnutls_retr_st * st)
{
	gnutls_certificate_type_t type;
	gnutls_x509_crt_t *crt;
	gnutls_x509_privkey_t *key;

	type = gnutls_certificate_type_get (session);
	if (type == GNUTLS_CRT_X509) {
		crt = load_certificate(certfile);
		if (crt == NULL) {
			fprintf(stderr, "Error loading client certificate (%s)",
				certfile);
			return -1;
		}
		key = load_privkey(keyfile);
		if (key == NULL) {
			fprintf(stderr, "Error loading client key (%s)",
				keyfile);
			return -1;
		}
		st->type = type;
		st->ncerts = 1;
		st->cert.x509 = crt;
		st->key.x509 = *key;
		st->deinit_all = 0;
	}
	else
		return -1;
	return 0;
}


int main(int argc, char **argv) {
	int ret, i, sd = -1;
	gnutls_session_t session;
	const char *err;
	char *conffile_name, *str;
	gnutls_certificate_credentials_t xcred;
	struct string_code str_code;

	if (argc == 2)
		conffile_name = argv[1];
	else if (argc == 1)
		conffile_name = APDCCONF;
	else {
		printf("Usage: apdc [conffile]\n");
		exit(1);
	}
	
	memset(apds_list, 0, APDC_MAX_LIST);
	if (conf_parse(conffile_name) != 0) {
		printf("Can't read config file '%s'\n", conffile_name);
		exit(2);
	}
	verfile = strconcat(dbpath, VERSION_FILE);
	str = strconcat(dbpath, PRODUCT_FILE);
	str_code = load_product_file(str);
	product_code = (uint32_t) str_code.code;
	product_string = str_code.str;
	free(str);
	patch_queue_path = strconcat(dbpath, PATCH_QUEUE_PATH);

	gnutls_global_init ();
	gnutls_certificate_allocate_credentials (&xcred);
	gnutls_certificate_set_x509_trust_file (xcred, cafile,
						GNUTLS_X509_FMT_PEM);
	gnutls_certificate_client_set_retrieve_function (xcred, cert_callback);
	/* We want to run constantlu */
	while (1) {
		gnutls_init (&session, GNUTLS_CLIENT);

		ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);
		if (ret < 0) {
			if (ret == GNUTLS_E_INVALID_REQUEST) {
				fprintf (stderr, "Syntax error at: %s\n", err);
			}
			exit(3);
		}
/* put the x509 credentials to the current session
 */
		gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

		/* Try to connect indefinitely */
		while (1) {
			for (i = 0; apds_list[i] != 0 && i < APDC_MAX_LIST; i++){
				sd = tcp_connect(apds_list[i]);
				if (sd > 0)
					break;
			}
			if (sd < 0)
				sleep(30);
			else
				break;
		}

		gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) 
					  (long) sd);
		ret = apdc_proto(session);
	      	if (ret == 0)
			gnutls_bye (session, GNUTLS_SHUT_RDWR);

		tcp_close (sd);
		gnutls_deinit(session);
		if (ret == APDC_UNRECOVERABLE_ERROR)
			break;
	}
	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();
	return 0;
}
