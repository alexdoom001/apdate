#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "apdc_main.h"
#include "apdc_proto.h"

char *cafile, *verfile, *certfile, *keyfile;
char *apds_list[APDC_MAX_LIST];
int prodcode;

/*
 * Connects to the peer and returns a socket
 * descriptor.
 */
int tcp_connect(char *server)
{
	char *servname, *ppos;
     	int err, sd, i, port;
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
	if (err < 0)
		fprintf(stderr, "Connection error (%s:%d)\n", servname, port);
	return sd;
}

/* Closes the given socket descriptor */
void tcp_close (int sd)
{
	shutdown (sd, SHUT_RDWR);
	close (sd);
}

int main(int argc, char **argv) {
	int ret, sd, i, ii;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	const char *err;
	char *conffile_name;
	gnutls_certificate_credentials_t xcred;

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
	
	gnutls_global_init ();
	gnutls_certificate_allocate_credentials (&xcred);
	gnutls_certificate_set_x509_trust_file (xcred, cafile, GNUTLS_X509_FMT_PEM);
	gnutls_init (&session, GNUTLS_CLIENT);

	ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);
	if (ret < 0)
	{
		if (ret == GNUTLS_E_INVALID_REQUEST)
		{
			fprintf (stderr, "Syntax error at: %s\n", err);
		}
		exit(3);
	}
/* put the x509 credentials to the current session
 */
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

	/* Try to connect indefinitely */
	while (1) {
		for (i = 0; apds_list[i] != 0 && i < APDC_MAX_LIST; i++) {
			sd = tcp_connect(apds_list[i]);
			if (sd > 0)
				break;
		}
		if (sd < 0)
			sleep(30);
		else
			break;
	}

	gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) (long) sd);
/* Perform the TLS handshake
 */
	ret = gnutls_handshake (session);
	if (ret < 0)
	{
		fprintf (stderr, "*** Handshake failed\n");
		gnutls_perror (ret);
		goto end;
	}
	else
	{
		printf ("- Handshake was completed\n");
	}
//	gnutls_record_send (session, MSG, strlen (MSG));
	ret = gnutls_record_recv (session, buffer, MAX_BUF);
	if (ret == 0)
	{
		printf ("- Peer has closed the TLS connection\n");
		goto end;
	}
	else if (ret < 0)
	{
		fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
		goto end;
	}
	printf ("- Received %d bytes: ", ret);
	for (ii = 0; ii < ret; ii++)
	{
		fputc (buffer[ii], stdout);
	}

	gnutls_bye (session, GNUTLS_SHUT_RDWR);
end:
	tcp_close (sd);
	gnutls_deinit (session);
	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();
	return 0;
}
