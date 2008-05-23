#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "apdate_client.h"
#include "apdc_main.h"
#include "apdc_proto.h"
#include "apdc_config.h"

#include <paths.h>
#include <fcntl.h>

char *cafile, *dbpath, *verfile, *certfile, *keyfile, *product_string, *certsdir, *revfile;
char *patch_queue_path, *crlfile, *libexec_path, *conffile_name, *upd_storage_path;
char *apds_list[APDC_MAX_LIST];
uint32_t product_code;
int debug_print = 0;

/*
 * Connects to the peer and returns a socket
 * descriptor.
 */
int tcp_connect(char *server)
{
	char *servname = NULL, *ppos;
     	int sd, i, port, optval, err = -1;
	socklen_t optlen = sizeof(optval);
	struct sockaddr_in sa;
	struct hostent *shost;

	ppos = strrchr(server, ':');
	if (ppos == NULL) {
		port = APDS_DEF_PORT;
		servname = strdup(server);
	}
	else {
		port = atoi(ppos+1);
		i = (int) (ppos - server);
		servname = malloc(i+1);
		servname = strncpy(servname, server, i);
		*(servname+i) = '\0';
	}

	shost = gethostbyname(servname);
	if (shost == NULL) {
		DEBUG(syslog(LOG_INFO, "Can't resolve %s", servname));
		free(servname);
		return -1;
	}

	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd < 0) {
		syslog(LOG_ERR, "socket(): %s", strerror(errno));
		free(servname);
		return -3;
	}
	optval = 1;
	optlen = sizeof(optval);
	if(setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
		syslog(LOG_ERR, "setsockopt(): %s", strerror(errno));
		free(servname);
		return -3;
	}
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
		syslog(LOG_INFO, "Connection error (%s:%d)", servname, port);
		free(servname);
		return -2;
	}
	free(servname);
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
	gnutls_x509_crt_t *crt = NULL;
	gnutls_x509_privkey_t *key;
	int ncerts;

	type = gnutls_certificate_type_get (session);
	if (type == GNUTLS_CRT_X509) {
		ncerts = load_certificate(&crt, certfile);
		if (ncerts <= 0) {
			syslog(LOG_ERR, "Error loading client certificate (%s)",
				certfile);
			return -1;
		}
		key = load_privkey(keyfile);
		if (key == NULL) {
			syslog(LOG_ERR, "Error loading client key (%s)",
				keyfile);
			return -1;
		}
		st->type = type;
		st->ncerts = ncerts;
		st->cert.x509 = crt;
		st->key.x509 = *key;
		st->deinit_all = 1;
		free(key);
	}
	else
		return -1;
	return 0;
}

int main(int argc, char **argv) {
	int ret, i, sd = -1;
	gnutls_session_t session;
	const char *err;
	gnutls_certificate_credentials_t xcred;
	pid_t pid, sid;
	int nullfd;

	if (argc == 2)
		if (*argv[1] != '/') {
			char *cwdbuf = malloc(CWDBUFSIZE);

			cwdbuf = getcwd(cwdbuf, CWDBUFSIZE);
			if (cwdbuf == NULL) {
				fprintf(stderr, "Incorrect working dir\n");
				syslog(LOG_ERR, "Incorrect working dir");
				exit(222);
			}
			
			conffile_name = g_build_filename(cwdbuf, argv[1], NULL);
			free(cwdbuf);
		} else
			conffile_name = argv[1];
	else if (argc == 1)
		conffile_name = APDCCONF;
	else {
		printf("Usage: apdc [conffile]\n");
		exit(1);
	}

	openlog("apdc", 0, LOG_LOCAL1);
	memset(apds_list, 0, APDC_MAX_LIST);
	if (conf_parse(conffile_name) != 0) {
		fprintf(stderr, "Can't read config file '%s'\n", conffile_name);
		syslog(LOG_ERR, "Can't read config file '%s'", conffile_name);
		exit(2);
	}
	patch_queue_path = strconcat(dbpath, PATCH_QUEUE_PATH);

	gnutls_global_init ();
	gnutls_certificate_allocate_credentials (&xcred);
	gnutls_certificate_set_x509_trust_file (xcred, cafile,
						GNUTLS_X509_FMT_PEM);
	gnutls_certificate_client_set_retrieve_function (xcred, cert_callback);

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
        umask(0);
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

	nullfd = open(_PATH_DEVNULL, O_RDWR);
	if (nullfd < 0)
	{
        	syslog(LOG_ERR, _PATH_DEVNULL " %s\n", strerror(errno));
		exit(3);
	}

	dup2(nullfd, STDIN_FILENO);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);

	/* We want to run constantly */
	while (1) {
		gnutls_init (&session, GNUTLS_CLIENT);

		ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);
		if (ret < 0) {
			if (ret == GNUTLS_E_INVALID_REQUEST) {
				syslog(LOG_ERR, "Syntax error at: %s\n", err);
			}
			exit(3);
		}
/* put the x509 credentials to the current session
 */
		gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

		/* Try to connect indefinitely */
		while (1) {
			for (i = 0; i < APDC_MAX_LIST && apds_list[i] != 0; i++){
				sd = tcp_connect(apds_list[i]);
				if (sd > 0)
					break;
			}
			if (sd < 0)
				sleep(300);
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
		/* The session was closed for some reason, which is not normal,
		   so sleep for a while before trying to connect again */
		sleep(180);

	}
	gnutls_certificate_free_credentials (xcred);
	gnutls_global_deinit ();
	return ret;
}
