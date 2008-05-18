#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apds_file_cache.h"
#include "apds_inotify.h"
#include "apds_main.h"
#include "apds_proto.h"
#include "apdate_common.h"
#include "apdate_products.h"

%%{
	machine apdate_server;
	include apdate_defs "apdate_defs.rl";

	main := proto_ident_guard | (proto_ident_pack . (prod_ident_guard |
							 (prod_ident_pack . 
							  ((upd_req_guard | 
							    upd_req_pack)**))));
}%%

pthread_key_t verstr_key, prodstr_key, session_key, prodint_key;

extern int debug_print;

int is_patch_needed(const struct dirent *item) {
	char *vstr;

	vstr = pthread_getspecific(verstr_key);
	if (strverscmp(vstr, item->d_name) < 0)
		return 1;
	else
		return 0;
}

static int push_update(const char *fversion) {
	uint32_t prodcode;
	void *fpoint, *fbound;
	int ret;
	unsigned int sz;
	char *fbuf;
	gnutls_session_t session;
	struct upd_map fmap;

	session = *((gnutls_session_t *) pthread_getspecific(session_key));
	prodcode = (uint32_t) (ssize_t) pthread_getspecific(prodint_key);
	fbuf = malloc(31);
	sprintf(fbuf, "%u/%s", prodcode, fversion);
	fmap = get_upd_map(fbuf);
	if (fmap.mmap == NULL) {
		free(fbuf);
		return -10000;
	}
	sz = htobe32((unsigned int) fmap.size);
	fbuf[0] = 3;
	memcpy(fbuf + 1, &sz, 4);
	ret = gnutls_record_send(session, fbuf, 5);
	free(fbuf);
	if (ret < 0)
		goto push_out;

	fbound = fmap.mmap + fmap.size;
	for (fpoint = fmap.mmap; fpoint < fbound; fpoint += MAX_BUF) {
		sz = (((fpoint + MAX_BUF) < fbound) ? MAX_BUF : fbound - fpoint);
		ret = gnutls_record_send(session, fpoint, sz);
		if (ret < 0)
			break;
		ret = 0;
	}

push_out:
	release_upd_file(fmap);
	return ret;
}

static char *mkproduct_path(const char *updb, const uint32_t prod) {
	char *product_path;
	int i;

	i = strlen(updb);
	product_path = malloc(i + 10);
	product_path = strcpy(product_path, updb);
	sprintf(product_path + i, "%u", (unsigned int) prod);
	product_path = strcat(product_path, "/");
	pthread_setspecific(prodstr_key, product_path);
	pthread_setspecific(prodint_key, (void *) (ssize_t) prod);
	return product_path;
}

static char *mkversion_string(const uint64_t version) {
	char *verstr;

	verstr = malloc(20);
	sprintf(verstr, "%llu", (long long unsigned int) version);
	pthread_setspecific(verstr_key, verstr);
	return verstr;
}

static int push_updates() {
	char *product_path;
	struct dirent **updates;
	int i, num_upds, ret = 0;

	product_path = pthread_getspecific(prodstr_key);
	num_upds = scandir(product_path, &updates, is_patch_needed, versionsort);
	for (i = 0; i<num_upds; i++) {
		if (ret == 0)
			ret = push_update(updates[i]->d_name);
		free(updates[i]);
	}
	free(updates);
	return ret;
}

static int push_inotify_update(const int wd) {
	int len, i = 0, ret = 0;
	char buf[INOTIFY_BUF];

	len = read(wd, buf, INOTIFY_BUF);
	if (len < 0) {
		perror("Inotify read failed");
	}
	while (i < len) {
		char *fname = (char *) &buf[i];
		if (ret == 0)
			ret = push_update(fname);
		i += strlen(fname) + 1;
	}
	return ret;
}

void apds_init_pthread_keys(void)
{
	pthread_key_create(&verstr_key, NULL);
	pthread_key_create(&prodstr_key, NULL);
	pthread_key_create(&prodint_key, NULL);
	pthread_key_create(&session_key, NULL);
}

void apds_deinit_pthread_keys(void)
{
	pthread_key_delete(verstr_key);
	pthread_key_delete(prodstr_key);
	pthread_key_delete(prodint_key);
	pthread_key_delete(session_key);
}

void *apds_proto_thread(void *ssd) {
	int ret, cs, i, sd, intcnt, inotify_watch = 0;
	unsigned int status;
	fd_set fds;
	unsigned char *p, *pe, *eof;
	unsigned char buffer[MAX_BUF];
	char *upd_dir, *version_string, *product_path;
	gnutls_session_t session;
	struct sess_sd *tsd = (struct sess_sd *) ssd;
	struct sockaddr_in sa;
	uint32_t i32, product_tag;
	uint64_t i64, upd_req_version;

	eof = NULL;
	sd = tsd->sd;
	session = tsd->sess;
	upd_dir = tsd->upd_dir_path;
	sa = tsd->sa;
	free(tsd);
	pthread_setspecific(session_key, &session);

	%%write data;
	%%write init;

	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) (long) sd);
	ret = gnutls_handshake(session);
	printf("APDS: connection from %s\n", inet_ntop(AF_INET, &sa.sin_addr,
						       (char *) buffer, MAX_BUF));

	if (ret < 0) {
		gnutls_perror(ret);
		goto out;
	}
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		fprintf(stderr, "Error verifying certificate\n");
		goto out_bye;
	}
	if (status & GNUTLS_CERT_INVALID) {
		fprintf(stderr, "Untrusted peer certificate\n");
		goto out_bye;
	}
	i = 0;
	for (;;) {
		FD_ZERO(&fds);
		FD_SET(sd, &fds);
		if (inotify_watch > 0)
			FD_SET(inotify_watch, &fds);
		
		ret = select(((sd > inotify_watch ? sd : inotify_watch) + 1),
			     &fds, NULL, NULL, NULL);
		if (FD_ISSET(sd, &fds)) {
			ret = gnutls_record_recv(session, buffer, MAX_BUF);
			if (ret < 0) {
				gnutls_perror(ret);
				goto out;
			} else if (ret == 0) {
				goto out;
			} else {
				p = buffer;
				pe = buffer + ret;
				%%write exec;
				if (ret < 0) {
					gnutls_perror(ret);
					goto out;
				}
			}
		} else if (FD_ISSET(inotify_watch, &fds)) {
			ret = push_inotify_update(inotify_watch);
			if (ret < 0) {
				gnutls_perror(ret);
				goto out;
			}
		}
		else
			break;
	}

out_bye:
	gnutls_bye(session, GNUTLS_SHUT_WR);
out:
	if (inotify_watch > 0)
		inotify_unsub(inotify_watch);
	free(version_string);
	free(product_path);
	close(sd);
	gnutls_deinit(session);
	printf("APDS: connection closed\n");
	return NULL;
}
