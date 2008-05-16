#include <dirent.h>
#include <endian.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "apds_main.h"
#include "apds_proto.h"

%%{
	machine apdate_server;
	include apdate_defs "apdate_defs.rl";

	main := proto_ident_guard | (proto_ident_pack . (prod_ident_guard |
							 (prod_ident_pack . 
							  ((upd_req_guard | 
							    upd_req_pack)**))));
}%%

char *vstr;

int is_patch_needed(const struct dirent *item) {
	if (strverscmp(vstr, item->d_name) < 0)
		return 1;
	else
		return 0;
}

int push_update(gnutls_session_t session, char *file) {
	struct stat fst;
	int fd;
	unsigned int sz_be;
	ssize_t rb;
	char sbuf[MAX_BUF];

	stat(file, &fst);
	sz_be = htobe32((unsigned int) fst.st_size);
	sbuf[0] = 3;
	memcpy(sbuf+1, &sz_be, 4);
	gnutls_record_send(session, sbuf, 5);
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;
	while (rb = read(fd, sbuf, MAX_BUF)) {
		if (rb < 0) {
			close(fd);
			return -1;
		}
		gnutls_record_send(session, sbuf, rb);
	}
	
	close(fd);
	return 0;
}

void push_updates(gnutls_session_t session, uint64_t ver, uint32_t prod) {
	char *ppath, *fpath;
	struct dirent **updates;
	int i, num_upds;

	i = strlen(upddb);
	ppath = malloc(i + 10);
	fpath = malloc(i + 30);
	ppath = strcpy(ppath, upddb);
	sprintf(ppath + i, "%u", (unsigned int) prod);
	vstr = malloc(20);
	sprintf(vstr, "%llu", (long long unsigned int) ver);
       	num_upds = scandir(ppath, &updates, is_patch_needed, versionsort);
	ppath = strcat(ppath, "/");
	for (i = 0; i<num_upds; i++) {
		fpath = strcpy(fpath, ppath);
		fpath = strcat(fpath, updates[i]->d_name);
		push_update(session, fpath);
	}
}

void *apds_proto_thread(void *ssd) {
	int err, ret, cs, i, sd, intcnt, apdate_server_start = 1;
	unsigned char *p, *pe, *eof;
	unsigned char buffer[MAX_BUF];
	char *upd_dir;
	gnutls_session_t sess;
	struct sess_sd *tsd = (struct sess_sd *) ssd;
	struct sockaddr_in sa;
	uint32_t i32, product_tag;
	uint64_t i64, upd_req_version;

	eof = NULL;
	sd = tsd->sd;
	sess = tsd->sess;
	upd_dir = tsd->upd_dir_path;
	sa = tsd->sa;
	free(tsd);

	%%write init;

	gnutls_transport_set_ptr(sess, (gnutls_transport_ptr_t) (long) sd);
	ret = gnutls_handshake(sess);

	if (ret < 0) {
		gnutls_perror(ret);
		goto out;
	}

	i = 0;
	for (;;) {
		ret = gnutls_record_recv (sess, buffer, MAX_BUF);
		if (ret <= 0) {
			gnutls_perror(ret);
			break;
		} else {
			p = buffer;
			pe = buffer + ret;

			%%write exec;
		}
	}

out_bye:
	gnutls_bye(sess, GNUTLS_SHUT_WR);
out:
	close(sd);
	gnutls_deinit(sess);
	return;
}
