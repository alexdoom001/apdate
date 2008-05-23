#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "apdate_client.h"
#include "apdc_proto.h"
#include "apdc_main.h"
#include "apdc_proto.h"

%%{
	machine apdate_client;
	include apdate_defs "apdate_defs.rl";

	main := (upd_push_pack | cl_cert_up_pack | ping_pack | pong_pack)*;
}%%

static gnutls_datum_t mk_request_pk(struct chan_rev request, char type) {
	char *w;
	gnutls_datum_t b;
	unsigned int chlen;

	chlen = strlen(request.channel);

	if (type == PTYPE_BASES && request.state == VR_STATE_UPDATE_FAILED) {
		/* Some bases failed to upgrade, request recovery */
		b.size = 1 + sizeof(uint32_t) + chlen;
		b.data = malloc(b.size);
		if (b.data != NULL) {
			b.data[0] = 7;
			*((uint32_t *) &(b.data[1])) = htobe32((uint32_t)chlen);
			mempcpy(&(b.data[1+sizeof(uint32_t)]), request.channel, chlen);
		}
	} else {
		b.size = 2 + sizeof(uint32_t) + chlen + sizeof(uint64_t);
		if (type == PTYPE_SOFTWARE)
			b.size += sizeof(uint64_t);
		b.data = malloc(b.size);
		if (b.data != NULL) {
			/* channel version packet */
			b.data[0] = 6;
			b.data[1] = type;
			*((uint32_t *) &(b.data[2])) = htobe32((uint32_t)chlen);
			w = mempcpy(&(b.data[2+sizeof(uint32_t)]), request.channel, chlen);
			*((uint64_t *) w) = htobe64(request.main);
			if (type == PTYPE_SOFTWARE) {
				w += sizeof(uint64_t);
				*((uint64_t *) w) = htobe64(request.rev);
			}
		}
	}

	return b;
}

static int send_request_pk(gnutls_session_t session, struct chan_rev request, char type) {
	gnutls_datum_t b;
	int ret;

	b = mk_request_pk(request, type);
	if (b.data == NULL)
		ret = APDC_UNRECOVERABLE_ERROR;
	else {
		ret = gnutls_record_send(session, b.data, b.size);
		DEBUG(syslog(LOG_DEBUG, "Send req for channel %s, version: %llu/%llu",
			     request.channel, (unsigned long long int) request.main,
			     (unsigned long long int) request.rev));
		free(b.data);
	}
	return ret;
}

static int send_proto_pk(gnutls_session_t session) {
	char buffer[2];

	buffer[0] = 0;
	buffer[1] = PROTO_VERSION;

	return gnutls_record_send(session, buffer, 2);
}

static int send_ready_pk(gnutls_session_t session) {
	char buffer[2];

	buffer[0] = 5;
	buffer[1] = 2;

	return gnutls_record_send(session, buffer, 2);
}

static int send_requests(gnutls_session_t session, GArray **old_reqs, char *dbtype, int type)
{
	int i, j, ret = 0;
	GArray *req_list;

	req_list = get_db_list(dbtype);
	if (req_list != NULL) {
		for (i = req_list->len - 1; i >= 0; i--) {
			if (*old_reqs != NULL) {
				int skip = 0;
				for (j = (*old_reqs)->len - 1; j >= 0; j--)
					if (strcmp(g_array_index(req_list, struct chan_rev, i).channel,
						   g_array_index(*old_reqs, struct chan_rev, j).channel) == 0 &&
					    g_array_index(req_list, struct chan_rev, i).main == 
					    g_array_index(*old_reqs, struct chan_rev, j).main &&
					    g_array_index(req_list, struct chan_rev, i).state == 
					    g_array_index(*old_reqs, struct chan_rev, j).state &&
					    g_array_index(*old_reqs, struct chan_rev, j).rev ==
					    g_array_index(req_list, struct chan_rev, i).rev) {
						skip = 1;
						break;
					}
				if (skip)
					continue;
			}
			ret = send_request_pk(session, g_array_index(req_list, struct chan_rev, i), type);
			if (ret == APDC_UNRECOVERABLE_ERROR)
				return APDC_UNRECOVERABLE_ERROR;
			HANDLE_TLS_ERR;
		}
	} else
		return -4500;

	if (*old_reqs != NULL) {
		for (j = (*old_reqs)->len - 1; j >= 0; j--)
			free(g_array_index(*old_reqs, struct chan_rev, j).channel);
		g_array_free(*old_reqs, TRUE);
	}
	*old_reqs = req_list;

	return 0;
out_bye:
	return -4500;
}

static int send_request_list(gnutls_session_t session, GArray **sw_reqs, GArray **bs_reqs, GArray **ps_reqs) {
	if (send_requests(session, sw_reqs, "software", PTYPE_SOFTWARE) != 0 ||
	    send_requests(session, bs_reqs, "bases", PTYPE_BASES) != 0 ||
	    send_requests(session, ps_reqs, "personal", PTYPE_PERSONAL) != 0)
		return -4500;
	else
		return 0;
}

static int send_certs(gnutls_session_t session) {
	char *fname, *map, *fbound, *fpoint, fbuf[5];
	int i, j, mapsize, fd, ret = 0;
	uint32_t sz;
	struct dirent **dirnames;

	i = scandir(certsdir, &dirnames, NULL, alphasort);
	if (i < 0) {
		return 9834;
	} else if (i == 0) {
		return 9835;
	}
	for (j = 0; j < i; j++) {
		if (strcmp(dirnames[j]->d_name, ".") == 0 ||
		    strcmp(dirnames[j]->d_name, "..") == 0) {
			free(dirnames[j]);
			continue;
		}
		if ((fname = g_build_filename(certsdir, dirnames[j]->d_name,
					      NULL)) == NULL) {
			ret = 123323;
			continue;
		}
		free(dirnames[j]);
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			ret = 12222;
			free(fname);
			continue;
		}

		/* Get file size*/
		if ((mapsize = lseek(fd, 0, SEEK_END)) < 0 || lseek(fd, 0, SEEK_SET)
		    != 0) {
			close(fd);
			ret = 2121212;
			free(fname);
			continue;
		}
		if (mapsize > 102400) {
			syslog(LOG_WARNING, "File %s too big", fname);
			close(fd);
			free(fname);
			ret = 2121212;
			continue;
		}
		free(fname);
			
		map = mmap(NULL, mapsize, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
		if (map == MAP_FAILED) {
			close(fd);
			ret = 2222;
			continue;
		}
		sz = htobe32((unsigned int) mapsize);
		/* Certificate subscription packet type */
		fbuf[0] = 4;
		memcpy(fbuf + 1, &sz, 4);
		ret = gnutls_record_send(session, fbuf, 5);
		if (ret < 0) {
			munmap(map, mapsize);
			close(fd);
			continue;
		}

		fbound = map + mapsize;
		for (fpoint = map; fpoint < fbound; fpoint += MAX_BUF) {
			sz = (((fpoint + MAX_BUF) < fbound) ? MAX_BUF : fbound - fpoint);
			ret = gnutls_record_send(session, fpoint, sz);
			if (ret < 0)
				break;
			ret = 0;
		}

		munmap(map, mapsize);
		close(fd);
	}
	free(dirnames);
	return ret;
}

int apdc_proto(gnutls_session_t session) {
	int ret, cs, recvfile = 0, intcnt = 0;
	unsigned int status;
	unsigned char *p, *pe, *fmap;
	char *runcmd;
	char *tname = malloc(strlen(TMP_FILE_PATTERN)+1);
	unsigned char buffer[MAX_BUF + 1];
	uint32_t i32, en_byte_count = 0, en_length = 0;
	GArray *sw_reqs = NULL, *bs_reqs = NULL, *ps_reqs = NULL;

	%%write data;
	%%write init;

	/* GCC complains about these being unused */
	(void) apdate_client_en_main;
	(void) apdate_client_first_final;
	ret = gnutls_handshake(session);
	if (ret < 0) {
		syslog(LOG_ERR, "Error in TLS: %s", gnutls_strerror(ret));
		goto out_bye;
	}
	DEBUG(syslog(LOG_DEBUG, "TLS connection established"));

	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		syslog(LOG_ERR, "Server cert verification fail");
		goto out_bye;
	}
	if (status & GNUTLS_CERT_INVALID) {
		syslog(LOG_ERR, "Invalid cerver cert");
		ret = 1;
		goto out_bye;
	}
	DEBUG(syslog(LOG_DEBUG, "Server cert is OK"));
	ret = send_proto_pk(session);
	HANDLE_TLS_ERR;
	ret = send_certs(session);
	HANDLE_TLS_ERR;
	ret = send_request_list(session, &sw_reqs, &bs_reqs, &ps_reqs);
	HANDLE_TLS_ERR;
	ret = send_ready_pk(session);
	HANDLE_TLS_ERR;
	while (1) {
		ret = gnutls_record_recv(session, buffer, MAX_BUF);
		if (ret == 0) {
			syslog(LOG_NOTICE, "TLS closed by the peer");
			goto out_bye;
		} else HANDLE_TLS_ERR;

		p = buffer;
		pe = buffer + ret;

		%%write exec;
		if (cs == apdate_client_error) {
			ret = 1;
			goto out_bye;
		}
	}
out_bye:
	free(tname);
	return ret;
}
