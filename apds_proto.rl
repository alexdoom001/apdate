#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apds_file_cache.h"
#include "apds_inotify.h"
#include "apds_main.h"
#include "apds_proto.h"
#include "apdate_common.h"

%%{
	machine apdate_server;
	include apdate_defs "apdate_defs.rl";

	main := (proto_ident1_pack . prod_ident_pack*) |
		(proto_ident2_pack . (certsub_pack+ . ((software_ver_pack | bases_ver_pack | personal_ver_pack
							| request_all_pack)*
						       :> ready_for_updates_pack .
						       (software_ver_pack | bases_ver_pack | personal_ver_pack
							| ping_pack | pong_pack | request_all_pack)**)));
}%%

pthread_key_t apds_key;

extern int debug_print;

static char *mkpatchpath(char *upddb, struct up_prod *rq)
{
	char *res, rev[16];

	sprintf(rev, "%llu", (unsigned long long int) rq->rev);

	res = g_build_filename(upddb, rq->prod, rq->ver, rev, (char *) NULL);

	return res;
}

static int push_update(const char *fpath) {
	char fbuf[5];
	void *fpoint, *fbound;
	int ret;
	unsigned int sz;
	struct upd_map fmap;
	struct apds_session *apdss;
	double load;

	/*
	 * If this stalls for more than 10 minutes, you're in trouble and should
	 * be running for a new server
	 */

	for (sz = 0; sz < 60; sz++) {
		ret = getloadavg(&load, 1);
		if (ret != 1)
			break;
		// truncating conversion is what we want here
		if (((long int) load) < nr_cpus)
			break;
		sleep(10);
	}
	if (sz == 60)
		syslog(LOG_NOTICE, "Thread stalled for more then 10 minutes, load: %f", load);

	DEBUG(syslog(LOG_INFO, "%lli: pushing %s\n", PTH_ID, fpath));
	apdss = (struct apds_session *) pthread_getspecific(apds_key);
	fmap = get_upd_map(fpath);
	if (fmap.mmap == NULL) {
		syslog(LOG_ERR, "%lli: failed to get map for %s\n", PTH_ID, fpath);
		return -10000;
	}

	sz = htobe32((unsigned int) fmap.size);
	fbuf[0] = 2;
	memcpy(fbuf + 1, &sz, 4);
	ret = gnutls_record_send(apdss->sess, fbuf, 5);
	if (ret < 0) {
		syslog(LOG_INFO, "%lli: failed to send header\n", PTH_ID);
		goto push_out;
	}

	fbound = fmap.mmap + fmap.size;
	for (fpoint = fmap.mmap; fpoint < fbound; fpoint += MAX_BUF) {
		sz = (((fpoint + MAX_BUF) < fbound) ? MAX_BUF : fbound - fpoint);
		ret = gnutls_record_send(apdss->sess, fpoint, sz);
		if (ret < 0) {
			syslog(LOG_INFO, "%lli: failed to send data\n", PTH_ID);
			break;
		}
		ret = 0;
	}

push_out:
	release_upd_file(fmap);
	return ret;
}

static int push_inotify_update(const int wd) {
	int len, i = 0, ret = 0;
	char buf[INOTIFY_BUF];
	struct apds_session *apdss = (struct apds_session *)
		pthread_getspecific(apds_key);

	len = read(wd, buf, INOTIFY_BUF);
	if (len < 0) {
		perror("Inotify read failed");
	}
	if (len == INOTIFY_BUF)
		syslog(LOG_WARNING, "%lli: read %d bytes from inotify which is max",
		       PTH_ID, len);
	while (i < len) {
		char *fname = (char *) &buf[i];
		int j;

		for (j = 0; j < apdss->reqs->len; j++)
			if (strcmp(fname, g_array_index(apdss->reqs, char *,
							j)) == 0) {
				ret = push_update(fname);
				free(g_array_index(apdss->reqs, char *, j));
				g_array_remove_index(apdss->reqs, j);
				break;
			}
		if (ret != 0)
			break;
		i += strlen(fname) + 1;
	}
	return ret;
}

static int add_or_upd_request(const char *chanreq, const char *chandir) {
	int j = -1, already_there = 0;
	char *d = NULL, *reqreal = NULL, *dirreal = NULL, *fname = NULL;
	struct apds_session *apdss = (struct apds_session *)
		pthread_getspecific(apds_key);

	/* There might be symlinks in paths, resolve that */
	fname = g_path_get_basename(chanreq);
	if (fname == NULL)
		goto out_ret;

	dirreal = realpath(chandir, dirreal);
	if (dirreal == NULL)
		goto out_fn;

	reqreal = g_build_filename(dirreal, fname, NULL);
	if (reqreal == NULL)
		goto out_dir;

	for (j = 0; j < apdss->reqs->len; j++) {
		if (strcmp(reqreal, g_array_index(apdss->reqs, char *, j)) == 0) {
			already_there = 1;
			break;
		}
		d = g_path_get_dirname(g_array_index(apdss->reqs, char *, j));
		if (strcmp(dirreal, d) == 0) {
			free(d);
			syslog(LOG_DEBUG, "%lli: Updating request %s to %s",
			       PTH_ID, g_array_index(apdss->reqs, char *, j), reqreal);
			if (apdss->got_ready_to_roll) {
				if (inotify_unsub(j) != 0)
					THREAD_ERR("inotify_unsub err in add_or_upd_request");
			} else {
				free(g_array_index(apdss->reqs, char *, j));
				g_array_remove_index(apdss->reqs, j);
			}
			break;
		} else
			free(d);
	}
	if (!already_there) {
		g_array_append_val(apdss->reqs, reqreal);
		reqreal = NULL;
		j = apdss->reqs->len - 1;
	}

	while (1 == 0) {
out_bye:
		j = -1;
	}

	free(reqreal);
out_dir:
	free(dirreal);
out_fn:
	free(fname);
out_ret:
	return j;
}

static int try_or_inotify_req(int index) {
	struct apds_session *apdss = (struct apds_session *)
		pthread_getspecific(apds_key);
	char *chanreq = g_array_index(apdss->reqs, char *, index);

	if (apdss->got_ready_to_roll) {
		if (access(chanreq, R_OK) == 0) {
			if (push_update(chanreq) != 0)
				THREAD_ERR("failed to push update in try_or_inotify_req");
			free(chanreq);
			g_array_remove_index(apdss->reqs, index);

			return 1;
		} else {
			if (inotify_sub(chanreq) != 0)
				THREAD_ERR("failed to subscribe in try_or_inotify_req");
			/* Look for create/watch race */
			if (access(chanreq, R_OK) == 0) {
				if (push_update(chanreq) != 0)
					THREAD_ERR("failed to push update in try_or_inotify_req");
				if (inotify_unsub(index) != 0)
					THREAD_ERR("failed to inotify_unsub in try_or_inotify_req");
				return 1;
			}
		}
	}
	return 0;
out_bye:
	return -1;
}

void apds_init_pthread_keys(void)
{
	pthread_key_create(&apds_key, NULL);
}

void apds_deinit_pthread_keys(void)
{
	pthread_key_delete(apds_key);
}

void *apds_proto_thread(void *ssd) {
	int ret, cs, i, sd, intcnt;
	unsigned int status;
	unsigned char *p, *pe, *ts, *fmap = NULL;
	char *product, *version;
	unsigned char buffer[MAX_BUF];
	char *version_string = NULL, *product_path = NULL;
	struct apds_session apdss;
	struct sockaddr_in sa;
	uint64_t i64, revision, i64tmp;
	uint32_t i32, en_byte_count = 0, en_length = 0;
	gnutls_datum_t tlsdata;
	gnutls_x509_crt_t *tlscrt = NULL;
	gnutls_session_t session;

	// Not interested in any kind of joining here
	pthread_detach(pthread_self());

	sd = ((struct sess_sd *) ssd)->sd;
	apdss.sess = ((struct sess_sd *) ssd)->sess;
	session = apdss.sess;
	sa = ((struct sess_sd *) ssd)->sa;
	free(ssd);
	apdss.reqs = g_array_new(FALSE, FALSE, sizeof(char *));
	apdss.types = g_array_new(FALSE, FALSE, sizeof(char *));
	apdss.i_wfd = -1;
	apdss.i_rfd = -1;
	apdss.serial = NULL;
	apdss.product = NULL;
	apdss.got_ready_to_roll = 0;
	pthread_setspecific(apds_key, &apdss);

	%%write data;
	%%write init;

	/* These are produced by Ragel and GCC doesn't like them */
	(void)apdate_server_en_main;
	(void)apdate_server_first_final;

	gnutls_transport_set_ptr(apdss.sess, (gnutls_transport_ptr_t) (long) sd);
	ret = gnutls_handshake(apdss.sess);
	DEBUG(syslog(LOG_DEBUG, "%lli: connection from %s\n", PTH_ID,
		     inet_ntop(AF_INET, &sa.sin_addr, (char *) buffer,
			       MAX_BUF)));

	if (ret < 0) {
		syslog(LOG_ERR, "%lli: %s", PTH_ID, gnutls_strerror(ret));
		goto out;
	}
	ret = gnutls_certificate_verify_peers2(apdss.sess, &status);
	if (ret < 0) {
		syslog(LOG_ERR, "%lli: Error verifying client certificate", PTH_ID);
		goto out_bye;
	}
	if (status & GNUTLS_CERT_INVALID) {
		syslog(LOG_ERR, "%lli: Untrusted peer certificate", PTH_ID);
		goto out_bye;
	}
	i = 0;
	for (;;) {
		struct pollfd ufds[2];
		ufds[0].fd = sd;
		ufds[0].events = POLLIN;
		if (apdss.i_rfd > 0) {
			ufds[1].fd = apdss.i_rfd;
			ufds[1].events = POLLIN;
		}
		
		/* 10 minutes before ping-pong */
		ret = poll(ufds, (apdss.i_rfd > 0 ? 2 : 1), 10 * 60 * 1000);
		if (ret < 0) {
			perror("Poll failed\n");
			goto out;
		}
		if (ret == 0) {
			char fbuf[2];
			
			DEBUG(syslog(LOG_DEBUG, "%lli: timeout, sending ping", PTH_ID));

			fbuf[0] = 5;
			fbuf[1] = 0;
			ret = gnutls_record_send(session, fbuf, 2);
			if (ret < 0) {
				syslog(LOG_INFO, "%lli: failed to send ping\n", PTH_ID);
				goto out_bye;
			}
		} else {
			if (ufds[0].revents & POLLIN) {
				ret = gnutls_record_recv(apdss.sess, buffer, MAX_BUF);
				if (ret < 0) {
					syslog(LOG_ERR, "%lli: %s", PTH_ID, gnutls_strerror(ret));
					goto out;
				} else if (ret == 0) {
					DEBUG(syslog(LOG_INFO, "%lli: Connection closed by peer", PTH_ID));
					goto out;
				} else {
					p = buffer;
					pe = buffer + ret;
					%%write exec;
					if (cs == apdate_server_error) {
						syslog(LOG_ERR, "%lli: State machine error (incompatible client proto?)", PTH_ID);
						goto out_bye;
					}
					if (ret < 0) {
						if (ret != -10000)
							syslog(LOG_ERR, "%lli: %s", PTH_ID, gnutls_strerror(ret));
						else
							syslog(LOG_ERR, "%lli: Unrecoverable internal error", PTH_ID);
						goto out;
					}
				}
			} else if (ufds[0].revents & (POLLERR | POLLHUP)) {
				syslog(LOG_WARNING, "%lli: poll() error", PTH_ID);
				goto out;
			} else if ((apdss.i_rfd > 0) && (ufds[1].revents & POLLIN)) {
				ret = push_inotify_update(apdss.i_rfd);
				if (ret < 0) {
					if (ret != -10000)
						syslog(LOG_ERR, "%lli: %s", PTH_ID, gnutls_strerror(ret));
					goto out;
				}
			} else if ((apdss.i_rfd > 0) && (ufds[1].revents & (POLLERR | POLLHUP))) {
				syslog(LOG_ERR, "%lli: Inotify client failure", PTH_ID);
				goto out;
			}
			else
				syslog(LOG_WARNING, "%lli: Spurious poll return!", PTH_ID);
		}
	}

out_bye:
	gnutls_bye(apdss.sess, GNUTLS_SHUT_WR);
out:
	if (apdss.i_rfd > 0)
		for (i = apdss.reqs->len - 1; i >= 0; i--)
			inotify_unsub(i);
	else
		for (i = 0; i < apdss.reqs->len; i++)
			free(g_array_index(apdss.reqs, char *, i));
	for (i = 0; i < apdss.types->len; i++)
		free(g_array_index(apdss.types, char *, i));

	free(fmap);
	free(version_string);
	free(product_path);
	free(apdss.serial);
	free(apdss.product);
	g_array_free(apdss.reqs, TRUE);
	g_array_free(apdss.types, TRUE);
	close(sd);
	gnutls_deinit(apdss.sess);
	DEBUG(syslog(LOG_DEBUG, "%lli: connection closed\n", PTH_ID));
	return NULL;
}
