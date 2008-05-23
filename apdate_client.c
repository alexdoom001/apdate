#include <ctype.h>
#include <db.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "apdate_client.h"
#include "apdate_common.h"

int get_ver_rec_from_db(DB *dbp, char *key, struct ver_rec *vr) {
	DBT dbkey, dbdata;
	int ret;

	memset(&dbkey, 0, sizeof(dbkey));
	memset(&dbdata, 0, sizeof(dbdata));
	dbkey.data = key;
	dbkey.size = strlen(key);
	ret = dbp->get(dbp, NULL, &dbkey, &dbdata, 0);
	if (ret == 0) {
		vr->main = be64toh(((struct ver_rec *) dbdata.data)->main);
		vr->rev = be64toh(((struct ver_rec *) dbdata.data)->rev);
		vr->state = be64toh(((struct ver_rec *) dbdata.data)->state);
	}

	return ret;
}

int put_ver_rec_to_db(DB *dbp, char *key, struct ver_rec *vr) {
	DBT dbkey, dbdata;
	struct ver_rec tvr;

	memset(&dbkey, 0, sizeof(dbkey));
	memset(&dbdata, 0, sizeof(dbdata));
	dbkey.data = key;
	dbkey.size = strlen(key);
	tvr.main = htobe64(vr->main);
	tvr.rev = htobe64(vr->rev);
	tvr.state = htobe64(vr->state);
	dbdata.data = &tvr;
	dbdata.size = sizeof(tvr);
	return dbp->put(dbp, NULL, &dbkey, &dbdata, 0);
}

int rm_db_key(DB *dbp, char *key) {
	DBT dbkey;

	memset(&dbkey, 0, sizeof(dbkey));
	dbkey.data = key;
	dbkey.size = strlen(key);
	return dbp->del(dbp, NULL, &dbkey, 0);
}

DB* openverdb(char *dbname, int flags) {
	DB *dbp = NULL;

	if (verfile == NULL)
		return NULL;
	if (dbname == NULL)
		return NULL;

	if (db_create(&dbp, NULL, 0) != 0)
		return NULL;

	if (dbp->open(dbp, NULL, verfile, dbname, DB_BTREE, flags, 0) != 0)
		return NULL;
	return dbp;
}

GArray* get_db_list(char *dbtype) {
	char *verfile;
	int i;
	struct chan_rev req;
	GArray *req_list;
	DB *dbp;
	DBC *dbc;
	DBT key, data;

	req_list = g_array_new(FALSE, FALSE, sizeof(struct chan_rev));
	if (req_list == NULL) {
		syslog(LOG_ERR, "g_array_new failure in get_db_list(), OOM?");
		goto chk_fail_0;
	}

	verfile = g_build_filename(dbpath, "version.db", (char *) NULL);
	if (verfile == NULL) {
		syslog(LOG_ERR, "g_build_filename failure in get_db_list(), OOM?");
		goto chk_fail_1;
	}
	if (db_create(&dbp, NULL, 0) != 0) {
		syslog(LOG_ERR, "db_create fail in get_db_list(), OOM?");
		goto chk_fail_2;
	}
	if (dbp->open(dbp, NULL, verfile, dbtype, DB_BTREE, DB_RDONLY, 0) != 0) {
		syslog(LOG_ERR, "dbpr->open() fail in get_db_list()");
		goto chk_fail_3;
	}
	if (dbp->cursor(dbp, NULL, &dbc, 0) != 0) {
		syslog(LOG_ERR, "dbph->cursor() fail in get_db_list()");
		goto chk_fail_3;
	}
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	while((i = dbc->get(dbc, &key, &data, DB_NEXT)) == 0) {
		if (data.size != sizeof(struct ver_rec)) {
			syslog(LOG_ERR, "DB corrupted, data has %d bytes", data.size);
			goto chk_fail_3;
		}
		req.channel = malloc(key.size + 1);
		if (req.channel == NULL) {
			syslog(LOG_ERR, "malloc(req.channel) failed in get_db_list, OOM?");
			goto chk_fail_3;
		}
		memcpy(req.channel, key.data, key.size);
		req.channel[key.size] = 0;
		req.main = be64toh(((struct ver_rec *) data.data)->main);
		req.rev = be64toh(((struct ver_rec *) data.data)->rev);
		req.state = be64toh(((struct ver_rec *) data.data)->state);
		g_array_append_val(req_list, req);
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
	}
	if (i != DB_NOTFOUND) {
		syslog(LOG_ERR, "dbc->get() fail in get_db_list()");
		goto chk_fail_3;
	}
	dbc->close(dbc);
	dbp->close(dbp, 0);
	free(verfile);

	return req_list;

chk_fail_3:
	dbp->close(dbp, 0);
chk_fail_2:
	free(verfile);
chk_fail_1:
	g_array_free(req_list, TRUE);
chk_fail_0:
	return NULL;
}

char *get_device_sn()
{
	char *res = NULL;
	gnutls_x509_crt_t *tlscrt = NULL;

	if (load_certificate(&tlscrt, certfile) > 0)
		res = get_cert_field_by_oid(tlscrt[0], "2.5.4.5", 1);
	free(tlscrt);

	return res;
}
