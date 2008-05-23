#ifndef APDATE_CLIENT_H
#define APDATE_CLIENT_H

#include <db.h>
#include <byteswap.h>
#include <gnutls/gnutls.h>
#include <stdint.h>
#include <glib.h>

#define APD_VER_LEN 32

#define VR_STATE_OK 0
#define VR_STATE_UPDATE_FAILED 1

struct ver_rec {
	uint64_t main;
	uint64_t rev;
	uint64_t state;
};

int get_ver_rec_from_db(DB *dbp, char *key, struct ver_rec *vr);
int put_ver_rec_to_db(DB *dbp, char *key, struct ver_rec *vr);
int rm_db_key(DB *dbp, char *key);
DB* openverdb(char *dbname, int flags);

GArray* get_db_list(char *dbtype);

char *get_device_sn();

extern char* verfile, *dbpath, *certfile;

#endif
