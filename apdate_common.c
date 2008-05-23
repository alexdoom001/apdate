/*
 * variation on libmisc theme
 */

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

#include "apdate_common.h"

/* 
 * Helper functions to load a certificate and key
 * files into memory.
 */
gnutls_datum_t load_file(const char *file)
{
	FILE *f;
	gnutls_datum_t loaded_file = { NULL, 0 };
	long filelen;
	void *ptr;

	if (!(f = fopen(file, "r")))
		goto lfout;
	if (fseek(f, 0, SEEK_END) != 0
	    || (filelen = ftell(f)) < 0
	    || fseek(f, 0, SEEK_SET) != 0
	    || !(ptr = malloc((size_t) filelen)))
		goto lfout_1;
	if (fread(ptr, 1, (size_t) filelen, f) < (size_t) filelen) {
		free(ptr);
		goto lfout_1;
	}
	loaded_file.data = ptr;
	loaded_file.size = (unsigned int) filelen;
lfout_1:
	fclose(f);
lfout:
	return loaded_file;
}

void unload_file (gnutls_datum_t data)
{
	free(data.data);
}

int load_certificate_ram(gnutls_x509_crt_t **crt, gnutls_datum_t data)
{
	unsigned int ncerts = 16;

	*crt = malloc(ncerts*sizeof(gnutls_x509_crt_t));
	if (*crt == NULL)
		return -1;

	if (gnutls_x509_crt_list_import(*crt, &ncerts, &data,
					GNUTLS_X509_FMT_PEM,
					GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED) < 0) {
		free(*crt);
		*crt = NULL;
		return -1;
	}
	return ncerts;
}

int load_certificate(gnutls_x509_crt_t **crt, const char *path)
{
	int ret;
	gnutls_datum_t data;

	data = load_file(path);
	if (data.data == NULL)
		return -1;

	ret = load_certificate_ram(crt, data);
	unload_file(data);
	return ret;
}

gnutls_x509_privkey_t *load_privkey(const char *path)
{
	int ret;
	gnutls_x509_privkey_t *key;
	gnutls_datum_t data;

	key = malloc(sizeof(gnutls_x509_privkey_t));
	if (key == NULL)
		return NULL;

	data = load_file(path);
	if (data.data == NULL) {
		free(key);
		return NULL;
	}
	ret = gnutls_x509_privkey_init(key);
	if (ret != GNUTLS_E_SUCCESS) {
		free(key);
		unload_file(data);
		return NULL;
	}
	ret = gnutls_x509_privkey_import(*key, &data, GNUTLS_X509_FMT_PEM);
	unload_file(data);
	if (ret < 0) {
		free(key);
		return NULL;
	}
	return key;
}

char *strconcat(const char *s1, const char *s2)
{
	char *res;
	int i;

	i = strlen(s1);

	res = malloc(i + strlen(s2) + 1);
	if (res == NULL)
		return NULL;

	strcpy(res, s1);
	strcpy(res + i, s2);

	return res;
}

gnutls_x509_crt_t *load_calist(const char *path, unsigned int *calist_size) {
	int ret;
	gnutls_x509_crt_t *crts;
	gnutls_datum_t data;

	*calist_size = 10;
	crts = malloc(*calist_size * sizeof(gnutls_x509_crt_t));
	data = load_file(path);
	if (data.data == NULL) {
		free(crts);
		return NULL;
	}

	ret = gnutls_x509_crt_list_import(crts, calist_size, &data,
					  GNUTLS_X509_FMT_PEM, 0);
	unload_file(data);
	if (ret < 0) {
		free(crts);
		return NULL;
	}
	return crts;
}

gnutls_x509_crl_t *load_crl(const char *path) {
	int ret;
	gnutls_x509_crl_t *crl = malloc(sizeof(gnutls_x509_crl_t));
	gnutls_datum_t data;

	data = load_file(path);
	if (data.data == NULL) {
		free(crl);
		return NULL;
	}
	gnutls_x509_crl_init(crl);
	ret = gnutls_x509_crl_import(*crl, &data, GNUTLS_X509_FMT_PEM);
	unload_file(data);
	if (ret != GNUTLS_E_SUCCESS) {
		free(crl);
		return NULL;
	}
	return crl;
}

int check_cert_field(const char *str, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (!(isdigit(str[i]) || isalpha(str[i]) ||
		      str[i] == ' ' || str[i] == '.' || str[i] == '_' ||
		      // \r workarounds buggy product names with \r
		      str[i] == '-' || str[i] == '\r'))
			return 1;
	return 0;
}

char *get_cert_field_by_oid(gnutls_x509_crt_t crt, const char *oid, const int check)
{
	char buf[OIDBUF_SIZE];
	size_t bsize = OIDBUF_SIZE;

	if (gnutls_x509_crt_get_dn_by_oid(crt, oid, 0, 0, buf,
					  &bsize) != 0) {
		syslog(LOG_ERR, "Error getting OID %s from cert", oid);
		return NULL;
	}
	if (bsize >= OIDBUF_SIZE) {
		syslog(LOG_ERR, "Too small buffer for OID %s", oid);
	} 
	if (check && (check_cert_field(buf, bsize) != 0)) {
		syslog(LOG_ERR, "Bad symbols in OID %s", oid);
		return NULL;
	}
	buf[bsize] = '\0';
	return strdup(buf);
}
