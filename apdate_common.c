/*
 * variation on libmisc theme
 */

#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int get_file_lock(const char *name)
{
	int fd;

	fd = open(name, O_WRONLY | O_CREAT | O_EXCL);
	while ((fd < 0) && (errno == -EEXIST)) {
		sleep(5);
		fd = open(name, O_WRONLY | O_CREAT | O_EXCL);
	}
	if (fd < 0)
		return -1;
	return fd;
}

void release_file_lock(const char *name, int fd)
{
	close(fd);
	unlink(name);
}


gnutls_x509_crt_t *load_certificate(const char *path)
{
	int ret;
	gnutls_x509_crt_t *crt;
	gnutls_datum_t data;

	crt = malloc(sizeof(gnutls_x509_crt_t));
	if (crt == NULL)
		return NULL;

	data = load_file(path);
	if (data.data == NULL) {
		free(crt);
		return NULL;
	}
	ret = gnutls_x509_crt_init(crt);
	if (ret !=  GNUTLS_E_SUCCESS) {
		free(crt);
		return NULL;
	}
	ret = gnutls_x509_crt_import(*crt, &data, GNUTLS_X509_FMT_PEM);
	unload_file(data);
	if (ret < 0) {
		free(crt);
		return NULL;
	}
	return crt;
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

struct string_code load_product_file(const char *fname)
{
	FILE *f;
	int ret;
	struct string_code strc;

	f = fopen(fname, "r");
	if (f == NULL) {
		printf("Can't read product code file '%s'", fname);
		exit(3);
	}

	ret = fscanf(f, "%lli\n%a[^\n]", (long long int *) &strc.code,
		     &strc.str);
	fclose(f);
	if (ret != 2) {
		printf("Garbage in product file '%s'\n", fname);
		exit(4);
	}
	return strc;
}

int64_t strcode_get_code(struct string_code *prlist, unsigned int lsize,
			 char *name)
{
	unsigned int i;

	for (i = 0; i < lsize; i++)
		if (strcmp(name, prlist[i].str) == 0)
			break;
	if (i == lsize)
		return 0;
	else
		return prlist[i].code;
}

char *strcode_get_name(struct string_code *prlist, unsigned int lsize,
		       int64_t code)
{
	unsigned int i;

	for (i = 0; i < lsize; i++)
		if (prlist[i].code == code)
			break;
	if (i == lsize)
		return NULL;
	else
		return prlist[i].str;

}
