#ifndef APDATE_COMMON_H
#define APDATE_COMMON_H

#include <byteswap.h>
#include <gnutls/gnutls.h>

#define APDS_DEF_PORT 790
#define MAX_BUF 1024
#define DH_BITS 1024
#define TMP_PREFIX "/tmp/"
#define TMP_FILE_PATTERN TMP_PREFIX "apdc-upXXXXXX"
#define TMP_DIR_PATTERN TMP_PREFIX "apdp-XXXXXX"

#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define HANDLE_TLS_ERR if (ret < 0) { \
	fprintf(stderr, "Error: %s\n", gnutls_strerror(ret)); \
	goto out_bye; \
	}
#define DEBUG(command) if (debug_print != 0) {command;}

#ifndef be32toh
#    define be32toh(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_32(i))
#    define htobe32(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_32(i))
#    define be64toh(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_64(i))
#    define htobe64(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_64(i))
#endif

struct string_code {
	char *str;
	int64_t code;
};

#define STRCODE_LIST_MEMSIZE(i) (i * sizeof(struct string_code))

gnutls_datum_t load_file(const char *file);
void unload_file (gnutls_datum_t data);
int get_file_lock(const char *name);
void release_file_lock(const char *name, int fd);
gnutls_x509_crt_t *load_certificate(const char *path);
gnutls_x509_privkey_t *load_privkey(const char *path);
char *strconcat(const char *s1, const char *s2);
struct string_code load_product_file(const char *fname);
int64_t strcode_get_code(struct string_code *prlist, unsigned int lsize, char *name);
char *strcode_get_name(struct string_code *prlist, unsigned int lsize, int64_t code);

#endif
