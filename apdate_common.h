#ifndef APDATE_COMMON_H
#define APDATE_COMMON_H

#include <byteswap.h>
#include <gnutls/gnutls.h>
#include <stdint.h>

#define APDS_DEF_PORT 790
#define MAX_BUF 1024
#define DH_BITS 1024
#define TMP_PREFIX "/tmp/"
#define TMP_FILE_PATTERN TMP_PREFIX "apdate-XXXXXX"
#define TMP_DIR_PATTERN TMP_PREFIX "apdate-d-XXXXXX"

#define APDATE_DB_DIR "/cfg/apdate/"

#define SOCKET_ERR(err,s) if(err==-1) {syslog(LOG_ERR, "%s: %s", s, strerror(errno)); return(1);}
#define HANDLE_TLS_ERR if (ret < 0) { \
	syslog(LOG_ERR, "%s", gnutls_strerror(ret)); \
	goto out_bye; \
	}
#define PTH_ID (long long int) pthread_self()
#define THREAD_ERR(m) {					      \
	syslog(LOG_ERR, "%lli: ERR: %s\n", PTH_ID, m); \
	goto out_bye; \
	}

#define DEBUG(command) if (debug_print != 0) {command;}

#ifndef be32toh
#    define be32toh(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_32(i))
#    define htobe32(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_32(i))
#    define be64toh(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_64(i))
#    define htobe64(i) (__BYTE_ORDER == __BIG_ENDIAN ? i : bswap_64(i))
#endif

#define APDATE_FILE_MAGIC "ApDaTE"

struct up_prod {
	char *prod;
	char *ver;
	uint64_t rev;
};

struct chan_rev {
	char *channel;
	uint64_t main;
	uint64_t rev;
	uint64_t state;
};

#define OIDBUF_SIZE 256

gnutls_datum_t load_file(const char *file);
void unload_file (gnutls_datum_t data);
int load_certificate_ram(gnutls_x509_crt_t **crt, gnutls_datum_t data);
int load_certificate(gnutls_x509_crt_t **crt, const char *path);
gnutls_x509_privkey_t *load_privkey(const char *path);
char *strconcat(const char *s1, const char *s2);
gnutls_x509_crl_t *load_crl(const char *path);
gnutls_x509_crt_t *load_calist(const char *path, unsigned int *calist_size);
char *get_cert_field_by_oid(gnutls_x509_crt_t crt, const char *oid, const int check);
int check_cert_field(const char *str, size_t size);

#endif
