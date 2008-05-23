#ifndef APDS_MAIN_H
#define APDS_MAIN_H 1

#include "apdate_common.h"

#define TLS_SESSION_CACHE 8192
#define ETC_PREFIX "/etc/apds/"

#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

#define APDSCONF ETC_PREFIX "apds.conf"
#define APDS_UNRECOVERABLE_ERROR -10000

extern char *upddb;
extern long int nr_cpus;
extern unsigned int calist_size;
extern gnutls_x509_crt_t *calist;
extern gnutls_x509_crl_t *crl;
extern int debug_print;

extern pthread_barrier_t initbarrier;

#endif
