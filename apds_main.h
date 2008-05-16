#include <gnutls/gnutls.h>
#include "apdate_common.h"

#define TLS_SESSION_CACHE 1024
#define ETC_PREFIX "/etc/apds/"

#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

#define APDSCONF ETC_PREFIX "apds.conf"

extern char *upddb;
