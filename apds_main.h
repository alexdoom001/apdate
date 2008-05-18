#ifndef APDS_MAIN_H
#define APDS_MAIN_H 1

#include "apdate_common.h"
#include "apdate_products.h"

#define TLS_SESSION_CACHE 1024
#define ETC_PREFIX "/etc/apds/"

#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

#define APDSCONF ETC_PREFIX "apds.conf"

extern char *upddb;
extern struct prcode_list *products;

#endif
