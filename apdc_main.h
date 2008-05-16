#include "apdate_common.h"

#define ETC_PREFIX "/etc/apdc/"
#define TMP_PREFIX "/tmp/"
#define APDCCONF ETC_PREFIX "apdc.conf"
#define VERSION_FILE "version"
#define PRODUCT_FILE "product"
#define PATCH_QUEUE_PATH "patches"
#define TMP_FILE_PATTERN TMP_PREFIX "apdc-upXXXXXX"

#define APDC_MAX_LIST 10
#define PROTO_VERSION 1
#define APDC_UNRECOVERABLE_ERROR -100000

#define HANDLE_TLS_ERR if (ret < 0) { \
	fprintf (stderr, "Error: %s\n", gnutls_strerror(ret)); \
	goto out_bye; \
	}

extern char *cafile, *verfile, *dbpath, *certfile, *keyfile, *product_string;
extern char *patch_queue_path;
extern char *apds_list[];
extern int product_code;
