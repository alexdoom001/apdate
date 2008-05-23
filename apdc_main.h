#ifndef APDC_MAIN_H
#define APDC_MAIN_H 1

#include <glib.h>
#include <stdint.h>

#include "apdate_common.h"

#define ETC_PREFIX "/etc/apdc/"
#define APDCCONF ETC_PREFIX "apdc.conf"
#define VERSION_DIR "version"
#define PRODUCT_FILE "product"
#define PATCH_QUEUE_PATH "patches"
#define STAGING_PATH "staging/"
#define STAGING_LOCK "staging.lock"

#define CWDBUFSIZE 128
#define APDC_MAX_LIST 10
#define PROTO_VERSION 2
#define REQ_LIST_SIZE 32
#define APDC_UNRECOVERABLE_ERROR -100000

extern char *cafile, *verfile, *dbpath, *certfile, *keyfile, *product_string, *certsdir, *revfile;
extern char *patch_queue_path, *crlfile, *libexec_path, *conffile_name, *upd_storage_path;
extern char *apds_list[];
extern uint32_t product_code;
extern int debug_print;

#endif
