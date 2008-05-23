#ifndef APDP_VERSION_H
#define APDP_VERSION_H 1

#include <stdint.h>
#include "apdate_common.h"

#define APDATE_TYPE_SOFTWARE	0
#define APDATE_TYPE_SOFTWARE_HF	1
#define APDATE_TYPE_BASES	2
#define APDATE_TYPE_BASES_ALL	3
#define APDATE_TYPE_PERSONAL	4

struct apdate_file {
	uint32_t filetype;
	char *type;
	char *channel;
	char *description;
	uint64_t rev_from;
	uint64_t rev_to;
	uint64_t timestamp;
	gnutls_datum_t certificate;
	gnutls_datum_t apfile;
	gnutls_datum_t signed_content;
	gnutls_datum_t signature;
};

struct apdate_file *apdate_parse_file(char *data, size_t data_len);

#endif
