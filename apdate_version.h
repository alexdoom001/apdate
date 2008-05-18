#ifndef APDP_VERSION_H
#define APDP_VERSION_H 1

#include "apdate_common.h"

#define PRODUCT_LIST_STEP 4
#define PRODUCT_LIST_MEMSIZE(i) (sizeof(struct string_code) * i)

struct version_content {
	char *type;
	unsigned long long int timestamp;
	struct string_code *product;
	unsigned int pr_cnt;
};

struct version_content *apdate_parse_version(char *data, size_t data_len);

#endif
