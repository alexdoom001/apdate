#ifndef APDATE_PRODUCTS_H
#define APDATE_PRODUCTS_H 1

#include <stdint.h>
#include "apdate_common.h"

struct prcode_list {
	struct string_code *prodcode;
	unsigned int size;
};

#define PRCODE_LIST_STEP 8

struct prcode_list *apdate_parse_product_list(char *data, size_t data_len);

#endif
