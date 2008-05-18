/*
 * Parses products name<->code description file
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "apdate_products.h"

%%{

machine apdate_products;

alphtype char;

action mark_ts {
	ts = p;
}

action token_alloc {
	token = malloc(p - ts + 1);
	token = memcpy(token, ts, p - ts);
	token[p - ts] = '\0';
}

action get_product_code {
	prodcode_list->prodcode[prodcode_count++].code = (int64_t) atoi(token);
	free(token);
}

action get_product_name {
	if (prodcode_count == prodcode_maxcount) {
		prodcode_maxcount *= 2;
		prodcode_list->prodcode = realloc(prodcode_list->prodcode,
						 STRCODE_LIST_MEMSIZE(
							 prodcode_maxcount));
		if (prodcode_list->prodcode == NULL) {
			printf("Failed to reallo prodcode list, sorry");
			exit(78);
		}
	}
	prodcode_list->prodcode[prodcode_count].str = token;
}

action suicide {
	fprintf(stderr, "Bad products file @%ld\n", (long int) (p - data));
	fhold;
}

product_name = ((print - ':')+) >mark_ts %token_alloc %get_product_name;
product_code = (digit+) >mark_ts %token_alloc %get_product_code;
product_string = product_name . ':' . product_code '\n';
product_file = product_string+;

  main := product_file $err(suicide);

}%%

struct prcode_list *apdate_parse_product_list(char *data, size_t data_len)
{
	char *p, *pe, *token, *ts, *eof;
	struct prcode_list *prodcode_list;
	unsigned int i, prodcode_count = 0, prodcode_maxcount = 0;
	int cs;

	if (data == NULL)
		return NULL;

	prodcode_list = malloc(sizeof(struct prcode_list));
	prodcode_list->prodcode = NULL;

	p = data;
	pe = data + data_len;
	eof = pe;

	%%write data;
	%%write init;
	%%write exec;
	if (cs != apdate_products_first_final) {
		for (i = 0; i < prodcode_count; i++) {
			free(prodcode_list->prodcode[i].str);
		}
		free(prodcode_list->prodcode);
		free(prodcode_list);
		prodcode_list = NULL;
	} else {
		prodcode_list->size = prodcode_count;
	}

	return prodcode_list;
}
