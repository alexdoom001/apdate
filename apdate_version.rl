/*
 * version file parsing
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "apdate_version.h"

%%{

machine apdate_version;

alphtype char;

action mark_ts {
	ts = p;
}

action token_alloc {
	token = malloc(p - ts + 1);
	token = memcpy(token, ts, p - ts);
	token[p - ts] = '\0';
}

action get_update_type {
	version->type = token;
}

action get_product {
	if (product_count == max_product_count) {
		max_product_count *= 2;
		version->product = realloc(version->product,
					   PRODUCT_LIST_MEMSIZE(
						   max_product_count));
		if (version->product == NULL) {
			printf("version->product realloc failed\n");
			exit(79);
		}
		memset(version->product + PRODUCT_LIST_MEMSIZE(
			       max_product_count / 2), 0,
		       PRODUCT_LIST_MEMSIZE(PRODUCT_LIST_STEP));
	}
	version->product[product_count].str = token;
}

action get_timestamp {
	version->timestamp = atoll(token);
	free(token);
}

action get_product_code {
	version->product[product_count].code = atoll(token);
	free(token);
}

action finish_product_line {
	product_count++;
}

action suicide {
	fprintf(stderr, "Bad version file @%ld\n", (long int) (p - data));
	fhold;
}

update_mark = ("KAS_AV" | "KAS_AS" | "CLAMAV" | "SPAMASSASSIN" | "SQUIDGUARD" |
	       "SNORT" | "RESOLV" | "CERT") >mark_ts %token_alloc;
eol = "\n";
date = digit+ >mark_ts %token_alloc;
code = digit+ >mark_ts %token_alloc %get_product_code;
product = ((print - ':')+) >mark_ts %token_alloc %get_product;

update_type_str = update_mark . eol @get_update_type;
date_str = date . eol @get_timestamp;
product_str = product . (':' . code)? . eol @finish_product_line;
version_file = update_type_str . (date_str | eol) . (product_str+);

  main := version_file $err(suicide);

}%%

struct version_content *apdate_parse_version(char *data, size_t data_len)
{
	char *p, *pe, *token, *ts, *eof;
	struct version_content *version;
	unsigned int i, product_count = 0, max_product_count = 0;
	int cs;

	if (data == NULL)
		return NULL;

	version = malloc(sizeof(struct version_content));
	memset(version, '\0', sizeof(struct version_content));
	p = data;
	pe = data + data_len;
	eof = pe;

	%%write data;
	%%write init;
	%%write exec;
	if (cs != apdate_version_first_final) {
		for (i = 0; i < product_count; i++) {
			free(version->product[i].str);
		}
		free(version->product);
		free(version->type);
		free(version);
		version = NULL;
	} else {
		version->pr_cnt = product_count;
	}

	return version;
}
