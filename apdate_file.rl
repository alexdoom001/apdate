/*
 * version file parsing
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <sys/statvfs.h>

#include "apdate_file.h"

%%{

machine apdate_file;
include apdate_defs "apdate_defs.rl";

alphtype char;

action get_type {
	apdfile->type = ts;
}

action get_filetype {
	apdfile->filetype = be32toh(i32);
}

action get_channel {
	apdfile->channel = ts;
}

action get_description {
	apdfile->description = ts;
}

action get_revision {
	apdfile->rev_from = be64toh(i64);
}

action get_dest_revision {
	apdfile->rev_to = be64toh(i64);
}

action get_timestamp {
	apdfile->timestamp = be64toh(i64);
}

action get_certificate {
	apdfile->certificate.data = (unsigned char *) ts;
	apdfile->certificate.size = p - ts;
}

action get_signature {
	apdfile->signature.data = (unsigned char *) ts;
	apdfile->signature.size = p + 1 - ts;
	if (apdfile->signature.size != en_length)
		fprintf(stderr, "Error! Garbage at the end of file");
}

action get_apdate {
	apdfile->apfile.data = (unsigned char *) ts;
	apdfile->apfile.size = p - ts;
	apdfile->signed_content.size = p - (char *) apdfile->signed_content.data;
}

action suicide {
	fprintf(stderr, "Bad apdate file @%ld\n", (long int) (p - data));
	fhold;
}

magic = "ApDaTE";
version_tag = 1;
type_ = (print | space)+ >mark_ts %get_type;
type = type_ . '\0';
filetype = i32_recv @get_filetype;
channel_ = (print | space)+ >mark_ts %get_channel;
channel = channel_ . '\0';
description_ = (print | space)* >mark_ts %get_description;
description = description_ . '\0';
revision = i64_recv @get_revision;
to_revision = i64_recv @get_dest_revision;
date = i64_recv @get_timestamp;
certificate_ = (print | space)+ >mark_ts %get_certificate;
certificate = certificate_ . '\0';
en_length = i32_recv @set_elen;
apdate_ =  (any* when chk_elen) . (any when !chk_elen);
apdate = en_length . (apdate_ >mark_ts) %get_apdate;
signature_ = (any* when chk_elen) . (any when !chk_elen);
signature = en_length . (signature_ >mark_ts @get_signature);

main := magic . version_tag . filetype . type . channel . description . revision
        . to_revision . date . certificate . apdate . signature $err(suicide);

}%%

struct apdate_file *apdate_parse_file(char *data, size_t data_len)
{
	int cs;
	uint32_t i32, en_byte_count = 0, en_length = 0;
	uint64_t i64;
	char *p, *pe, *ts, *eof;
	unsigned int intcnt;
	struct apdate_file *apdfile;

	if (data == NULL)
		return NULL;

	apdfile = malloc(sizeof(struct apdate_file));
	memset(apdfile, '\0', sizeof(struct apdate_file));
	apdfile->signed_content.data = (unsigned char *) data;
	p = data;
	pe = data + data_len;
	eof = pe;

	%%write data;
	%%write init;
	/* Autoproduced by Ragel, GCC doesn't like these */
	(void) apdate_file_en_main;
	(void) apdate_file_error;
	%%write exec;
	if (cs != apdate_file_first_final) {
		fprintf(stderr, "Error reading apdate file at 0x%llx, cs: %d\n",
			(unsigned long long int) (p - data), cs);
		free(apdfile);
		apdfile = NULL;
	}

	return apdfile;
}
