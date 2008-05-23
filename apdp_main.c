/*
 * Signs an update and puts it in update DB
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if (GNUTLS_VERSION_NUMBER >= 0x021200)
#include <gnutls/abstract.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "apdate_file.h"
#include "apdp_main.h"
#include "apdate_common.h"
#include "apdp_config.h"

char *upddb, *keyfile, *certfile;

int main(int argc, char **argv)
{
	char *conffile_name = APDPCONF, *updtar = NULL, *aptype = NULL;
	char *pname, *revision = NULL, *dest_rev = NULL, *fmap, *channel = NULL, *descfile = NULL;
	char c, version_tag = 1;
	gnutls_datum_t fdata, outdata, certdata, descdata;
	gnutls_x509_crt_t *crt;
	gnutls_x509_privkey_t *key;
#if (GNUTLS_VERSION_NUMBER >= 0x020c00)
	gnutls_privkey_t newkey;
#endif
	int ret, ncerts, out, apfile, certfd, descfd = -1;
	long int l;
	uint32_t ui32, filetype = APDATE_TYPE_BASES;
	uint64_t ui64;
	gnutls_datum_t signature;

	gnutls_global_init();
	while ((c = getopt(argc, argv, "c:f:t:l:h:e:r:d:")) != -1)
	       switch (c) {
	       case 'c':
		       conffile_name = optarg;
		       break;
	       case 'f':
		       updtar = optarg;
		       break;
	       case 't':
		       aptype = optarg;
		       break;
	       case 'l':
		       if (strcmp(optarg, "sw") == 0)
			       filetype = APDATE_TYPE_SOFTWARE;
		       else if (strcmp(optarg, "hf") == 0)
			       filetype = APDATE_TYPE_SOFTWARE_HF;
		       else if (strcmp(optarg, "bases") == 0)
			       filetype = APDATE_TYPE_BASES;
		       else if (strcmp(optarg, "bases-all") == 0)
			       filetype = APDATE_TYPE_BASES_ALL;
		       else if (strcmp(optarg, "personal") == 0)
			       filetype = APDATE_TYPE_PERSONAL;
		       else {
			       fprintf(stderr, "Unsupported -l parameter\n");
			       exit(1);
		       }
		       break;
	       case 'h':
		       channel = optarg;
		       break;
	       case 'e':
		       descfile = optarg;
		       break;
	       case 'r':
		       revision = optarg;
		       break;
	       case 'd':
		       dest_rev = optarg;
		       break;
	       case '?':
		       switch (optopt) {
		       case 'c':
		       case 'f':
		       case 'p':
		       case 't':
		       case 'l':
		       case 'h':
		       case 'e':
		       case 'r':
		       case 'd':
			       fprintf(stderr, "-%c must have value.\n", optopt);
			       break;
		       default:
			       if (isprint(optopt))
				       fprintf(stderr, "Unknown parameter '-%c'.\n", optopt);
			       else
				       fprintf(stderr, "Unknow key '\\x%x'.\n", optopt);
		       }
		       /* Fallthrough */
	       default:
		       fprintf(stderr, "Usage: apdp [-c conffile] -f update \n");
		       fprintf(stderr, "       -t type -l sw|hf|bases|bases-all|personal\n");
		       fprintf(stderr, "       -h channel [-e description_file] -r revision -d dest_rev\n");
		       exit(1);
	       }

	if (updtar == NULL) {
		fprintf(stderr, "Missing mandatory update (-f) parameter\n");
		exit(99);
	}

	if (revision == NULL) {
		fprintf(stderr, "Missing mandatory revision (-r) parameter\n");
		exit(99);
	}

	if (dest_rev == NULL) {
		fprintf(stderr, "Missing mandatory destination revision (-d) parameter\n");
		exit(99);
	}

	if (dest_rev == NULL) {
		fprintf(stderr, "Missing mandatory channel (-h) parameter\n");
		exit(99);
	}

	if (aptype == NULL) {
		fprintf(stderr, "Missing mandatory apdate type (-t) parameter\n");
		exit(99);
	}

	if (conf_parse(conffile_name) != 0) {
		fprintf(stderr,"Can't read config file '%s'\n", conffile_name);
		exit(2);
	}

	gnutls_global_init();
	
	certfd = open(certfile, O_RDONLY);
	if (certfd < 0) {
		fprintf(stderr, "Error opening apdate certificate\n");
		exit(1212);
	}
	certdata.size = lseek(certfd, 0, SEEK_END);
	certdata.data = mmap(NULL, certdata.size, PROT_READ, MAP_SHARED, certfd,
			     0);
	if (certdata.data == MAP_FAILED) {
		fprintf(stderr, "Error mapping apdate certificate\n");
		close(certfd);
		exit(123);
	}

	ncerts = load_certificate_ram(&crt, certdata);
	if (ncerts <= 0) {
		fprintf(stderr, "Error loading apdate certificate\n");
		exit(1);
	}
	key = load_privkey(keyfile);
	if (key == NULL) {
		fprintf(stderr, "Error loading apdate private key\n");
		exit(2);
	}
#if (GNUTLS_VERSION_NUMBER >= 0x020c00)
	if (gnutls_privkey_init(&newkey) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error initing gnutls_privkey_t\n");
		exit(27);
	}
	if (gnutls_privkey_import_x509(newkey, *key, 0) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error converting apdate private key\n");
		exit(28);
	}
#endif
	pname = strdup(TMP_FILE_PATTERN);
	out = mkstemp(pname);
	if (out < 0) {
		fprintf(stderr, "Can't create temp output file\n");
		exit(3);
	}

	apfile = open(updtar, O_RDONLY);
	if (apfile < 0) {
		fprintf(stderr, "Error opening update file\n");
		exit(999);
	}
	fdata.size = lseek(apfile, 0, SEEK_END);
	fdata.data = mmap(NULL, fdata.size, PROT_READ, MAP_SHARED, apfile, 0);
	if (fdata.data == MAP_FAILED) {
		fprintf(stderr, "Error mapping update file\n");
		exit(483);
	}

	descdata.size = 0;
	descdata.data = NULL;
	if (descfile != NULL) {
		descfd = open(descfile, O_RDONLY);
		if (descfd < 0) {
			fprintf(stderr, "Error opening description file\n");
			exit(999);
		}
		descdata.size = lseek(descfd, 0, SEEK_END);
		if (descdata.size > 0) {
			descdata.data = mmap(NULL, descdata.size, PROT_READ, MAP_SHARED, descfd, 0);
			if (descdata.data == MAP_FAILED) {
				fprintf(stderr, "Error mapping description file\n");
				exit(483);
			}
		}
	}

	// math.ceil(math.log10(math.pow(2,40))) + 1

	/*
	 * Signed message size
	 * Magic + version_tag + filetype + type + channel
	 * + description + revision + dest_revision + timestamp + certificate
	 * + apdfile
	 */
	outdata.size = (strlen(APDATE_FILE_MAGIC)) + (1) + (4)
		+ (strlen(aptype) + 1) + (strlen(channel) + 1)
		+ (descdata.size + 1) + (8) + (8) + (8) + (certdata.size + 1)
		+ (4 + fdata.size);
	if (ftruncate(out, outdata.size) != 0) {
		fprintf(stderr, "Can't truncate temp file\n");
		goto out_bye;
	}
	outdata.data = mmap(NULL, outdata.size, PROT_READ | PROT_WRITE, MAP_SHARED, out,
		    0);
	if (outdata.data == MAP_FAILED) {
		fprintf(stderr, "Can't mmap temp file\n");
		goto out_bye;
	}
	fmap = mempcpy(outdata.data, APDATE_FILE_MAGIC, strlen(APDATE_FILE_MAGIC));
	fmap = mempcpy(fmap, &version_tag, 1);
	ui32 = htobe32((uint32_t) filetype);
	fmap = mempcpy(fmap, &ui32, 4);
	fmap = mempcpy(fmap, aptype, strlen(aptype) + 1);
	fmap = mempcpy(fmap, channel, strlen(channel) + 1);
	if (descdata.size != 0)
		fmap = mempcpy(fmap, descdata.data, descdata.size);
	*fmap = '\0';
	fmap++;
	ui64 = htobe64((uint64_t) atoll(revision));
	fmap = mempcpy(fmap, &ui64, 8);
	ui64 = htobe64((uint64_t) atoll(dest_rev));
	fmap = mempcpy(fmap, &ui64, 8);
	ui64 = htobe64((uint64_t) time(NULL));
	fmap = mempcpy(fmap, &ui64, 8);
	fmap = mempcpy(fmap, certdata.data, certdata.size);
	*fmap = '\0';
	fmap++;
	ui32 = htobe32(fdata.size);
	fmap = mempcpy(fmap, &ui32, 4);
	fmap = mempcpy(fmap, fdata.data, fdata.size);
	if (munmap(certdata.data, certdata.size) != 0
	    || munmap(fdata.data, fdata.size) != 0
	    || (descdata.size != 0 && munmap(descdata.data, descdata.size) != 0)) {
		fprintf(stderr, "Unmapping error\n");
		goto out_clean_tmp;
	}
	close(certfd);
	close(apfile);
	if (descfd != -1)
		close(descfd);
	
	/* Make relative pointer */
	l = fmap - (char *) outdata.data;

#if (GNUTLS_VERSION_NUMBER >= 0x021200)
	ret = gnutls_privkey_sign_data(newkey, GNUTLS_DIG_SHA256, 0, &outdata,
				      &signature);
#else
	signature.data = malloc(SIGNATURE_SIZE);
	signature.size = SIGNATURE_SIZE;
	ret = gnutls_x509_privkey_sign_data(*key, GNUTLS_DIG_SHA256, 0, &outdata,
					    signature.data, (size_t *) &signature.size);
#endif
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Failed to sign update\n");
		goto out_clean_tmp;
	}
	if (ftruncate(out, outdata.size + 4 + signature.size) != 0) {
		fprintf(stderr, "Failed to make output file");
		goto out_clean_tmp;
	}
	
	outdata.data = mremap(outdata.data, outdata.size, outdata.size + 4
			    + signature.size, MREMAP_MAYMOVE);
	if (outdata.data == MAP_FAILED) {
		fprintf(stderr, "Failed to remap output file");
		goto out_clean_tmp;
	}
	fmap = (char *) outdata.data + l;

	l = htobe32(signature.size);
	fmap = mempcpy(fmap, &l, 4);
	fmap = mempcpy(fmap, signature.data, signature.size);
	free(signature.data);
	if (munmap(outdata.data, outdata.size + 4 + signature.size) != 0) {
		fprintf(stderr, "Failed to unmap output file");
		goto out_clean_tmp;
	}

	close(out);
	/* file name to stdout */
	printf("%s\n", pname);
	return 0;

out_clean_tmp:
	close(out);

	unlink(pname);
out_bye:
	return -1;
}
