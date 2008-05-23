
/*
 * Verifies update and runs update-specific unpacker
 * Exactly one reason for this crap in C: no CLI signature verifiers
 * Well, thinking a bit more, there is also another one: reliable
 * automata-based file format validator/parser
 */

#include <db.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <syslog.h>

#include "apdate_common.h"
#include "apdate_client.h"
#include "apdate_file.h"
#include "apdc_main.h"
#include "apdc_config.h"

#if LIBGNUTLS_VERSION_MAJOR <= 2 && LIBGNUTLS_VERSION_MINOR <= 6 && LIBGNUTLS_VERSION_PATCH < 6
#define GNUTLS_VERIFY_DISABLE_TIME_CHECKS 0
#endif

#define PATHBUFSIZE 256
#define CMDBUFSIZE 512
char *cafile, *dbpath, *verfile, *certfile, *keyfile, *product_string, *certsdir, *revfile;
char *patch_queue_path, *crlfile, *libexec_path, *upd_storage_path;
char *apds_list[APDC_MAX_LIST];
uint32_t product_code;
int debug_print = 0;

static void usage_blurb()
{
	fprintf(stderr, "Usage: apda [conffile] (extract|apply|apply-ro|description) update_file\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *conffile_name, *apdate, *cmdline, *sn;
	char *apdcontent, *updtmpf = NULL, *action;
	int ret, ncerts, apdfh, updtmph, extract_mode = 0, description_mode = 0, ro_mode = 0;
	long int apdf_len;
	unsigned int calist_size, verify;
	gnutls_x509_crt_t *crt, *calist;
	gnutls_x509_crl_t *crl;
	struct apdate_file *apdfile;
	struct stat b;
	struct ver_rec vr, ovr;
	struct statvfs stvfs;
	DB *dbp = NULL;

	gnutls_global_init();
	if (argc == 3) {
		conffile_name = APDCCONF;
		action = argv[1];
		apdate = argv[2];
	} else if (argc == 4) {
		conffile_name = argv[1];
		action = argv[2];
		apdate = argv[3];
	} else
		usage_blurb();

	// Just extract update archive
	if (strcmp(action, "extract") == 0)
		extract_mode = 1;
	//Apply update (RW filesystem)
	else if (strcmp(action, "apply") == 0) {
		extract_mode = 0;
		description_mode = 0;
	//Apply update (on RO filesystems: real update databases and add to queue programs update)
	} else if (strcmp(action, "apply-ro") == 0) {
		extract_mode = 0;
		description_mode = 0;
		ro_mode = 1; 
	//Show description
	} else if (strcmp(action, "description") == 0)
		description_mode = 1;
	else
		usage_blurb();

	memset(apds_list, 0, APDC_MAX_LIST);
	if (conf_parse(conffile_name) != 0) {
		fprintf(stderr, "Can't read config file '%s'\n", conffile_name);
		exit(2);
	}

	// Open Update file && read it
	apdfh = open(apdate, O_RDONLY);
	apdf_len = lseek(apdfh, 0, SEEK_END);
	apdcontent = mmap(NULL, apdf_len, PROT_READ, MAP_SHARED,
			  apdfh, 0);
	if (apdcontent == MAP_FAILED) {
		fprintf(stderr, "Can't mmap apdate file\n");
		ret = 188;
		goto out;
	}
	apdfile = apdate_parse_file(apdcontent, apdf_len);

	if (apdfile == NULL) {
		fprintf(stderr, "Broken apdate file\n");
		ret = 456;
		goto out;
	}
	// Load sertificates & etc..
	ncerts = load_certificate_ram(&crt, apdfile->certificate);
	if (ncerts <= 0) {
		fprintf(stderr, "Error loading apdate certificate\n");
		ret = 4;
		goto out;
	}
	calist = load_calist(cafile, &calist_size);
	if (calist == NULL) {
		fprintf(stderr, "Error loading CA list\n");
		ret = 5;
		goto out;
	}
	crl = load_crl(crlfile);
	if (crl == NULL) {
		fprintf(stderr, "Error loading CRL\n");
		ret = 6;
		goto out;
	}
	ret = gnutls_x509_crt_list_verify(crt, ncerts, calist, calist_size, crl,
					  1, GNUTLS_VERIFY_DISABLE_TIME_CHECKS,
					  &verify);
	if ((ret < 0) || (verify & GNUTLS_CERT_INVALID) || (verify &
							    GNUTLS_CERT_REVOKED)) {
		fprintf(stderr, "Certificate verification failed\n");
		ret = 7;
		goto out;
	}

	ret = gnutls_x509_crt_verify_data(*crt, 0, &(apdfile->signed_content), &(apdfile->signature));
	if (ret != 1) {
		fprintf(stderr, "Failed to verify update file\n");
		ret = 10;
		goto out;
	}

	cmdline = malloc(CMDBUFSIZE);
	verfile = malloc(PATHBUFSIZE);

	// Check, if we have processing module for current update type
	snprintf(cmdline, CMDBUFSIZE, "%s/%s", libexec_path, apdfile->type);
	if (stat(cmdline, &b) != 0) {
		fprintf(stderr, "Unable to found handler for %s\n", apdfile->type);
		ret = 15;
		goto out;
	}
	// For description just print update description and exit
	if (description_mode) {
		printf("%s", apdfile->description);
		exit(0);
	}
	/*
	 * Seems like an update is proper one, so we can invoke type-specific
	 * handlers now safely
	 */
	// if ro_mode is 1 and this is program updte, then just store this update
	if (ro_mode == 1 && extract_mode == 0 && (apdfile->filetype != APDATE_TYPE_BASES && apdfile->filetype != APDATE_TYPE_BASES_ALL) ) {
		struct stat st;
		struct dirent **namelist;
		int n, i, last_ap = 0, dup_found = 0;
		char fname[12];
		char *fpath = NULL;
		FILE *outfh;

		/* Check for dups */
		n = scandir(upd_storage_path, &namelist, NULL, alphasort);
		if (n < 0) {
			fprintf(stderr, "Unable to open directory '%s'\n", upd_storage_path);
			exit(2001);
		}
		for (i = 0; i < n; i++)
			if (sscanf(namelist[i]->d_name, "apdate_%03d", &last_ap)) {
				char *apname;

				apname = g_build_filename(upd_storage_path, namelist[i]->d_name, NULL);
				free(namelist[i]);
				if (apname == NULL)
					continue;
				if (stat(apname, &st) != 0) {
					free(apname);
					continue;
				}
				if (st.st_size == apdf_len) {
					int apfd;
					char *apfd_map;

					if ((apfd = open(apname, O_RDONLY)) > 0) {
						if ((apfd_map = mmap(NULL, apdf_len, PROT_READ, MAP_SHARED,
								     apfd, 0)) != MAP_FAILED) {
							if (memcmp(apfd_map, apdcontent, apdf_len) == 0)
								dup_found = 1;
							munmap(apfd_map, apdf_len);
						}
						close(apfd);
					}
				}
				free(apname);
			}
		free(namelist);
		if (dup_found) {
			exit(0);
		}

		i = last_ap;
		do {
			i++;
			free(fpath);
			sprintf(fname, "apdate_%03d", i);
			fpath = g_build_filename(upd_storage_path, fname, NULL);
		} while (stat(fpath, &st) == 0);

		// check space and copy package to proper place
		if (statvfs(upd_storage_path, &stvfs) < 0) {
			fprintf(stderr, "Unable to calc free storage space\n");
			exit(1244);
		}
		if (stvfs.f_bsize * stvfs.f_bfree < apdf_len) {
			fprintf(stderr, "No free storage space available\n");
			exit(1245);
		}

		outfh = fopen(fpath,"w");
		if (fwrite(apdcontent,1,apdf_len,outfh) != apdf_len) {
			fprintf(stderr, "Unable to move file\n");
			fclose(outfh);
			unlink(fpath);
		}
		fclose(outfh);
		
		openlog("apda", 0, LOG_LOCAL1);
		syslog(LOG_WARNING, "SW update found, reboot required");
		closelog();

		free(fpath);
		exit(0);
	}

	updtmpf = strdup(TMP_FILE_PATTERN);
	updtmph = mkstemp(updtmpf);
	if (updtmph < 0) {
		fprintf(stderr, "Can't create temporary output file\n");
		exit(133);
	}
	if (fstatvfs(updtmph, &stvfs) < 0) {
		fprintf(stderr, "Unable to calc free storage space\n");
		exit(1244);
	}
	if (stvfs.f_bsize * stvfs.f_bfree < apdfile->apfile.size) {
		fprintf(stderr, "No free space available\n");
		exit(1245);
	}
	if (write(updtmph, apdfile->apfile.data, apdfile->apfile.size)
	    != apdfile->apfile.size || close(updtmph) != 0) {
		fprintf(stderr, "Error writing to temp output file\n");
		ret = 134;
		goto out;
	}

	if (extract_mode) {
		printf("%s\n", updtmpf);
		exit(0);
	}

	ret = snprintf(verfile, PATHBUFSIZE, "%s/version.db", dbpath);

	if (ret < 0 || ret > PATHBUFSIZE) {
		fprintf(stderr, "Internal error 140\n");
		ret = 140;
		goto out;
	}
	switch (apdfile->filetype) {
	case APDATE_TYPE_SOFTWARE:
	case APDATE_TYPE_SOFTWARE_HF:
		dbp = openverdb("software", 0);
		break;
	case APDATE_TYPE_BASES:
	case APDATE_TYPE_BASES_ALL:
		dbp = openverdb("bases", 0);
		break;
	case APDATE_TYPE_PERSONAL:
		dbp = openverdb("personal", 0);
	}

	if (dbp == NULL) {
		fprintf(stderr, "Unable to open db\n");
		ret = 141;
		goto out;
	}

	snprintf(verfile, PATHBUFSIZE, "%s/%s", apdfile->type, apdfile->channel);
	vr.main = apdfile->rev_to;
	vr.rev = 0;
	vr.state = VR_STATE_OK;
	if (get_ver_rec_from_db(dbp, verfile, &ovr) != 0) {
		ovr.main = 0;
		ovr.rev = 0;
		ovr.state = VR_STATE_OK;
	}
	switch (apdfile->filetype) {
	case APDATE_TYPE_SOFTWARE:
	case APDATE_TYPE_SOFTWARE_HF:
		if (ovr.main != apdfile->rev_from) {
			fprintf(stderr, "Error: update package is for another version %s (%llu), current: %llu\n",
				verfile, (long long unsigned int) apdfile->rev_from,
				(long long unsigned int) ovr.main);
			ret = 144;
			goto out;
		}
		if (apdfile->filetype == APDATE_TYPE_SOFTWARE)
			break;
		if (ovr.rev != (apdfile->rev_to - 1)) {
			fprintf(stderr, "Error: update package is for another version %s (%llu), current: %llu\n",
				verfile, (long long unsigned int) apdfile->rev_to - 1,
				(long long unsigned int) ovr.rev);
			ret = 143;
			goto out;
		}
		/* Hotfixes have different meaning for rev_from and rev_to */
		vr.main = apdfile->rev_from;
		vr.rev = apdfile->rev_to;
		break;
	case APDATE_TYPE_BASES:
		if (ovr.main != apdfile->rev_from) {
			fprintf(stderr, "Error: update package is for another version %s (%llu), current: %llu\n",
				verfile, (long long unsigned int) apdfile->rev_from,
				(long long unsigned int) ovr.main);
			ret = 144;
			goto out;
		}
		break;
	case APDATE_TYPE_BASES_ALL:
		if (ovr.main >= apdfile->rev_to) {
			fprintf(stderr, "Error: update package is for another version %s (%llu), current: %llu\n",
				verfile, (long long unsigned int) apdfile->rev_to,
				(long long unsigned int) ovr.main);
			ret = 144;
			goto out;
		}
		break;
	case APDATE_TYPE_PERSONAL:
		if (ovr.main != apdfile->rev_from) {
			fprintf(stderr, "Error: update package is for another version %s (%llu), current: %llu\n",
				verfile, (long long unsigned int) apdfile->rev_from,
				(long long unsigned int) ovr.main);
			ret = 143;
			goto out;
		}
	}
	sprintf(cmdline, "%s/%s apply %s", libexec_path, apdfile->type, updtmpf);
	ret = system(cmdline);
	if (ret != 0) {
		ovr.state = VR_STATE_UPDATE_FAILED;
		put_ver_rec_to_db(dbp, verfile, &ovr);
		fprintf(stderr, "Failed to apply update\n");
		sprintf(cmdline, "%s/%s restore", libexec_path, apdfile->type);
		if (system(cmdline) != 0)
			fprintf(stderr, "Failed to restore from badly applied update!\n");
	} else {
		put_ver_rec_to_db(dbp, verfile, &vr);
	}

out:
	if (dbp != NULL)
		dbp->close(dbp, 0);

	if (updtmpf != NULL)
		unlink(updtmpf);
	return ret;
}
