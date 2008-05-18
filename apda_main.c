
/*
 * Verifies update and runs update-specific unpacker
 * Exactly one reason for this crap in C: no CLI signature verifiers
 */

#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apdate_common.h"
#include "apdate_version.h"
#include "apdc_main.h"
#include "apdc_config.h"

char *cafile, *dbpath, *verfile, *certfile, *keyfile, *product_string;
char *patch_queue_path, *crlfile, *libexec_path;
char *apds_list[APDC_MAX_LIST];
uint32_t product_code;

gnutls_x509_crt_t *load_calist(char *path, unsigned int *calist_size) {
	int ret;
	gnutls_x509_crt_t *crts;
	gnutls_datum_t data;

	*calist_size = 10;
	crts = malloc(*calist_size * sizeof(gnutls_x509_crt_t));
	data = load_file(path);
	if (data.data == NULL) {
		free(crts);
		return NULL;
	}

	ret = gnutls_x509_crt_list_import(crts, calist_size, &data,
					  GNUTLS_X509_FMT_PEM, 0);
	unload_file(data);
	if (ret < 0) {
		free(crts);
		return NULL;
	}
	return crts;
}

gnutls_x509_crl_t *load_crl(char *path) {
	int ret;
	gnutls_x509_crl_t *crl = malloc(sizeof(gnutls_x509_crl_t));
	gnutls_datum_t data;

	data = load_file(path);
	if (data.data == NULL) {
		free(crl);
		return NULL;
	}
	gnutls_x509_crl_init(crl);
	ret = gnutls_x509_crl_import(*crl, &data, GNUTLS_X509_FMT_PEM);
	unload_file(data);
	if (ret != GNUTLS_E_SUCCESS) {
		free(crl);
		return NULL;
	}
	return crl;
}

int main(int argc, char **argv)
{
	char *conffile_name, *apdate, *lockfile, *staging_path, *cmdline;
	char *fname;
	int staging_lock, ret;
	unsigned int calist_size, verify;
	gnutls_x509_crt_t *crt, *calist;
	gnutls_x509_crl_t *crl;
	gnutls_datum_t fdata, signature;
	struct version_content *version;
	struct string_code prod_code;
	int64_t vercode;

	gnutls_global_init();
	if (argc == 2) {
		conffile_name = APDCCONF;
		apdate = argv[1];
	} else if (argc == 3) {
		conffile_name = argv[1];
		apdate = argv[2];
	} else {
		fprintf(stderr, "Usage: apdc_apply_update [conffile] update_file\n");
		exit(1);
	}
	memset(apds_list, 0, APDC_MAX_LIST);
	if (conf_parse(conffile_name) != 0) {
		printf("Can't read config file '%s'\n", conffile_name);
		exit(2);
	}
	verfile = strconcat(dbpath, VERSION_FILE);
	lockfile = strconcat(dbpath, STAGING_LOCK);
	staging_path = strconcat(dbpath, STAGING_PATH);

	cmdline = malloc(512);
	sprintf(cmdline, "tar xf %s -C %s", apdate, staging_path);

	staging_lock = get_file_lock(lockfile);
	ret = system(cmdline);
	if (ret != 0) {
		fprintf(stderr, "Failed to untar apdate file\n");
		goto out;
	}
	fname = strconcat(staging_path, "certificate");
	crt = load_certificate(fname);
	free(fname);
	if (crt == NULL) {
		fprintf(stderr, "Error loading apdate certificate\n");
		goto out;
	}
	calist = load_calist(cafile, &calist_size);
	if (calist == NULL) {
		fprintf(stderr, "Error loading CA list\n");
		goto out;
	}
	crl = load_crl(crlfile);
	if (crl == NULL) {
		fprintf(stderr, "Error loading CRL\n");
		goto out;
	}
	ret = gnutls_x509_crt_verify(*crt, calist, calist_size, 0, &verify);
	if (ret < 0 || verify & GNUTLS_CERT_INVALID) {
		fprintf(stderr, "Certificate verification failed\n");
		goto out;
	}
	fname = strconcat(staging_path, "version");
	fdata = load_file(fname);
	version = apdate_parse_version((char *) fdata.data, fdata.size);
	if (version == NULL) {
		fprintf(stderr, "Incorrect version file\n");
		goto out;
	}
	unload_file(fdata);
	fdata = load_file(fname);
	free(fname);
	fname = strconcat(staging_path, "version.sig");
	signature = load_file(fname);
	free(fname);
	ret = gnutls_x509_crt_verify_data(*crt, 0, &fdata, &signature);
	unload_file(fdata);
	unload_file(signature);
	if (ret != 1) {
		fprintf(stderr, "Failed to verify version file\n");
		goto out;
	}
	fname = strconcat(staging_path, "update");
	fdata = load_file(fname);
	free(fname);
	fname = strconcat(staging_path, "update.sig");
	signature = load_file(fname);
	free(fname);
	ret = gnutls_x509_crt_verify_data(*crt, 0, &fdata, &signature);
	if (ret != 1) {
		fprintf(stderr, "Failed to verify update file\n");
		goto out;
	}
	unload_file(fdata);
	unload_file(signature);

	/*
	 * Seems like an update is proper one, so we can invoke type-specific
	 * handlers now safely
	 */

	sprintf(cmdline, "cp -f %s %s.backup", verfile, verfile);
	ret = system(cmdline);
	if (ret != 0) {
		fprintf(stderr, "Something is horribly b0rken there, can't backup version file\n");
		exit(101);
	}

	fname = strconcat(dbpath, PRODUCT_FILE);
	prod_code = load_product_file(fname);
	free(fname);
	vercode = strcode_get_code(version->product, version->pr_cnt,
				   prod_code.str);
	fname = malloc(30);
	sprintf(fname, "%lli", (long long int) vercode);
	write(staging_lock, fname, strlen(fname));
	free(fname);
	fsync(staging_lock);
	sprintf(cmdline, "%s/%s apply", libexec_path, version->type);
	ret = system(cmdline);
	if (ret != 0)
		fprintf(stderr, "Achtung! Failed to apply update\n");
	else {
		FILE *vf;

		vf = fopen(verfile, "w");
		if (vf == NULL)
			fprintf(stderr, "Error: can't change version file!\n");
		else {
			char *bname;

			fprintf(vf, "%lli", (long long int) vercode);
			fclose(vf);
			sync();
			bname = strconcat(verfile, ".backup");
			unlink(bname);
			free(bname);
		}
	}
out:
        sprintf(cmdline, "rm -fr %s/*", staging_path);
	system(cmdline);
	release_file_lock(lockfile, staging_lock);
	return 0;
}
