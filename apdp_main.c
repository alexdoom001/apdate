/*
 * Signs an update and puts it in update DB
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "apdp_main.h"
#include "apdate_common.h"
#include "apdp_config.h"
#include "apdate_version.h"
#include "apdate_products.h"

char *upddb, *keyfile, *certfile, *prodfile;

int main(int argc, char **argv)
{
	char *conffile_name, *updtar, *verdesc, *lockfile, *cmdline, *verf_name;
	char *pname, *tmpdir;
	char **lncmds;
	char signature[SIGNATURE_SIZE];
	int fdb_lock, i, ret;
	FILE *verf, *signf;
	time_t ctime;
	size_t signature_size = SIGNATURE_SIZE;
	gnutls_datum_t fdata;
	gnutls_x509_crt_t *crt;
	gnutls_x509_privkey_t *key;
	struct version_content *version;
	struct prcode_list *products;

	gnutls_global_init();
	if (argc == 3) {
		conffile_name = APDPCONF;
		updtar = argv[1];
		verdesc = argv[2];
	} else if (argc == 4) {
		conffile_name = argv[1];
		updtar = argv[2];
		verdesc = argv[3];
	} else {
		fprintf(stderr, "Usage: apdp [conffile] update version\n");
		exit(1);
	}

	if (conf_parse(conffile_name) != 0) {
		printf("Can't read config file '%s'\n", conffile_name);
		exit(2);
	}

	gnutls_global_init();

	crt = load_certificate(certfile);
	if (crt == NULL) {
		fprintf(stderr, "Error loading apdate certificate\n");
		exit(1);
	}
	key = load_privkey(keyfile);
	if (key == NULL) {
		fprintf(stderr, "Error loading apdate private key\n");
		exit(2);
	}
	fdata = load_file(verdesc);
	version = apdate_parse_version((char *) fdata.data, fdata.size);
	if (version == NULL) {
		fprintf(stderr, "Error parsing version file\n");
		exit(3);
	}
	unload_file(fdata);
	fdata = load_file(prodfile);
	products = apdate_parse_product_list((char *) fdata.data, fdata.size);
	if (products == NULL) {
		fprintf(stderr, "Error loading products file\n");
		exit(4);
	}
	unload_file(fdata);
	tmpdir = strdup(TMP_DIR_PATTERN);
	tmpdir = mkdtemp(tmpdir);
	if (tmpdir == NULL) {
		fprintf(stderr, "Error: can't create tmp directory\n");
		exit(5);
	}
	cmdline = malloc(256);
	sprintf(cmdline, "cp %s %s/update", updtar, tmpdir);
	ret = system(cmdline);
	if (ret != 0) {
		fprintf(stderr, "Failed to copy update into temporary dir\n");
		goto out_clean_tmp;
	}
	sprintf(cmdline, "cp %s %s/certificate", certfile, tmpdir);
	ret = system(cmdline);
	if (ret != 0) {
		fprintf(stderr, "Failed to copy generator certificate into temporary dir\n");
		goto out_clean_tmp;
	}
	fdata = load_file(updtar);
	if (fdata.data == NULL) {
		fprintf(stderr, "Failed to load update\n");
		goto out_clean_tmp;
	}
	ret = gnutls_x509_privkey_sign_data(*key, GNUTLS_DIG_SHA256, 0, &fdata, \
				      signature, &signature_size);
	unload_file(fdata);
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Failed to sign update\n");
		goto out_clean_tmp;
	}
	sprintf(cmdline, "%s/update.sig", tmpdir);
	signf = fopen(cmdline, "w");
	if (signf == NULL) {
		fprintf(stderr, "Failed to create signature file for update\n");
		goto out_clean_tmp;
	}
	fwrite(signature, 1, signature_size, signf);
	fclose(signf);

	verf_name = strconcat(tmpdir, "/version");
	if (verf_name == NULL) {
		fprintf(stderr, "Error: OOM\n");
		goto out_clean_tmp;
	}
	verf = fopen(verf_name, "w");
	if (verf == NULL) {
		fprintf(stderr, "Error working with version file in temporary directory");
		goto out_clean_tmp;
	}
	ctime = time(NULL);
	fprintf(verf, "%s\n", version->type);
	fprintf(verf, "%li\n", (long int) ctime);

	pname = malloc(128);
	sprintf(pname, "%s-%li.apd", version->type, (long int) ctime);

	lncmds = malloc(version->pr_cnt * sizeof(char *));
	lockfile = strconcat(upddb, ".lock");
	fdb_lock = get_file_lock(lockfile);
	for (i = 0; i < version->pr_cnt; i++) {
		uint32_t code;
		uint64_t last;
		int num_patches, j;
		char prpath[256], lncmd[256];
		struct dirent **proddir;

		code = (uint32_t) strcode_get_code(products->prodcode,
						   products->size,
						   version->product[i].str);
		if (code == 0) {
			fprintf(stderr, "Bad product in version file: %s",
				version->product[i].str);
			goto release_lock_out;
		}
		sprintf(prpath, "%s/%u", upddb, code);
		num_patches = scandir(prpath, &proddir, NULL, versionsort);
		if (num_patches != 0)
			last = atoll(proddir[num_patches-1]->d_name);
		else
			last = 0;
		last++;
		for (j = 0; j < num_patches; j++)
			free(proddir[j]);
		free(proddir);
		fprintf(verf, "%s:%llu\n", version->product[i].str,
			(long long unsigned int) last);
		sprintf(lncmd, "ln -fs ../patches/%s %s/%llu", pname, prpath,
			(long long unsigned int) last);
		lncmds[i] = strdup(lncmd);
	}
	fclose(verf);
	fdata = load_file(verf_name);
	if (fdata.data == NULL) {
		fprintf(stderr, "Failed to load generated version file\n");
		goto release_lock_out;
	}
	signature_size = SIGNATURE_SIZE;
	ret = gnutls_x509_privkey_sign_data(*key, GNUTLS_DIG_SHA256, 0, &fdata, \
				      signature, &signature_size);
	unload_file(fdata);
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Failed to sign version file\n");
		goto release_lock_out;
	}
	sprintf(cmdline, "%s/version.sig", tmpdir);
	signf = fopen(cmdline, "w");
	if (signf == NULL) {
		fprintf(stderr, "Failed to create signature file for version\n");
		goto release_lock_out;
	}
	fwrite(signature, 1, signature_size, signf);
	fclose(signf);

	sprintf(cmdline, "tar czf %s/patches/%s -C %s .", upddb, pname, tmpdir);
	ret = system(cmdline);
	if (ret != 0) {
		fprintf(stderr, "Failed to create apdate tarball\n");
		goto release_lock_out;
	}
	for (i = 0; i < version->pr_cnt; i++) {
		ret = system(lncmds[i]);
		if (ret != 0) {
			fprintf(stderr, "Symlinking apdate tarball failed: %s\n",
				lncmds[i]);
			goto release_lock_out;
		}
	}
release_lock_out:
	release_file_lock(lockfile, fdb_lock);
out_clean_tmp:
	sprintf(cmdline, "rm -fr %s", tmpdir);
	system(cmdline);
	return 0;
}
