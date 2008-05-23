
/*
 * Apdate DB manipulation
 */

#include <ctype.h>
#include <db.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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
#define LINE_SIZE 80
char *cafile, *dbpath, *verfile, *certfile, *keyfile, *product_string, *certsdir, *revfile;
char *patch_queue_path, *crlfile, *libexec_path, *upd_storage_path;
char *apds_list[APDC_MAX_LIST];
uint32_t product_code;
int debug_print = 0;

static void usage_blurb()
{
	/* '-i dbfile' is hidden on purpose */
	fprintf(stderr, "Usage: apdi [-c conffile] [-s certs|feeds|rev|revfull|sn]\n");
	exit(1);
}

static int print_cert(char *fname)
{
	char *str, *pstr;
	int i;
	time_t expirt;
	gnutls_x509_crt_t *crt;
	
	pstr = malloc(LINE_SIZE*2);
	if (pstr == NULL)
		return -1;

	i = load_certificate(&crt, fname);
	if (i <= 0) {
		free(pstr);
		return -1;
	}
	/* CN */
	str = get_cert_field_by_oid(crt[0], "2.5.4.3", 0);
	expirt = gnutls_x509_crt_get_expiration_time(crt[0]);
	i = snprintf(pstr, LINE_SIZE/2 - 1, "%s", str);
	free(str);
	for (; i < LINE_SIZE/2; i++) {
		pstr[i] = ' ';
	}
	i = snprintf(pstr + LINE_SIZE/2, LINE_SIZE/2, "%s", ctime(&expirt));
	if (time(NULL) > expirt)
		snprintf(pstr + LINE_SIZE/2 + i - 1, LINE_SIZE*4/3 - i, " (expired)\n");
	printf("%s", pstr);
	free(pstr);

	return 0;
}

static GArray* get_rev_channels()
{
	char *b, *b2, *c;
	GArray *ar;
	gnutls_datum_t data;

	data = load_file(revfile);
	if (data.data == NULL)
		return NULL;

	ar = g_array_new(FALSE, FALSE, sizeof(char *));
	if (ar == NULL)
		goto out;

	b = (char *) data.data;
	while ((b2 = strchr(b, '\n')) != NULL) {
		*b2 = '\0';
		c = strdup(b);
		if (c == NULL)
			goto out;
		if (b2 != b + 1)
			g_array_append_val(ar, c);
		else
			free(c);
		b = b2 + 1;
	}
out:
	free(data.data);
	return ar;
}

int search_db_for_key(DB *dbp, char *tc, DBT* key) {
	int i, l;
	DBC *dbc;
	DBT data;

	if (key == NULL)
		return -1;
	if (dbp->cursor(dbp, NULL, &dbc, 0) != 0)
		return -2;

	memset(key, 0, sizeof(*key));
	memset(&data, 0, sizeof(data));

	l = strlen(tc);
	while((i = dbc->get(dbc, key, &data, DB_NEXT)) == 0) {
		if (strncmp(tc, key->data, l) == 0)
			return 0;
		memset(key, 0, sizeof(*key));
		memset(&data, 0, sizeof(data));
	}
	if (i != DB_NOTFOUND)
		return -3;

	return 1;
}


#define A_INITDB 0
#define A_SHOW   1
#define A_ADDKEY 2
#define A_REPKEY 3

int main(int argc, char **argv)
{
	char *conffile_name = APDCCONF, *apdate, *newkey;
	char *apdcontent, *updtmpf, *showit, *tc, *dbfilename = NULL, *dbtype = "regular";
	int action, i, j, c, ret = 0, ncerts, apdfh, updtmph, extract_mode = 0;
	long int apdf_len, mainrev = 0;
	unsigned int calist_size, verify;
	gnutls_x509_crt_t *calist;
	gnutls_x509_crl_t *crl;
	struct ver_rec vr;
	DB *dbp = NULL, *dbp2 = NULL;
	DBT key, key2;

	gnutls_global_init();

	while ((c = getopt(argc, argv, "c:i:s:a:m:u:d:")) != -1)
	       switch (c) {
	       case 'c':
		       conffile_name = optarg;
		       break;
	       case 'i':
		       dbfilename = optarg;
		       action = A_INITDB;
		       break;
	       case 's':
		       showit = optarg;
		       action = A_SHOW;
		       break;
	       case 'a':
		       newkey = optarg;
		       action = A_ADDKEY;
		       break;
	       case 'm':
		       mainrev = strtol(optarg, NULL, 10);
		       switch (errno) {
		       case EINVAL:
			       fprintf(stderr, "-m value must be integer\n");
			       usage_blurb();
			       break;
		       case ERANGE:
			       fprintf(stderr, "Incorrect value of -m arg\n");
			       usage_blurb();
			       break;
		       }
		       if (mainrev < 0) {
			       fprintf(stderr, "-m value must be unsigned\n");
			       usage_blurb();
		       }
		       break;
	       case 'u':
		       newkey = optarg;
		       action = A_REPKEY;
		       break;
	       case 'd':
		       dbtype = optarg;
		       break;
	       case '?':
		       switch (optopt) {
		       case 'c':
		       case 'i':
		       case 'm':
		       case 's':
		       case 'a':
		       case 'u':
		       case 'd':
			       fprintf(stderr, "-%c must have a value\n", optopt);
			       break;
		       default:
			       if (isprint(optopt))
				       fprintf(stderr, "Unknown parameter '-%c'.\n", optopt);
			       else
				       fprintf(stderr, "Unknown symbol '\\x%x'.\n", optopt);
		       }
		       /* Fallthrough */
	       default:
		       usage_blurb();
	       }

	memset(apds_list, 0, APDC_MAX_LIST);
	if (conf_parse(conffile_name) != 0) {
		fprintf(stderr, "Can't read config file '%s'\n", conffile_name);
		exit(2);
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

	verfile = malloc(PATHBUFSIZE);

	verfile = g_build_filename(dbpath, "version.db", NULL);

	if (verfile == NULL) {
		fprintf(stderr, "Internal error 140\n");
		ret = 140;
		goto out;
	}
	switch (action) {
	case A_INITDB:
		if (dbfilename != NULL) {
			if (strcmp(verfile, dbfilename) != 0) {
				fprintf(stderr, "Internal error 1419, %s vs %s\n", verfile, dbfilename);
				ret = 1421;
			} else if (db_create(&dbp, NULL, 0) != 0
				   || dbp->open(dbp, NULL, verfile, "software", DB_BTREE, DB_CREATE, 0) != 0
				   || dbp->close(dbp, 0) != 0) {
				fprintf(stderr, "Internal error 1420\n");
				ret = 1420;
			} else if (db_create(&dbp, NULL, 0) != 0
				   || dbp->open(dbp, NULL, verfile, "bases", DB_BTREE, DB_CREATE, 0) != 0
				   || dbp->close(dbp, 0) != 0) {
				fprintf(stderr, "Internal error 1420\n");
				ret = 1420;
			} else if (db_create(&dbp, NULL, 0) != 0
				   || dbp->open(dbp, NULL, verfile, "personal", DB_BTREE, DB_CREATE, 0) != 0
				   || dbp->close(dbp, 0) != 0) {
				fprintf(stderr, "Internal error 1420\n");
				ret = 1420;
			} else if (db_create(&dbp, NULL, 0) != 0
				   || dbp->open(dbp, NULL, verfile, "settings", DB_BTREE, DB_CREATE, 0) != 0
				   || dbp->close(dbp, 0) != 0) {
				fprintf(stderr, "Internal error 1420\n");
				ret = 1420;
			} else {
				dbp = NULL;
				ret = 0;
			}
		}
		break;
	case A_SHOW:
		if (strcmp(showit, "certs") == 0) {
			char *fname;
			int i, j;
			struct dirent **dirnames;

			printf("Subsciprion\t\t\t\tExpiration date\n");
			for (i = 0; i < LINE_SIZE; i++)
				printf("=");
			printf("\n");

			if (print_cert(certfile) != 0) {
				fprintf(stderr, " * Certificate processing failure %s\n", certfile);
				goto out;
			}
			i = scandir(certsdir, &dirnames, NULL, alphasort);
			if (i < 0) {
				fprintf(stderr, " * Could not read certs dir\n");
				goto out;
			} else if (i == 0) {
				fprintf(stderr, " * Certs dir is empty\n");
				goto out;
			}
			for (j = 0; j < i; j++) {
				if (strcmp(dirnames[j]->d_name, ".") == 0 ||
				    strcmp(dirnames[j]->d_name, "..") == 0) {
					free(dirnames[j]);
					continue;
				}
				if ((fname = g_build_filename(certsdir, dirnames[j]->d_name,
							      NULL)) == NULL) {
					ret = 123323;
					continue;
				}
				if (print_cert(fname) != 0) {
					fprintf(stderr, " * Certificate processing failure %s\n", fname);
					goto out;
				}
				free(fname);
				free(dirnames[j]);
			}
			free(dirnames);
		} else if (strcmp(showit, "feeds") == 0) {
			goto out;
		} else if (strcmp(showit, "rev") == 0) {
			GArray *ar;
			int i;
			uint64_t rev, hfrev;

			dbp = openverdb("software", DB_RDONLY);
			if (dbp == NULL) {
				fprintf(stderr, "Unable to open db\n");
				goto out;
			}
			ar = get_rev_channels();
			if (ar == NULL) {
				fprintf(stderr, "Unable to open sw channels\n");
				goto out;
			}

			if (get_ver_rec_from_db(dbp, g_array_index(ar, char *, (ar->len - 1)), &vr) != 0)
				vr.main = 0;
			printf("%llu\n", (unsigned long long int) vr.main);
			for (i = 0; i < ar->len; i++) {
				free(g_array_index(ar, char *, i));
			}
			g_array_free(ar, TRUE);
		} else if (strcmp(showit, "revfull") == 0) {
			char pstr[LINE_SIZE];
			int i, num, j = 0;
			GArray *req_list;
			struct chan_rev request;

			printf("Channel\t\t\t\t\tRevision\n");
			for (i = 0; i < LINE_SIZE; i++)
				printf("=");
			printf("\n");

			req_list = get_db_list("software");
			if (req_list != NULL) {
				for (i = 0; i < req_list->len; i++) {
					request = g_array_index(req_list, struct chan_rev, i);
					num = snprintf(pstr, LINE_SIZE/2 - 1, "%s", request.channel);
					for (j = num; j < LINE_SIZE/2; j++) {
						pstr[j] = ' ';
					}
					snprintf(pstr + LINE_SIZE/2, LINE_SIZE/2, "%llu/%llu",
						     (unsigned long long int) request.main,
						     (unsigned long long int) request.rev);
					printf("%s\n", pstr);
					free(request.channel);
				}
				g_array_free(req_list, TRUE);
			}
			req_list = get_db_list("bases");
			if (req_list != NULL) {
				for (i = 0; i < req_list->len; i++) {
					request = g_array_index(req_list, struct chan_rev, i);
					num = snprintf(pstr, LINE_SIZE/2 - 1, "%s", request.channel);
					for (j = num; j < LINE_SIZE/2; j++) {
						pstr[j] = ' ';
					}
					snprintf(pstr + LINE_SIZE/2, LINE_SIZE/2, "%llu",
						     (unsigned long long int) request.main);
					printf("%s\n", pstr);
					free(request.channel);
				}
				g_array_free(req_list, TRUE);
			}
			req_list = get_db_list("personal");
			if (req_list != NULL) {
				for (i = 0; i < req_list->len; i++) {
					request = g_array_index(req_list, struct chan_rev, i);
					num = snprintf(pstr, LINE_SIZE/2 - 1, "%s", request.channel);
					for (j = num; j < LINE_SIZE/2; j++) {
						pstr[j] = ' ';
					}
					snprintf(pstr + LINE_SIZE/2, LINE_SIZE/2, "%llu",
						     (unsigned long long int) request.main);
					printf("%s\n", pstr);
					free(request.channel);
				}
				g_array_free(req_list, TRUE);
			}
		} else if (strcmp(showit, "sn") == 0) {
			char *sn = get_device_sn();
			if (sn == NULL) {
				printf("unknown\n");
			} else {
				printf("%s\n", sn);
				free(sn);
			}
		}
		break;
	case A_ADDKEY:
		dbp = openverdb(dbtype, 0);
		if (dbp == NULL) {
			fprintf(stderr, "Unable to open db\n");
			goto out;
		}
		tc = g_path_get_dirname(newkey);
		
		if (strcmp(dbtype, "software") == 0)
			i = - get_ver_rec_from_db(dbp, newkey, &vr);
		else
			i = search_db_for_key(dbp, tc, &key);
		if (i == 0) {
			fprintf(stderr, "Channel already in db\n");
			ret = 2323;
		} else if (i < 0) {
			fprintf(stderr, "Error in db processing\n");
			ret = 8743;
		} else {
			vr.main = (unsigned long int) mainrev;
			vr.rev = 0;
			vr.state = VR_STATE_OK;
			put_ver_rec_to_db(dbp, newkey, &vr);
		}
		break;
	case A_REPKEY:
		dbp = openverdb("bases", 0);
		if (dbp == NULL) {
			fprintf(stderr, "Unable to open db\n");
			goto out;
		}
		tc = g_path_get_dirname(newkey);
		i = get_ver_rec_from_db(dbp, newkey, &vr);
		if (i == 0) {
			fprintf(stderr, "Channel alredy in db\n");
			ret = 4744;
			goto out;
		}
		i = search_db_for_key(dbp, tc, &key);
		if (i == 0) {
			dbp->del(dbp, NULL, &key, 0);
			vr.main = 0;
			vr.rev = 0;
			vr.state = VR_STATE_OK;
			put_ver_rec_to_db(dbp, newkey, &vr);
		} else if (i < 0) {
			fprintf(stderr, "Error in db processing\n");
			ret = 8743;
		} else {
			fprintf(stderr, "Unable to find channel in db\n");
			ret = 2398;
		}
		break;
	default:
		fprintf(stderr, "Incorrect parameters\n");
	}

out:
	if (dbp != NULL)
		dbp->close(dbp, 0);
	if (dbp2 != NULL)
		dbp2->close(dbp2, 0);

	return ret;
}
