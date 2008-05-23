%%{
machine apdate_defs;

alphtype unsigned char;

proto_ident_ptype	= 0;
prod_ident_ptype	= 1;
upd_push_ptype		= 2;
cl_cert_up_ptype	= 3;
certsub_ptype		= 4;
tech_ptype		= 5;
ver_ptype		= 6;
request_all_ptype	= 7;

software_ver_subtype	= 0;
bases_ver_subtype	= 1;
personal_ver_subtype	= 2;

products = "CLAMAV" | "SPAMASSASSIN" | "SQUIDGUARD" |
	"SNORT" | "CERT" | "L7PROTO" | "BASE_BIN";

action fill_i32 {
	((unsigned char *) &i32)[intcnt] = *p;
	intcnt++;
}

action fill_i64 {
	((unsigned char *) &i64)[intcnt] = *p;
	intcnt++;
}

action zero_intcnt {
	intcnt = 0;
}

i32_recv = any{4} $fill_i32 >zero_intcnt;
i64_recv = any{8} $fill_i64 >zero_intcnt;

action mark_ts {
	ts = p;
}

action get_rev {
	revision = be64toh(i64);

}

action get_prodstr {
	product = strdup((char *) ts);
}

action get_verstr {
	version = strdup((char *) ts);
}

action handle_up_prod {
	struct up_prod req;
	char *q;

	req.prod = (char *) product;
	req.ver = (char *) version;
	req.rev = revision;

	DEBUG(syslog(LOG_INFO, "%lli: request: %s %s %llu\n",
		     (long long int) pthread_self(), req.prod, req.ver,
		     (long long unsigned int) req.rev));
		
	q = mkpatchpath(upddb, &req);
	if (q == NULL) {
		ret = APDS_UNRECOVERABLE_ERROR;
	} else
		if (access(q, R_OK) == 0)
			push_update(q);
		else {
			inotify_sub(q);
			g_array_append_val(apdss.reqs, q);

			/* Look for create/watch race */
			if (access(q, R_OK) == 0) {
				push_update(q);
				inotify_unsub(apdss.reqs->len - 1);
			}
		}
	free(product);
	free(version);
}

proto_ident_1 = 1;
proto_ident_2 = 2;
proto_ident1_pack = proto_ident_ptype . (proto_ident_1);
proto_ident2_pack = proto_ident_ptype . (proto_ident_2);

prodstr = (products . '\0') >mark_ts @get_prodstr;
verstr = (print+ . '\0') >mark_ts @get_verstr;
rev = i64_recv @get_rev;
prod_ident_pack = prod_ident_ptype . prodstr . verstr . rev @handle_up_prod;

action set_elen {
	en_byte_count = 0;
	en_length = be32toh(i32);
}

action chk_elen {
	++en_byte_count < en_length
}

action recv_cl_cert {
}

action recv_certsub {
	int ncerts;

	tlsdata.data = fmap;
	tlsdata.size = en_length;
	DEBUG(syslog(LOG_DEBUG, "%lli: Received certificate from client, loading...",
		     (long long int) pthread_self()));

	ncerts = load_certificate_ram(&tlscrt, tlsdata);
	if (ncerts <= 0) {
		syslog(LOG_ERR, "%lli: Failed to load received certificate",
		       (long long int) pthread_self());
		goto out_bye;
	} else {
		char *str;
		unsigned int verify;

		str = get_cert_field_by_oid(tlscrt[0], "2.5.4.5", 1);
		if (str == NULL) {
			syslog(LOG_ERR, "%lli: Error getting serial from certificate",
			       (long long int) pthread_self());
			goto out_bye;
		}

		if (apdss.serial == NULL)
			apdss.serial = str;
		else {
			if (strcmp(apdss.serial, str) != 0) {
				syslog(LOG_ERR, "Mismatched serials in subsequent certificates: %s vs %s",
				       apdss.serial, str);
				free(str);
				goto out_bye;
			}
			free(str);
		}

		str = get_cert_field_by_oid(tlscrt[0], "2.5.4.42", 1);
		if (str == NULL) {
			syslog(LOG_ERR, "%lli: Error getting product from certificate",
			       (long long int) pthread_self());			
			goto out_bye;
		}

		if (apdss.product == NULL)
			apdss.product = str;
		else {
			if (strcmp(apdss.product, str) != 0) {
				syslog(LOG_ERR, "Mismatched products in subsequent certificates: %s vs %s",
				       apdss.product, str);
				free(str);
				goto out_bye;
			}
			free(str);
		}

		str = get_cert_field_by_oid(tlscrt[0], "2.5.4.46", 1);
		if (str == NULL) {
			syslog(LOG_ERR, "%lli: Error getting type from certificate",
			       (long long int) pthread_self());			
			goto out_bye;
		}

		ret = gnutls_x509_crt_list_verify(tlscrt, ncerts, calist, calist_size, crl,
						  1, 0, &verify);
		if (ret < 0) {
			syslog(LOG_ERR, "Failed to verify %s/%s certificate for %s machine",
			       apdss.product, str, apdss.serial);
			goto out_bye;
		}
		if (verify != 0)
			syslog(LOG_NOTICE, "Broken (expired?) certificate for %s/%s on %s device",
			       apdss.product, str, apdss.serial);
		else {
			char *chandir, *channel, *type, *chanreq, revb[200];
			int j, k, l, m, n;
			struct dirent **dirnames, **dir2names;

			chandir = g_build_filename(upddb, apdss.product, str, (char *) NULL);
			k = scandir(chandir, &dirnames, NULL, alphasort);
			if (k < 0) {
				syslog(LOG_ERR, "Unable to get type listing for %s/%s", apdss.product, str);
				free(str);
				goto out_bye;
			} else if (k == 0) {
				syslog(LOG_INFO, "No types for %s/%s", apdss.product, str);
			}
			for (j = 0; j < k; j++) {
				if (strcmp(dirnames[j]->d_name, ".") == 0 ||
				    strcmp(dirnames[j]->d_name, "..") == 0) {
					free(dirnames[j]);
					continue;
				}
				
				if (dirnames[j]->d_type & (DT_DIR | DT_LNK)) {
					type = g_build_path(G_DIR_SEPARATOR_S, chandir,
							       dirnames[j]->d_name,
							       G_DIR_SEPARATOR_S, (char *) NULL);
					m = scandir(type, &dir2names, NULL, alphasort);
					if (m < 0) {
						syslog(LOG_ERR, "Unable to get channel listing for %s/%s", apdss.product, str);
						free(str);
						goto out_bye;
					} else if (m == 0) {
						syslog(LOG_INFO, "No channels for %s/%s", apdss.product, str);
					}
					for (n = 0; n < m; n++) {
						if (strcmp(dir2names[n]->d_name, ".") == 0 ||
						    strcmp(dir2names[n]->d_name, "..") == 0) {
							free(dir2names[n]);
							continue;
						}
						if (dir2names[n]->d_type & (DT_DIR | DT_LNK)) {
							channel = g_build_path(G_DIR_SEPARATOR_S, type,
									       dir2names[n]->d_name,
									       G_DIR_SEPARATOR_S, (char *) NULL);
							for (l = 0; l < apdss.reqs->len; l++)
								if (strncmp(channel, g_array_index(apdss.reqs, char *, l),
									    strlen(channel)) == 0)
									break;
							if (l == apdss.reqs->len) {
								char *typechan;

								DEBUG(syslog(LOG_DEBUG, "%lli: Adding %s to reqs",
									     (long long int) pthread_self(), channel));
								typechan = g_build_path(G_DIR_SEPARATOR_S, dirnames[j]->d_name,
											dir2names[n]->d_name, (char *) NULL);
								g_array_append_val(apdss.types, typechan);
								/*chanreq = g_build_filename(channel, "0", (char *) NULL);
								add_file_to_requests(chanreq);
								free(chanreq);*/
							} else
								syslog(LOG_INFO, "Tried to add %s to reqs, but already had %s in place",
								       channel, g_array_index(apdss.reqs, char *, l));
							free(channel);
						} else
							syslog(LOG_NOTICE, "Garbage in the channel dir: %s/%s/%s", apdss.product,
							       str, dir2names[n]->d_name);
						free(dir2names[n]);
					}
					free(dir2names);
					free(type);
				} else
					syslog(LOG_NOTICE, "Garbage in the type dir: %s/%s/%s", apdss.product,
					       str, dirnames[j]->d_name);
				free(dirnames[j]);
			}
			free(dirnames);
			free(chandir);
			chandir = g_build_filename(upddb, apdss.product, "personal", (char *) NULL);
			if (chandir == NULL)
				THREAD_ERR("g_build_filename error on chandir");
			snprintf(revb, 200, "%s-0", apdss.serial);
			chanreq = g_build_filename(chandir, revb, (char *) NULL);
			if (chanreq == NULL)
				THREAD_ERR("g_build_filename error on chanreq");
			DEBUG(syslog(LOG_DEBUG, "%lli: Adding %s to personal reqs",
				     (long long int) pthread_self(), chanreq));

			j = add_or_upd_request(chanreq, chandir);
			if (j < 0)
				THREAD_ERR("failed to add_or_upd_request");
			free(chandir);
			free(chanreq);
		}
		free(str);
	}
	free(fmap);
	for (i = 0; i < ncerts; i++) {
		gnutls_x509_crt_deinit(tlscrt[i]);
	}
	gnutls_free(tlscrt);
	fmap = NULL;
	tlsdata.data = NULL;
	tlsdata.size = 0;
	tlscrt = NULL;
}

action finish_recv_file {
	munmap(fmap, en_length);
	fmap = NULL;
	close(recvfile);
}

action process_upd_file {
	runcmd = malloc(512);
	sprintf(runcmd, "%s/apda %s apply-ro %s\n", libexec_path, conffile_name, tname);
	ret = system(runcmd);
	free(runcmd);
	unlink(tname);
	if (ret != 0) {
		syslog(LOG_ERR, "Failed to apply received update");
		goto out_bye;
	}
	send_request_list(session, &sw_reqs, &bs_reqs, &ps_reqs);
}

action recv_payload_byte {
	fmap[en_byte_count - 1] = *p;
}

action recv_cl_byte {

}

action start_recv_file {
	struct statvfs stvfs;
	strcpy(tname, TMP_FILE_PATTERN);
	recvfile = mkstemp(tname);
	if (recvfile < 0) {
		syslog(LOG_ERR, "Can't create temp file");
		goto out_bye;
	}
	if (fstatvfs(recvfile, &stvfs) < 0) {
		goto out_bye;
	}
	if (stvfs.f_bsize * stvfs.f_bfree < en_length) {
		goto out_bye;
	}
	if (ftruncate(recvfile, en_length) != 0) {
		syslog(LOG_ERR, "Can't truncate temp file");
		goto out_bye;
	}
	fmap = mmap(NULL, en_length, PROT_READ| PROT_WRITE, MAP_SHARED, recvfile,
		    0);
	if (fmap == MAP_FAILED) {
		syslog(LOG_ERR, "Can't mmap temp file");
		goto out_bye;
	}
}

action start_recv_cl {
}

action start_recv_string {
       	fmap = malloc(en_length + 1);
	if (fmap == NULL) {
		syslog(LOG_ERR, "Error allocating space for a %d byte string", i32);
		goto out_bye;
	}
}

action finish_recv_string {
	fmap[en_length] = 0;
}

action get_bases_ver {
	int j;

 	DEBUG(syslog(LOG_DEBUG, "%lli: Received bases ver packet for %s with %llu",
		     (long long int) pthread_self(), fmap, (unsigned long long int) revision));

	for (j = 0; j < apdss.types->len; j++)
		if (strcmp(g_array_index(apdss.types, char *, j), (char *) fmap) == 0)
			break;
	
	if (j == apdss.types->len)
		syslog(LOG_NOTICE, "Received request for unknown (%s) channel", fmap);
	else {
		char revb[20];
		char *chandir, *chanreq;

		chandir = g_build_filename(upddb, apdss.product, "bases", fmap, (char *) NULL);
		if (chandir == NULL)
			THREAD_ERR("g_build_filename error on chandir");
		sprintf(revb, "%llu", (unsigned long long int) revision);
		chanreq = g_build_filename(chandir, revb, (char *) NULL);
		if (chanreq == NULL)
			THREAD_ERR("g_build_filename error on chanreq");

		j = add_or_upd_request(chanreq, chandir);
		if (j < 0)
			THREAD_ERR("failed to add_or_upd_request in get_bases_ver");
		try_or_inotify_req(j);
		free(chandir);
		free(chanreq);
	}
	free(fmap);
	fmap = NULL;
}

action recv_ping {
	char fbuf[2];

	DEBUG(syslog(LOG_DEBUG, "%lli: got ping", PTH_ID));
	fbuf[0] = 5;
	fbuf[1] = 1;
	ret = gnutls_record_send(session, fbuf, 2);
	DEBUG(syslog(LOG_INFO, "%lli: timeout, sending ping", PTH_ID));
	if (ret < 0) {
		syslog(LOG_INFO, "%lli: failed to send pong\n", PTH_ID);
		goto out_bye;
	}
}

action recv_pong {
	DEBUG(syslog(LOG_DEBUG, "%lli: got pong", PTH_ID));
	ret = 0;
}

action recv_ready_for_updates {
	DEBUG(syslog(LOG_DEBUG, "%lli: Received ready-to-roll", (long long int) pthread_self()));
	apdss.got_ready_to_roll = 1;
	for (i = 0; i < apdss.reqs->len; i++)
		/* If request is pushed, we have something else on the same index */
		if (try_or_inotify_req(i) > 0)
			i--;
}

action get_main_sw_ver {
	i64tmp = revision;
}

action get_software_ver {
	int j;

 	DEBUG(syslog(LOG_DEBUG, "%lli: Received software ver packet for %s/%llu with %llu",
		     (long long int) pthread_self(), fmap, (unsigned long long int) i64tmp,
		     (unsigned long long int) revision));

	for (j = 0; j < apdss.types->len; j++)
		if (strcmp(g_array_index(apdss.types, char *, j), (char *) fmap) == 0)
			break;
	
	if (j == apdss.types->len)
		syslog(LOG_NOTICE, "Received software request for unknown (%s) channel", fmap);
	else {
		char revb[200];
		char *chandir, *chanreq;

		chandir = g_build_filename(upddb, apdss.product, "software", fmap, (char *) NULL);
		if (chandir == NULL)
			THREAD_ERR("g_build_filename error on chandir");
		sprintf(revb, "%llu", (unsigned long long int) i64tmp);
		chanreq = g_build_filename(chandir, revb, (char *) NULL);
		if (chanreq == NULL)
			THREAD_ERR("g_build_filename error on chanreq");

		j = add_or_upd_request(chanreq, chandir);
		free(chandir);
		free(chanreq);
		if (j < 0)
			THREAD_ERR("failed to add_or_upd_request in get_software_ver");
		j = try_or_inotify_req(j);
		/* If we've just pushed main update, no reason to add watches for hotfixes */
		if (j <= 0) {
			chandir = g_build_filename(upddb, apdss.product, "software", fmap, "hf", (char *) NULL);
			if (chandir == NULL)
				THREAD_ERR("g_build_filename error on chandir");
			snprintf(revb, 200, "%s-%llu-%llu", apdss.serial, (unsigned long long int) i64tmp,
				 (unsigned long long int) revision);
			chanreq = g_build_filename(chandir, revb, (char *) NULL);
			if (chanreq == NULL)
				THREAD_ERR("g_build_filename error on chanreq");
			j = add_or_upd_request(chanreq, chandir);
			free(chandir);
			free(chanreq);
			if (j < 0)
				THREAD_ERR("failed to add_or_upd_request in get_software_ver");
			try_or_inotify_req(j);
		}
	}
	free(fmap);
	fmap = NULL;
}

action get_personal_ver {
	int j;
	char revb[200];

	DEBUG(syslog(LOG_DEBUG, "%lli: Received personal ver packet for %s with %llu",
		     (long long int) pthread_self(), fmap, (unsigned long long int) revision));

	char *chandir, *chanreq;

	chandir = g_build_filename(upddb, apdss.product, "personal", (char *) NULL);
	if (chandir == NULL)
		THREAD_ERR("g_build_filename error on chandir");
	snprintf(revb, 200, "%s-%llu", apdss.serial, (unsigned long long int) revision);
	chanreq = g_build_filename(chandir, revb, (char *) NULL);
	if (chanreq == NULL)
		THREAD_ERR("g_build_filename error on chanreq");

	j = add_or_upd_request(chanreq, chandir);
	free(chandir);
	free(chanreq);
	if (j < 0)
		THREAD_ERR("failed to add_or_upd_request in get_software_ver");
	try_or_inotify_req(j);
	free(fmap);
	fmap = NULL;
}

action get_request_all {
	int j;

 	DEBUG(syslog(LOG_INFO, "%lli: Received request for all-compatible update of %s",
		     (long long int) pthread_self(), fmap));

	for (j = 0; j < apdss.types->len; j++)
		if (strcmp(g_array_index(apdss.types, char *, j), (char *) fmap) == 0)
			break;
	
	if (j == apdss.types->len)
		syslog(LOG_NOTICE, "Received all request for unknown (%s) channel", fmap);
	else {
		char *chanreq, *chandir;

		chandir = g_build_filename(upddb, apdss.product, "bases", fmap, (char *) NULL);
		if (chandir == NULL)
			THREAD_ERR("g_build_filename error on chandir");

		chanreq = g_build_filename(upddb, apdss.product, "bases", fmap, "all", (char *) NULL);
		if (chanreq == NULL)
			THREAD_ERR("g_build_filename error on chanreq");
		j = add_or_upd_request(chanreq, chandir);
		free(chanreq);
		free(chandir);
		if (j < 0)
			THREAD_ERR("failed to add_or_upd_request in get_request_all");
		try_or_inotify_req(j);
	}
	free(fmap);
	fmap = NULL;
}


recv_length = i32_recv @set_elen;
c_string = (any - 0);
recv_payload = ((any* when chk_elen) . (any when !chk_elen));
recv_payload_string = ((c_string* when chk_elen) . (c_string when !chk_elen));

upd_push_pack = upd_push_ptype . recv_length . (recv_payload 
	$recv_payload_byte >start_recv_file) @finish_recv_file @process_upd_file;

cl_cert_up_pack = cl_cert_up_ptype . recv_length . (recv_payload $recv_cl_byte >start_recv_cl) @recv_cl_cert;

certsub_pack = certsub_ptype . recv_length . (recv_payload $recv_payload_byte >start_recv_string) @recv_certsub;

ping_tech = 0;
pong_tech = 1;
ready_for_updates_tech = 2;

ping_pack = tech_ptype . ping_tech @recv_ping;
pong_pack = tech_ptype . pong_tech @recv_pong;
ready_for_updates_pack = tech_ptype . ready_for_updates_tech @recv_ready_for_updates;

software_ver_pack = ver_ptype . software_ver_subtype . recv_length . (recv_payload_string >start_recv_string $recv_payload_byte) @finish_recv_string . rev @get_main_sw_ver . rev @get_software_ver;
bases_ver_pack = ver_ptype . bases_ver_subtype . recv_length . (recv_payload_string >start_recv_string $recv_payload_byte) @finish_recv_string . rev @get_bases_ver;
personal_ver_pack = ver_ptype . personal_ver_subtype . recv_length . (recv_payload_string >start_recv_string $recv_payload_byte) @finish_recv_string . rev @get_personal_ver;

request_all_pack = request_all_ptype . recv_length . (recv_payload_string >start_recv_string $recv_payload_byte) @finish_recv_string @get_request_all;

}%%
