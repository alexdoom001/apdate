%%{
machine apdate_defs;

alphtype unsigned char;

proto_ident_ptype	= 0;
prod_ident_ptype	= 1;
upd_req_ptype		= 2;
upd_push_ptype		= 3;
cl_cert_up_ptype	= 4;

action err_out {
	goto out_bye;
}

action switch_proto {
	switch (*p) {
	case 1: 
		break;
	default:
		goto out_bye;
	}
}

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

action switch_product {
	product_tag = be32toh(i32);
}

proto_ident = any $switch_proto;
proto_ident_pack = proto_ident_ptype . proto_ident;
proto_ident_guard = ^proto_ident_ptype >err_out;

prod_ident = i32_recv @switch_product;
prod_ident_pack = prod_ident_ptype . prod_ident;
prod_ident_guard = ^prod_ident_ptype >err_out;

action set_upd_req_info {
	upd_req_version = be64toh(i64);
	push_updates(sess, upd_req_version, product_tag);
}

upd_req_info_version = i64_recv @set_upd_req_info;

upd_req_pack = upd_req_ptype . upd_req_info_version;
upd_req_guard = ^upd_req_ptype >err_out;

action set_plen {
	pk_byte_count = 0;
	pk_length = be32toh(i32);
}

action chk_plen {
	++pk_byte_count < pk_length
}

action recv_cl_cert {
}

action recv_upd_file {
	fsync(upfile);
	close(upfile);
}

action recv_file_byte {
	write(upfile, p, 1);
}

action recv_cl_byte {

}

action start_recv_file {
	strcpy(tname, TMP_FILE_PATTERN);
	upfile = mkstemp(tname);
	if (upfile < 0) {
		fprintf(stderr, "Can't create temp file\n");
	}
}

action start_recv_cl {
}

recv_length = i32_recv @set_plen;
recv_payload = ((any* when chk_plen) . (any when !chk_plen));

upd_push_pack = upd_push_ptype . recv_length . (recv_payload $recv_file_byte >start_recv_file) @recv_upd_file;
upd_push_guard = ^upd_push_ptype >err_out;

cl_cert_up_pack = cl_cert_up_ptype . recv_length . (recv_payload $recv_cl_byte >start_recv_cl) @recv_cl_cert;
cl_cert_up_guard = ^cl_cert_up_ptype >err_out;

}%%
