%%{
machine apdate_defs;

proto_ident_ptype	= 0;
prod_ident_ptype	= 1;
upd_req_ptype		= 2;
upd_push_ptype		= 3;
upd_status_ptype	= 4;


action err_out {
	dump_connection();
}

action switch_proto {
	;
}

action fill_product {
	;
}

action switch_product {
	;
}

proto_ident = any $ switch_proto;
proto_ident_pack = (^proto_ident_ptype >err_out) | (proto_ident_ptype . proto_ident);

prod_ident = (any){4} $ fill_product @ switch_product;
prod_ident_pack = (^prod_ident_ptype >err_out) | (prod_ident_ptype . prod_ident);

upd_req_info_version = (any){8};

upd_req_info = (^upd_req_ptype >err_out) | (upd_req_ptype . upd_req_info_version);

action set_file_length {
	file_byte_count = 0;
	file_length = be32toh(*(fpc-3));
}

action file_length {
	file_byte_count++ < file_length;
}

upd_push_length = (any){4} %set_file_length;
upd_push_file = (any)+ when file_length;

upd_push = upd_push_ptype upd_push_length upd_push_file $ 10;

}%%
