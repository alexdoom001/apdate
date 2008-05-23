#ifndef APDC_PROTO_H
#define APDC_PROTO_H 1

#include <gnutls/gnutls.h>

int apdc_proto(gnutls_session_t sess);

#define PTYPE_SOFTWARE 0
#define PTYPE_BASES 1
#define PTYPE_PERSONAL 2

#endif
