#include <gnutls/gnutls.h>
#define TLS_SESSION_CACHE 1024
#define ETC_PREFIX "/etc/apds/"
#define MAX_BUF 1024
#define APDS_PORT 790
#define DH_BITS 1024


#define MAX_SESSION_ID_SIZE 32
#define MAX_SESSION_DATA_SIZE 512

#define KEYFILE ETC_PREFIX "key.pem"
#define CERTFILE ETC_PREFIX "cert.pem"
#define CAFILE ETC_PREFIX "ca.pem"
#define CRLFILE ETC_PREFIX "crl.pem"
#define APDSCONF ETC_PREFIX "apds.conf"

#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}

