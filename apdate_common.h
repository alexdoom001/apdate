#ifndef APDATE_COMMON_H

#define APDATE_COMMON_H

#define APDS_DEF_PORT 790
#define MAX_BUF 1024
#define DH_BITS 1024

#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}

#endif
