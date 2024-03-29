%{
#include <stdio.h>
#define YYSTYPE char *
#define YY_NO_INPUT 1
#include "apdc_config.tab.h"
%}

%%
ca_file                 return CAFILETOK;
apdate_servers          return APDS_LIST;
db_path                 return DBPATH;
cert_file               return CERTFILETOK;
key_file                return KEYFILETOK;
crl_file                return CRLFILETOK;
rev_file		return REVFILETOK;
libexec_path            return LIBEXECP;
upd_storage_path        return UPDSTORAGEP;
certs_dir		return CERTSDIR;
debug                   return DEBUGTOK;
[0-9]+                  yylval=strdup(yytext); return NUMBER;
[a-zA-Z0-9.:-]+         yylval=strdup(yytext); return APDS_HOST;
[a-zA-Z0-9\/.-]+        yylval=strdup(yytext); return FILENAME;
\"                      return QUOTE;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%
