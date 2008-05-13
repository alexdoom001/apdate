%{
#include <stdio.h>
#define YYSTYPE char *
#include "apds_config.tab.h"
%}

%%
update_db_path          return UPDDBPATH;
port                    return PORT;
key_file                return KEYFILE;
certificate_file        return CERTFILE;
ca_file                 return CAFILE;
crl_file                return CRLFILE;
[0-9]+                  yylval=strdup(yytext); return NUMBER;
[a-zA-Z0-9\/. -]+       yylval=strdup(yytext); return FILENAME;
\"                      return QUOTE;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%