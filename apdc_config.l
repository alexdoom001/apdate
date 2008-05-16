%{
#include <stdio.h>
#define YYSTYPE char *
#include "apdc_config.tab.h"
%}

%%
ca_file                 return CAFILE;
apdate_servers          return APDS_LIST;
db_path                 return DBPATH;
cert_file               return CERTFILE;
key_file                return KEYFILE;
[0-9]+                  yylval=strdup(yytext); return NUMBER;
[a-zA-Z0-9.:-]+         yylval=strdup(yytext); return APDS_HOST;
[a-zA-Z0-9\/.-]+        yylval=strdup(yytext); return FILENAME;
\"                      return QUOTE;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%