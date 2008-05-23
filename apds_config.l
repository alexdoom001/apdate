%{
#include <stdio.h>
#define YYSTYPE char *
#define YY_NO_INPUT 1
#include "apds_config.tab.h"
%}

%%
update_db_path          return UPDDBPATH;
port                    return PORT;
key_file                return KEYFILE;
certificate_file        return CERTFILE;
ca_file                 return CAFILE;
crl_file                return CRLFILE;
debug                   return DEBUG;
[0-9]+                  yylval=strdup(yytext); return NUMBER;
\"                      return QUOTE;
[a-zA-Z0-9\/_][a-zA-Z0-9\/\._-]*       yylval=strdup(yytext); return FILENAME;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%
