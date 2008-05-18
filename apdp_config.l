%{
#include <stdio.h>
#define YYSTYPE char *
#define YY_NO_INPUT 1
#include "apdp_config.tab.h"
%}

%%
update_db_path          return UPDDBPATH;
key_file                return KEYFILE;
certificate_file        return CERTFILE;
products_file           return PRODFILE;
[a-zA-Z0-9\/. -]+       yylval=strdup(yytext); return FILENAME;
\"                      return QUOTE;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%