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
[a-zA-Z0-9\/_][a-zA-Z0-9\/\._-]*        yylval=strdup(yytext); return FILENAME;
\"                      return QUOTE;
\n                      return EOL;
[ \t]+                  /* ignore whitespace */;
%%
