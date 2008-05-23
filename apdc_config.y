%{
#include <stdio.h>
#include <string.h>

#include "apdc_main.h"

#define YYSTYPE char *
    
    extern FILE *yyin;
    extern int yylex(void);
 
    unsigned int apds_count = 0;
    void yyerror(const char *str) {
	fprintf(stderr, "config error: %s\n", str);
    }

    int yywrap() {
	return 1;
    }
%}

%token EOL CAFILETOK APDS_LIST FILENAME APDS_HOST QUOTE NUMBER DBPATH CERTFILETOK KEYFILETOK CRLFILETOK LIBEXECP UPDSTORAGEP CERTSDIR DEBUGTOK REVFILETOK
%error-verbose

%%

input:
| input token;

token: EOL
| cafiledef
| apdsstring
| dbpath
| certfile
| keyfile
| crlfile
| libexecpath
| updstoragepath
| certsdir
| debugdef
| revfile
;

cafiledef: CAFILETOK QUOTE FILENAME QUOTE
{
    cafile = $3;
}
 
apdsstring: APDS_LIST QUOTE apdslist QUOTE;

apdslist: apdshost | apdshost apdslist;

apdshost: APDS_HOST
     {
	 if (apds_count < APDC_MAX_LIST) {
	     apds_list[apds_count] = $1;
	     apds_count++;
	 } else {
	     yyerror("Too many apdate servers");
	     YYERROR;
	 }
     }

dbpath: DBPATH QUOTE FILENAME QUOTE
{
    dbpath = $3;
}

certfile: CERTFILETOK QUOTE FILENAME QUOTE
{
    certfile = $3;
}

keyfile: KEYFILETOK QUOTE FILENAME QUOTE
{
    keyfile = $3;
}

crlfile: CRLFILETOK QUOTE FILENAME QUOTE
{
    crlfile = $3;
}

revfile: REVFILETOK QUOTE FILENAME QUOTE
{
    revfile = $3;
}

libexecpath: LIBEXECP QUOTE FILENAME QUOTE
{
    libexec_path = $3;
}

updstoragepath: UPDSTORAGEP QUOTE FILENAME QUOTE
{
    upd_storage_path = $3;
}

certsdir: CERTSDIR QUOTE FILENAME QUOTE
{
    certsdir = $3;
}
debugdef: DEBUGTOK
{
    debug_print = 1;
}

%%

int conf_parse(char *conffile)
{
    int i;

    yyin = fopen(conffile, "r");
    if (!yyin)
	return 1;
    i = yyparse();
    fclose(yyin);
    return i;
}
