%{
#include <stdio.h>
#include <string.h>

#include "apdc_main.h"

#define YYSTYPE char *
    
    extern char *cafile, *verfile, *certfile, *keyfile;
    extern char *apds_list[];
    extern int prodcode;
    extern FILE *yyin;
 
    char apds_count = 0;
    void yyerror(const char *str) {
	fprintf(stderr, "config error: %s\n", str);
    }

    int yywrap() {
	return 1;
    }
%}

%token EOL CAFILE APDS_LIST FILENAME APDS_HOST QUOTE NUMBER PRODCODE VERFILE CERTFILE KEYFILE
%error-verbose

%%

input:
| input token;

token: EOL
| cafiledef
| apdsstring
| prodcode
| verfile
| certfile
| keyfile
;

cafiledef: CAFILE QUOTE FILENAME QUOTE
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
prodcode: PRODCODE NUMBER
{
    prodcode = atoi($2);
}

verfile: VERFILE QUOTE FILENAME QUOTE
{
    verfile = $3;
}

certfile: CERTFILE QUOTE FILENAME QUOTE
{
    certfile = $3;
}

keyfile: KEYFILE QUOTE FILENAME QUOTE
{
    keyfile = $3;
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
