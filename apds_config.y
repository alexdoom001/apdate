%{
#include <stdio.h>
#include <string.h>

#define YYSTYPE char *
    
    extern char *upddb, *port, *keyfile, *certfile, *cafile, *crlfile, *prodsfile;
    extern FILE *yyin;
    extern int yylex(void);
    extern int debug_print;
    
    void yyerror(const char *str)
    {
	fprintf(stderr, "config error: %s\n", str);
    }

    int yywrap()
    {
	return 1;
    }
%}

%token EOL UPDDBPATH PORT KEYFILE CERTFILE CAFILE CRLFILE NUMBER FILENAME QUOTE PRODSFILE DEBUG
%error-verbose

%%

input:
| input token;

 token: EOL
	 | upddbdef
	 | portdef
	 | keyfiledef
	 | certfiledef
	 | cafiledef
	 | crlfiledef
         | prodsfiledef
         | debugdef
	 ;

 upddbdef: UPDDBPATH QUOTE FILENAME QUOTE
     {
	 upddb = $3;
     }
 portdef: PORT NUMBER
     {
	 port = $2;
     }
 keyfiledef: KEYFILE QUOTE FILENAME QUOTE
     {
	 keyfile = $3;
     }
 certfiledef: CERTFILE QUOTE FILENAME QUOTE
     {
	 certfile = $3;
     }
 cafiledef: CAFILE QUOTE FILENAME QUOTE
     {
	 cafile = $3;
     }
 crlfiledef: CRLFILE QUOTE FILENAME QUOTE
     {
	 crlfile = $3;
     }
 prodsfiledef: PRODSFILE QUOTE FILENAME QUOTE
     {
	 prodsfile = $3;
     }
 debugdef: DEBUG
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
