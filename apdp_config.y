%{
#include <stdio.h>
#include <string.h>

#define YYSTYPE char *
    
    extern char *upddb, *keyfile, *certfile;
    extern FILE *yyin;
    extern int yylex(void);
    
    void yyerror(const char *str)
    {
	fprintf(stderr, "config error: %s\n", str);
    }

    int yywrap()
    {
	return 1;
    }
%}

%token EOL UPDDBPATH KEYFILE CERTFILE FILENAME QUOTE
%error-verbose

%%

input:
| input token;

token: EOL
| upddbdef
| keyfiledef
| certfiledef
;

upddbdef: UPDDBPATH QUOTE FILENAME QUOTE
{
    upddb = $3;
}
keyfiledef: KEYFILE QUOTE FILENAME QUOTE
{
    keyfile = $3;
}
certfiledef: CERTFILE QUOTE FILENAME QUOTE
{
    certfile = $3;
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
