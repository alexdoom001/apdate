all: apds apdc TAGS

graphs: apds_proto.png apdc_proto.png

TAGS: *.c *.h
	ctags -f TAGS $^

%.png: %.dot
	dot -Tpng -o $@ $<

%.dot: %.rl
	ragel -V $< > $@

apds: apds_proto.o apds_main.o apds_cache_db.o apds_config.yy.o apds_config.tab.o
	$(CC) -lpthread -lgnutls -o $@ $^

apdc: apdc_proto.o apdc_main.o apdc_config.yy.o apdc_config.tab.o
	$(CC) -lgnutls -o $@ $^

apds_proto.c apdc_proto.c: %.c : %.rl
	ragel -G2 -o $@ $<

apds_proto.rl apdc_proto.rl: apdate_defs.rl
	touch $@

%.yy.c: %.l %.tab.h
	lex -o $@ $<

%.tab.c %.tab.h: %.y
	bison -d $<

clean:
	rm -f *~ *.dot *.png TAGS *.o apds_proto.c apdc_proto.c *.yy.c apds \
		*.tab.c *.tab.h apdc

.PHONY: all clean