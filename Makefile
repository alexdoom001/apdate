all: apds TAGS

graphs: apds_proto.png apdc_proto.png

TAGS:
	ctags -f TAGS *.c *.h

%.png: %.dot
	dot -Tpng -o $@ $<

%.dot: %.rl
	ragel -V $< > $@

apds: apds_proto.o apds_main.o apds_cache_db.o

apds_proto.c: apds_proto.rl
	ragel -G2 $<

apdc_proto.c: apdc_proto.rl
	ragel -G2 $<

apds_proto.rl apdc_proto.rl: apdate_defs.rl
	touch $@

clean:
	rm -f *~ *.dot *.png TAGS *.o apds_proto.c apdc_proto.c

.PHONY: all clean
