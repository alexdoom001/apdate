all: server client TAGS

SERVER=apds apdp
CLIENT=apdc apda
BINS=$(SERVER) $(CLIENT)

server: $(SERVER)
client: $(CLIENT)

graphs: apds_proto.png apdc_proto.png apdate_version.png apdate_products.png
	umbrello --export png umbrello.xmi

CFLAGS+=-g -D_GNU_SOURCE -Wall

TAGS: *.c *.h
	ctags -f TAGS $^

%.png: %.dot
	dot -Tpng -o $@ $<

%.dot: %.rl
	ragel -V $< > $@

apds: apds_proto.rr.o apds_main.o apds_cache_db.o apds_config.yy.o \
	apds_config.tab.o apds_inotify.o apdate_common.a apdate_products.rr.o \
	apds_file_cache.o
	$(CC) $(LDFLAGS) -lpthread -lgnutls -o $@ $^

apdc: apdc_proto.rr.o apdc_main.o apdc_config.yy.o apdc_config.tab.o apdate_common.a
	$(CC) $(LDFLAGS) -lgnutls -o $@ $^

apda: apda_main.o apdc_config.yy.o apdc_config.tab.o apdate_common.a \
	apdate_version.rr.o
	$(CC) $(LDFLAGS) -lgnutls -o $@ $^

apdate_common.a: apdate_common.o
	$(AR) -q $@ $^

apdp: apdp_main.o apdp_config.yy.o apdp_config.tab.o apdate_common.o \
	apdate_version.rr.o apdate_products.rr.o
	$(CC) -lgnutls -o $@ $^

apds_proto.rr.c apdc_proto.rr.c: apdate_defs.rl

%.rr.c: %.rl
	ragel -G2 -o $@ $<

%.yy.c: %.l %.tab.h
	lex --nounput -o $@ $<

%.tab.c %.tab.h: %.y
	bison -d $<

install_client: client
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/var/db/apdc/patches
	install -d $(DESTDIR)/var/db/apdc/staging
	install -d $(DESTDIR)/usr/lib/apdc
	install -d $(DESTDIR)/etc/apdc

	install -m 0755 apdc $(DESTDIR)/usr/bin/
	install -m 0755 apda $(DESTDIR)/usr/lib/apdc/
	install -m 0755 unpackers/* $(DESTDIR)/usr/lib/apdc/
	install -m 0755 apdc_place_incoming $(DESTDIR)/usr/lib/apdc/
	install -m 0644 apdc.conf $(DESTDIR)/etc/apdc/

install_server: server
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/apdp
	install -d $(DESTDIR)/etc/apds
	install -d $(DESTDIR)/etc/apdp
	install -d $(DESTDIR)/var/db/apds

	install -m 0755 apds $(DESTDIR)/usr/bin
	install -m 0755 apdp $(DESTDIR)/usr/bin
	install -m 0644 apds.conf $(DESTDIR)/etc/apds/
	install -m 0644 products $(DESTDIR)/etc/apds/
	install -m 0644 apdp.conf $(DESTDIR)/etc/apdp/
	install -m 0644 products $(DESTDIR)/etc/apdp/
	install -m 0755 packers/* $(DESTDIR)/usr/lib/apdp/

clean:
	rm -f *~ *.dot *.png TAGS *.o *.yy.c $(BINS) *.tab.c *.tab.h *.a *.rr.c \
		*/*~

.PHONY: all clean server client install_client install_server