all: server client TAGS

SERVER=apds apdp apda
CLIENT=apdc apda apdi
BINS=$(SERVER) $(CLIENT)

server: $(SERVER)
client: $(CLIENT)

GLIB_INCLUDES := $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS := $(shell pkg-config --libs glib-2.0)
override CFLAGS+=-g -D_GNU_SOURCE -Wall $(GLIB_INCLUDES)

TAGS: *.c *.h
	ctags -e -f TAGS $^

%.png: %.dot
	dot -Tpng -o $@ $<

%.dot: %.rl
	ragel -V $< > $@

apds: apds_proto.rr.o apds_main.o apds_cache_db.o apds_config.yy.o \
	apds_config.tab.o apds_inotify.o apdate_common.a \
	apds_file_cache.o
	$(CC) $(LDFLAGS) $(GLIB_LIBS) -lpthread -lgnutls -lgcrypt -o $@ $^

apdc: apdc_proto.rr.o apdc_main.o apdc_config.yy.o apdc_config.tab.o apdate_common.a \
	apdate_client.a
	$(CC) $(LDFLAGS) $(GLIB_LIBS) -ldb -lgnutls -o $@ $^

apda: apda_main.o apdc_config.yy.o apdc_config.tab.o apdate_common.a \
	apdate_file.rr.o apdate_client.a
	$(CC) $(LDFLAGS) $(GLIB_LIBS) -lgnutls -ldb -o $@ $^

apdi: apdi_main.o apdc_config.yy.o apdc_config.tab.o apdate_common.a \
	apdate_file.rr.o apdate_client.a
	$(CC) $(LDFLAGS) $(GLIB_LIBS) -lgnutls -ldb -o $@ $^

apdate_common.a: apdate_common.o
	$(AR) -rs $@ $^

apdate_client.a: apdate_client.o
	$(AR) -rs $@ $^

apdp: apdp_main.o apdp_config.yy.o apdp_config.tab.o apdate_common.o
	$(CC) -lgnutls -o $@ $^

apds_proto.rr.c apdc_proto.rr.c: apdate_defs.rl
apds_proto.png apdc_proto.png: apdate_defs.rl

%.rr.c: %.rl
	ragel -G2 -o $@ $<

%.yy.c: %.l %.tab.h
	lex --nounput -o $@ $<

%.tab.c %.tab.h: %.y
	bison -d $<

install_client: client
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/var/lib/apdc/patches
	install -d $(DESTDIR)/var/lib/apdc/staging
	install -d $(DESTDIR)/usr/lib/apdc
	install -d $(DESTDIR)/etc/apdc
	install -d $(DESTDIR)/etc/apdc/certs
	install -d $(DESTDIR)/etc/init.d

	install -m 0755 apdc $(DESTDIR)/usr/bin/
	install -m 0755 apdi $(DESTDIR)/usr/bin/
	install -m 0755 apda $(DESTDIR)/usr/lib/apdc/
	install -m 0644 unpackers/unpackers-lib $(DESTDIR)/usr/lib/apdc/
	install -m 0755 unpackers/* $(DESTDIR)/usr/lib/apdc/
	install -m 0644 apdc.conf $(DESTDIR)/etc/apdc/
	install -m 0755 apdc-init $(DESTDIR)/etc/init.d/apdc
	install -m 0755 apdc-init-recovery $(DESTDIR)/etc/init.d/apdc-recovery
	install -m 0755 apdate-update $(DESTDIR)/usr/lib/apdc/

install_server: server
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/apdp/bases-all-runs
	install -d $(DESTDIR)/etc/apds
	install -d $(DESTDIR)/etc/apdp
	install -d $(DESTDIR)/var/lib/apds
	install -d $(DESTDIR)/etc/init.d

	install -m 0755 apds $(DESTDIR)/usr/bin
	install -m 0755 apdp $(DESTDIR)/usr/bin
	install -m 0644 apds.conf $(DESTDIR)/etc/apds/
	install -m 0644 apdp.conf $(DESTDIR)/etc/apdp/
	install -m 0644 apdc.conf $(DESTDIR)/etc/apdp/
	install -m 0755 apda $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/clamav-antivirus $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/extruder $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/idps-rules $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/packers-lib $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/spamassassin-antispam $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/unextrude $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/voluntary-pack $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/web-blacklists $(DESTDIR)/usr/lib/apdp/
	install -m 0755 packers/bases-all-runs/* $(DESTDIR)/usr/lib/apdp/bases-all-runs/
	install -m 0755 unpackers/unpackers-lib $(DESTDIR)/usr/lib/apdp/
	install -m 0755 apdp_verificator $(DESTDIR)/usr/lib/apdp/
	install -m 0755 apds-init $(DESTDIR)/etc/init.d/apds
	install -m 0755 apds-verificator-init $(DESTDIR)/etc/init.d/apds-verificator

clean:
	rm -f *~ *.dot *.png TAGS *.o *.yy.c $(BINS) *.tab.c *.tab.h *.a *.rr.c \
		*/*~

.PHONY: all clean server client install_client install_server
