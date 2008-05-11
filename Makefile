all: apdate_server apdate_client

apdate_server: apdate_server.png
apdate_client: apdate_client.png

%.png: %.dot
	dot -Tpng -o $@ $<

%.dot: %.rl
	ragel -V $< > $@

apdate_server.rl apdate_client.rl: apdate_defs.rl
	touch $@

.PHONY: all apdate_server apdate_client
