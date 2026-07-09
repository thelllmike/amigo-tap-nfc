CC      = cc
CFLAGS  = -O2 -Wall
LDFLAGS = -framework PCSC

nfctag: nfctag.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: nfctag
	install -m 755 nfctag /usr/local/bin/nfctag

clean:
	rm -f nfctag

.PHONY: install clean
