.PHONY: install man build

PREFIX ?= /usr/local
BIN_DIR := $(PREFIX)/bin
MAN_DIR := $(PREFIX)/share/man/man1

build:
	go generate
	go build -o mdns-discover

man: build
	./mdns-discover --man > mdns-discover.1

install: build man
	@echo "Installing binary to $(DESTDIR)$(BIN_DIR)"
	install -d "$(DESTDIR)$(BIN_DIR)"
	install -m 0755 mdns-discover "$(DESTDIR)$(BIN_DIR)/mdns-discover"
	@echo "Installing man page to $(DESTDIR)$(MAN_DIR)"
	install -d "$(DESTDIR)$(MAN_DIR)"
	gzip -c mdns-discover.1 > mdns-discover.1.gz
	install -m 0644 mdns-discover.1.gz "$(DESTDIR)$(MAN_DIR)/mdns-discover.1.gz"
	@echo "Done. Try: man mdns-discover"
