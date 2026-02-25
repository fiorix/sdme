PREFIX ?= /usr/local
DESTDIR ?= $(PREFIX)

all:
	cargo build --release

install: install-man install-completions
	install -Dm755 target/release/sdme $(DESTDIR)/bin/sdme

install-man:
	install -Dm644 docs/sdme.1 $(DESTDIR)/share/man/man1/sdme.1

install-completions:
	install -dm755 $(DESTDIR)/share/bash-completion/completions
	target/release/sdme completions bash > $(DESTDIR)/share/bash-completion/completions/sdme
	install -dm755 $(DESTDIR)/share/zsh/site-functions
	target/release/sdme completions zsh > $(DESTDIR)/share/zsh/site-functions/_sdme
	install -dm755 $(DESTDIR)/share/fish/vendor_completions.d
	target/release/sdme completions fish > $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

uninstall: uninstall-man uninstall-completions
	rm -f $(DESTDIR)/bin/sdme

uninstall-man:
	rm -f $(DESTDIR)/share/man/man1/sdme.1

uninstall-completions:
	rm -f $(DESTDIR)/share/bash-completion/completions/sdme
	rm -f $(DESTDIR)/share/zsh/site-functions/_sdme
	rm -f $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

clean:
	cargo clean

.PHONY: all install install-man install-completions uninstall uninstall-man uninstall-completions clean
