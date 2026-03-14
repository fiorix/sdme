PREFIX ?= /usr/local
DESTDIR ?= $(PREFIX)

all:
	cargo build --release

install:
	install -Dm755 target/release/sdme $(DESTDIR)/bin/sdme

install-extras: install-man install-completions

install-man:
	install -Dm644 dist/sdme.1 $(DESTDIR)/share/man/man1/sdme.1

install-completions:
	install -dm755 $(DESTDIR)/share/bash-completion/completions
	target/release/sdme config completions bash > $(DESTDIR)/share/bash-completion/completions/sdme
	install -dm755 $(DESTDIR)/share/zsh/site-functions
	target/release/sdme config completions zsh > $(DESTDIR)/share/zsh/site-functions/_sdme
	install -dm755 $(DESTDIR)/share/fish/vendor_completions.d
	target/release/sdme config completions fish > $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

uninstall: uninstall-man uninstall-completions
	rm -f $(DESTDIR)/bin/sdme

uninstall-man:
	rm -f $(DESTDIR)/share/man/man1/sdme.1

uninstall-completions:
	rm -f $(DESTDIR)/share/bash-completion/completions/sdme
	rm -f $(DESTDIR)/share/zsh/site-functions/_sdme
	rm -f $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

dist/out/completions: all
	mkdir -p dist/out/completions
	target/release/sdme config completions bash > dist/out/completions/sdme.bash
	target/release/sdme config completions zsh > dist/out/completions/_sdme
	target/release/sdme config completions fish > dist/out/completions/sdme.fish

deb: dist/out/completions
	cargo deb --no-build

rpm: dist/out/completions
	cargo generate-rpm

pkg: dist/out/completions
	./dist/arch/build-pkg.sh

clean:
	cargo clean
	rm -rf dist/out

.PHONY: all install install-extras install-man install-completions uninstall uninstall-man uninstall-completions deb rpm pkg clean
