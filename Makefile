PREFIX ?= /usr/local
DESTDIR ?= $(PREFIX)

all:
	cargo build --release

install:
	install -Dm755 target/release/sdme $(DESTDIR)/bin/sdme

install-extras: install-completions

install-completions:
	install -dm755 $(DESTDIR)/share/bash-completion/completions
	target/release/sdme config completions bash > $(DESTDIR)/share/bash-completion/completions/sdme
	install -dm755 $(DESTDIR)/share/zsh/site-functions
	target/release/sdme config completions zsh > $(DESTDIR)/share/zsh/site-functions/_sdme
	install -dm755 $(DESTDIR)/share/fish/vendor_completions.d
	target/release/sdme config completions fish > $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

uninstall: uninstall-completions
	rm -f $(DESTDIR)/bin/sdme

uninstall-completions:
	rm -f $(DESTDIR)/share/bash-completion/completions/sdme
	rm -f $(DESTDIR)/share/zsh/site-functions/_sdme
	rm -f $(DESTDIR)/share/fish/vendor_completions.d/sdme.fish

packaging/out/completions: all
	mkdir -p packaging/out/completions
	target/release/sdme config completions bash > packaging/out/completions/sdme.bash
	target/release/sdme config completions zsh > packaging/out/completions/_sdme
	target/release/sdme config completions fish > packaging/out/completions/sdme.fish

deb: packaging/out/completions
	cargo deb --no-build

rpm: packaging/out/completions
	cargo generate-rpm

pkg: packaging/out/completions
	./packaging/arch/build-pkg.sh

clean:
	cargo clean
	rm -rf packaging/out

e2e:
	sudo test/scripts/run-parallel.sh

e2e-quick:
	sudo test/scripts/run-parallel.sh --only verify-export \
		--only verify-build --only verify-interrupt

e2e-smoke:
	sudo test/scripts/smoke.sh

e2e-preflight:
	sudo test/scripts/preflight.sh

.PHONY: all install install-extras install-completions uninstall uninstall-completions deb rpm pkg clean e2e e2e-quick e2e-smoke e2e-preflight
