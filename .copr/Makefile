# Copr "make_srpm" entry point.
#
# Copr clones this repo (at the pushed branch/tag) and runs, as root in a Fedora
# chroot with network:
#
#     make -f <repo>/.copr/Makefile srpm outdir=<dir> spec=<path>
#
# We delegate to the helper, which vendors the crate closure and builds a
# self-contained SRPM. Copr then builds the RPM from that SRPM fully offline
# (like Koji). Wired to GitHub via an SCM package + webhook so a tag push
# rebuilds automatically. See packaging/fedora/README.md.

# Absolute repo root, derived from this makefile's own path (.copr/Makefile).
REPO := $(patsubst %/.copr/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

srpm:
	cd "$(REPO)" && bash packaging/fedora/make-srpm.sh "$(outdir)"

.PHONY: srpm
