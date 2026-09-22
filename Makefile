.PHONY: build binary test test-race lint lint-darwin-ci vet guard cross install clean enclave

# clerk-protect is a PUBLIC binary. Four things here exist because of that:
#
#   * RELEASE_FLAGS build every artifact: -trimpath (no builder's file paths),
#     -buildvcs=false (no commit or dirty-tree stamp), and -s -w (no symbol
#     table and no DWARF, which names every function, type and source line).
#   * `binary` scans what it built before anything uses it: guardscan checks the
#     bytes for names that must never ship, every linked module against
#     allowed-modules.txt, and the artifact for debug information and vcs build
#     settings. `install` installs that scanned file rather than building
#     another, so no artifact this Makefile produces skips the scan.
#   * internal/guard's test builds and scans the same way for linux and windows
#     on amd64 and arm64, and for the host's darwin architecture.
#   * `cross`, because the Windows key store is compiled only on Windows and a
#     Mac or Linux leg would otherwise never notice it stopped building.
#
# The Secure Enclave shim (internal/keystore/enclave.swift) is Swift, and cgo
# does not compile Swift, so it becomes a static library before any darwin
# build. Every target that compiles Go depends on `enclave`. A bare `go build`
# on a Mac fails at link time with an undefined `_clerkprotect_enclave_sign`.

BIN           := clerk-protect
VERSION       ?= dev
RELEASE_FLAGS := -trimpath -buildvcs=false -ldflags "-s -w -X github.com/clerk/protect-cli/internal/version.Version=$(VERSION)"
INSTALL_DIR   ?= $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

# The forbidden-term list is private: it is the roster of internal names the
# scan keeps out of a public binary, so it is not in the public mirror
# (github.com/clerk/protect-cli). Where it exists, the scan uses it; where it
# does not, guardscan says the term check did not run rather than printing a
# clean scan it never made.
TERMS         := $(wildcard forbidden-terms.txt)
TERMS_FLAG    := $(if $(TERMS),-terms $(TERMS),)

# SWIFT_TARGET pins the macOS floor a RELEASE build deploys to, and is what
# makes a cross-architecture build possible at all: the shim has to be built for
# the architecture the Go build links. Empty for a local build, which targets
# this Mac's own OS.
#
#   GOARCH=amd64 CC="clang -arch x86_64" make binary SWIFT_TARGET=x86_64-apple-macos13
#
# Below macOS 13 the link wants Swift's back-deployment compatibility library,
# which this shim does not carry: the error names __swift_FORCE_LOAD_$_swiftCompatibility56.
# Changing SWIFT_TARGET does not rebuild an existing library — make compares it
# against the source, not the flags — so a release builds from a clean tree.
SWIFT_TARGET ?=
SWIFT_TARGET_FLAG := $(if $(SWIFT_TARGET),-target $(SWIFT_TARGET),)

# The floor has to reach the LINKER too, not only the shim. cgo links the Go
# binary through clang, and clang's default deployment target is this Mac's own
# SDK: a release built with only the shim pinned came out with `minos 26.5` —
# a binary that refuses to launch on every older Mac, while building, signing
# and running cleanly on the machine that made it. So the version at the end of
# SWIFT_TARGET ("arm64-apple-macos13" -> 13) is exported for clang as well.
ifneq ($(SWIFT_TARGET),)
export MACOSX_DEPLOYMENT_TARGET := $(lastword $(subst macos, ,$(SWIFT_TARGET)))
endif

ENCLAVE_DIR := internal/keystore
ENCLAVE_LIB := $(ENCLAVE_DIR)/libclerkprotectenclave.a
ENCLAVE_SRC := $(ENCLAVE_DIR)/enclave.swift

ifeq ($(shell uname -s),Darwin)
enclave: $(ENCLAVE_LIB)

$(ENCLAVE_LIB): $(ENCLAVE_SRC)
	swiftc -O -emit-library -static $(SWIFT_TARGET_FLAG) -o $@ $<
else
# Non-darwin builds compile no Swift.
enclave:
	@:
endif

build: binary
	go build ./...

binary: enclave
	go build $(RELEASE_FLAGS) -o $(BIN) ./cmd/clerk-protect
	@# The guard runs HERE, for this machine — not for the target. `go run`
	@# inherits GOOS and GOARCH, so a cross-build (GOOS=windows, or GOARCH=amd64
	@# on an Apple silicon Mac) would otherwise build the guard for the target and
	@# fail to execute it. Clearing them builds it for the host; it still scans the
	@# target binary, which is all it reads.
	GOOS= GOARCH= CGO_ENABLED= CC= go run ./tools/guardscan -allowlist allowed-modules.txt $(TERMS_FLAG) $(BIN)

# The scan is part of `binary`; `guard` is kept as its name.
guard: binary

install: binary
	install -d "$(INSTALL_DIR)"
	install -m 0755 $(BIN) "$(INSTALL_DIR)/$(BIN)"

test: enclave
	go test -count=1 ./...

test-race: enclave
	go test -race -count=1 ./...

vet: enclave
	go vet ./...

lint: enclave
	golangci-lint run ./...

# What CI's darwin leg runs instead of `lint`: the Linux leg lints everything it
# can compile, and the only code it cannot is darwin-constrained — the cgo/Swift
# keystore and the terminal check's darwin build. The guard keeps that scope
# honest: a darwin-constrained file anywhere else would be linted by no leg.
lint-darwin-ci: enclave
	@stray=$$({ grep -rlE '^//go:build .*darwin' --include='*.go' . | grep -vE '^\./internal/(keystore|term)/'; \
	            find . -name '*_darwin*.go' -not -path './internal/keystore/*' -not -path './internal/term/*'; } | sort -u); \
	if [ -n "$$stray" ]; then \
	  echo "lint-darwin-ci: darwin-constrained files outside internal/keystore and internal/term:"; \
	  echo "$$stray" | sed 's/^/  /'; \
	  exit 1; \
	fi
	golangci-lint run ./internal/keystore/... ./internal/term/...

cross:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath ./...
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./...
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath ./...
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./...
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...

clean:
	rm -f $(BIN) $(ENCLAVE_LIB)
