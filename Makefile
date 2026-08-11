# NetScan-WoL build targets.
#
# There are no external dependencies, so every target here works offline with
# nothing but a Go toolchain.

VERSION ?= 2.0.0
PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.Version=$(VERSION)

# Platforms built by `make release`.
PLATFORMS := linux/amd64 linux/arm64 linux/arm

.PHONY: all
all: build

.PHONY: build
build: ## Build both binaries into bin/
	@mkdir -p bin
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/nswhub ./cmd/nswhub
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/nswagent ./cmd/nswagent
	@echo "built bin/nswhub and bin/nswagent ($(VERSION))"

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: test-race
test-race: ## Run the test suite under the race detector
	go test -race ./...

.PHONY: test-raw
test-raw: ## Exercise the raw ARP socket path in a private network namespace
	@go test -c -o /tmp/nsw-scan.test ./internal/scan/
	@unshare -Ur -n --map-root-user bash -c '\
		ip link add dummy0 type dummy && \
		ip addr add 10.99.0.1/29 dev dummy0 && \
		ip link set dummy0 up && \
		/tmp/nsw-scan.test -test.run TestRawSweep -test.v'
	@rm -f /tmp/nsw-scan.test

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: check
check: vet test ## Vet and test

.PHONY: release
release: ## Cross-compile release binaries into dist/
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "  $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o dist/nswhub-$$os-$$arch ./cmd/nswhub; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o dist/nswagent-$$os-$$arch ./cmd/nswagent; \
	done
	@cd dist && sha256sum * > SHA256SUMS
	@echo "release binaries and checksums are in dist/"

.PHONY: images
images: ## Build container images with podman or docker
	$(eval RUNTIME := $(shell command -v podman || command -v docker))
	$(RUNTIME) build -f deploy/docker/Containerfile.hub \
		--build-arg VERSION=$(VERSION) -t netscan-wol-hub:$(VERSION) .
	$(RUNTIME) build -f deploy/docker/Containerfile.agent \
		--build-arg VERSION=$(VERSION) -t netscan-wol-agent:$(VERSION) .

.PHONY: install
install: build ## Install both binaries and grant the agent CAP_NET_RAW
	install -Dm0755 bin/nswhub $(DESTDIR)$(BINDIR)/nswhub
	install -Dm0755 bin/nswagent $(DESTDIR)$(BINDIR)/nswagent
	@# Raw sockets for ARP, rather than running the agent as root.
	@setcap cap_net_raw+ep $(DESTDIR)$(BINDIR)/nswagent 2>/dev/null \
		&& echo "granted CAP_NET_RAW to nswagent" \
		|| echo "note: could not set CAP_NET_RAW (needs root); ARP scanning will be degraded"

.PHONY: install-services
install-services: ## Install the systemd units
	install -Dm0644 deploy/systemd/nswhub.service $(DESTDIR)/etc/systemd/system/nswhub.service
	install -Dm0644 deploy/systemd/nswagent.service $(DESTDIR)/etc/systemd/system/nswagent.service
	@echo "run: systemctl daemon-reload && systemctl enable --now nswhub"

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin dist

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
