BINARY   := phantomfleet
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
IMAGE    ?= phantomfleet
GO       ?= go

.PHONY: all build test race lint fmt fmt-check vet tidy licenses docker snapshot clean help

all: fmt-check vet test build ## Format check, vet, test and build

build: ## Build the binary for the host platform
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test: ## Run unit tests
	$(GO) test ./...

race: ## Run unit tests with the race detector
	$(GO) test -race ./...

vet: ## go vet
	$(GO) vet ./...

lint: ## Run golangci-lint (https://golangci-lint.run/welcome/install/)
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run

fmt: ## Format sources
	gofmt -s -w .

fmt-check: ## Fail if any file needs gofmt
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy: ## go mod tidy
	$(GO) mod tidy

licenses: ## Collect third-party licence files into THIRD_PARTY_LICENSES/
	sh scripts/third-party-licenses.sh THIRD_PARTY_LICENSES

docker: ## Build the container image (tags $(IMAGE):$(VERSION) and $(IMAGE):dev)
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):dev .

snapshot: ## Local goreleaser dry run into ./dist
	goreleaser release --snapshot --clean

clean: ## Remove build outputs
	rm -rf $(BINARY) dist/ THIRD_PARTY_LICENSES/

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
