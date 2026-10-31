.PHONY: build test check fmt

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o dist/openbao-plugin-secrets-relay ./cmd/openbao-plugin-secrets-relay

test:
	go test -race ./...

check:
	@test -z "$$(gofmt -l $$(git ls-files -- '*.go'))" || { echo "Run make fmt"; exit 1; }
	go vet ./...
	go test -race ./...
	go mod verify

fmt:
	gofmt -w $$(git ls-files -- '*.go')
