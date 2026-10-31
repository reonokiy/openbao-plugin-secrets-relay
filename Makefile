.PHONY: build test check fmt local-init local-up local-status local-check local-password local-login local-down

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
	python3 -m unittest discover -s dev -p '*_test.py'

fmt:
	gofmt -w $$(git ls-files -- '*.go')

local-init: build
	python3 dev/local_openbao.py init

local-up: build
	python3 dev/local_openbao.py up

local-status:
	python3 dev/local_openbao.py status

local-check:
	python3 dev/local_openbao.py check

local-password:
	python3 dev/local_openbao.py password

local-login:
	python3 dev/local_openbao.py login

local-down:
	python3 dev/local_openbao.py stop
