SHELL := /bin/sh
.DEFAULT_GOAL := help

.PHONY: help deps build format format-check lint test security check dry-run release-check

help:
	@printf '%s\n' \
		'make deps          install pinned local dependencies' \
		'make build         build the cf-vless CLI' \
		'make format        format authored Go and TypeScript files' \
		'make lint          run non-mutating format, type, and static checks' \
		'make test          run Go race tests and Worker runtime tests' \
		'make security      scan Go vulnerabilities and repository secrets' \
		'make check         run lint, tests, and security checks' \
		'make release-check run make check plus both Worker dry-run builds'

deps:
	git submodule update --init --recursive
	go mod download
	npm --prefix worker ci

build:
	mkdir -p bin
	go build -trimpath -o bin/cf-vless ./cmd/cf-vless

format:
	go fmt ./...
	npm --prefix worker run format

format-check:
	@unformatted="$$(git ls-files --cached --others --exclude-standard '*.go' | \
		while IFS= read -r file; do test ! -f "$$file" || gofmt -l "$$file"; done)"; \
		test -z "$$unformatted" || { printf 'gofmt required:\n%s\n' "$$unformatted"; exit 1; }
	npm --prefix worker run format:check
	npm --prefix worker run lint:docs

lint: format-check
	go tool actionlint
	go vet ./...
	go tool staticcheck ./cmd/... ./internal/... ./test/...
	go tool errcheck -exclude .errcheck-excludes.txt -ignoretests ./cmd/... ./internal/...
	npm --prefix worker run types:check
	npm --prefix worker run typecheck
	npm --prefix worker run lint

test:
	go test -race ./...
	npm --prefix worker test

security:
	go tool govulncheck -test ./...
	./test/security/no-secrets.sh

check: lint test security

dry-run:
	(cd worker && cf build)
	(cd worker && cf deploy --dry-run --message "cf-vless release preflight")
	npm --prefix worker exec -- wrangler deploy --cwd worker --dry-run --outdir dist

release-check: check dry-run
