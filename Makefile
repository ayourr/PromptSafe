VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test dist clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/promptsafe ./cmd/promptsafe

test:
	go vet ./...
	go test ./...

dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/promptsafe-linux-amd64 ./cmd/promptsafe
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/promptsafe-linux-arm64 ./cmd/promptsafe
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/promptsafe-windows-amd64.exe ./cmd/promptsafe
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/promptsafe-windows-arm64.exe ./cmd/promptsafe
	cp scripts/install.sh scripts/install.ps1 dist/
	cd dist && sha256sum * > checksums.txt

clean:
	rm -rf bin dist
