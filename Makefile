VERSION ?= 0.1.0
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

clean:
	rm -rf bin dist
