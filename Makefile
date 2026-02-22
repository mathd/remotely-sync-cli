BIN := s3sync-go

.PHONY: fmt test build tidy help

fmt:
	gofmt -w .

tidy:
	go mod tidy

test:
	go test ./...

build:
	go build -o $(BIN) .

help:
	go run . sync --help
