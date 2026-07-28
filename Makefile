.PHONY: test run build deploy

test:
	go test ./...

run:
	go run ./cmd/function

build:
	go build -o bin/function ./cmd/function
