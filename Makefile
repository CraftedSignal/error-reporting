.PHONY: test run run-resolver build lint fmt tidy clean

test:
	GOWORK=off go test -race ./...

run:
	GOWORK=off go run ./cmd/function

run-resolver:
	GOWORK=off go run ./cmd/resolver

build:
	GOWORK=off CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/function ./cmd/function
	GOWORK=off CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/resolver ./cmd/resolver

lint:
	golangci-lint run --config=.github/golangci.yml

fmt:
	GOWORK=off go fmt ./...

tidy:
	GOWORK=off go mod tidy

clean:
	rm -rf bin/
