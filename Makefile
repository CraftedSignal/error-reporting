.PHONY: test run build lint fmt tidy clean

test:
	go test -race ./...

run:
	go run ./cmd/function

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/function ./cmd/function

lint:
	golangci-lint run --config=.github/golangci.yml

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/
