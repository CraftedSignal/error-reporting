# syntax=docker/dockerfile:1

# Hardened container image for the error-reporting Cloud Function.
# Builds a statically-linked Go binary and runs it as a non-root user in a
# minimal distroless base image.

FROM golang:1.26.5-alpine AS builder

# Install git and ca-certificates for module downloads.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Download dependencies first to leverage Docker cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a statically-linked binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags=-static" \
    -a -installsuffix cgo \
    -o /bin/function \
    ./cmd/function

# --- Runtime image ---
FROM gcr.io/distroless/static-debian12:nonroot

# Copy CA certificates for HTTPS calls to Slack.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary.
COPY --from=builder /bin/function /function

# Run as non-root (distroless nonroot image uses UID 65532).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/function"]
