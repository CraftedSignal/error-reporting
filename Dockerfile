# syntax=docker/dockerfile:1

# Hardened container image for the error-reporting Cloud Function.
# Builds a statically-linked Go binary and runs it as a non-root user in a
# scratch base image (minimal attack surface, no shell/package manager).

FROM golang:1.26-alpine AS builder

# Install git and ca-certificates for module downloads.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Download dependencies first to leverage Docker cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build statically-linked binaries. The default entrypoint remains the ingest
# function; Terraform overrides the command to /resolver for the worker service.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags=-static" \
    -o /bin/function \
    ./cmd/function

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags=-static" \
    -o /bin/resolver \
    ./cmd/resolver

# Prep stage: gather CA certs and a minimal passwd/group for scratch.
FROM alpine:3.24 AS prep

RUN apk add --no-cache ca-certificates && \
    mkdir -p /scratch/etc/ssl/certs && \
    cp /etc/ssl/certs/ca-certificates.crt /scratch/etc/ssl/certs/ && \
    echo "function:x:1000:1000::/app:/sbin/nologin" > /scratch/etc/passwd && \
    echo "function:x:1000:" > /scratch/etc/group

# --- Runtime image ---
FROM scratch

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.source="https://github.com/CraftedSignal/error-reporting" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=prep /scratch/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=prep /scratch/etc/passwd /etc/passwd
COPY --from=prep /scratch/etc/group /etc/group

# Copy the binary.
COPY --from=builder --chmod=755 /bin/function /function
COPY --from=builder --chmod=755 /bin/resolver /resolver

# Run as non-root.
USER 1000:1000

EXPOSE 8080

ENTRYPOINT ["/function"]
