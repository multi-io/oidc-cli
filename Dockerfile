ARG GO_VERSION=1.16.6
FROM golang:${GO_VERSION} AS builder
WORKDIR /go/src/github.com/multi-io/oidc-cli
COPY . .
RUN make build

FROM alpine:3.12

RUN apk add --no-cache ca-certificates

COPY --from=builder \
    /go/src/github.com/multi-io/oidc-cli/oidc-cli \
    /usr/local/bin/
COPY server/templates /usr/local/bin/server/templates
COPY server/assets /usr/local/bin/server/assets
USER nobody

WORKDIR /usr/local/bin

ENTRYPOINT /usr/local/bin/oidc-cli
