FROM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates upx

WORKDIR /app

ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -ldflags="-s -w" -a -v -o blockchain-signer-vault-plugin
RUN upx --best --lzma blockchain-signer-vault-plugin
RUN sha256sum -b blockchain-signer-vault-plugin | cut -d' ' -f1 > SHA256SUM
RUN ls -lh blockchain-signer-vault-plugin SHA256SUM

FROM hashicorp/vault:1.21

COPY --from=builder /app/blockchain-signer-vault-plugin /vault/plugins/blockchain-signer-vault-plugin
# COPY --from=builder /app/SHA256SUM /vault/plugins/SHA256SUM
COPY --chmod=755 scripts/vault-init-dev.sh /vault-init-dev.sh
RUN ls -lh /vault/plugins/blockchain-signer-vault-plugin /vault-init-dev.sh

RUN apk add bash curl jq
COPY --chmod=755 <<EOT /entrypoint.sh
#!/usr/bin/env bash
set -e
( sleep 5 ; /vault-init-dev.sh ) & vault server -dev -dev-plugin-dir=/vault/plugins/ -dev-listen-address="0.0.0.0:8200" -dev-root-token-id=DevVaultToken -log-level=trace
EOT

EXPOSE 8200

ENTRYPOINT ["/entrypoint.sh"]
