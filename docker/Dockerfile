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

FROM alpine:latest

COPY --from=builder /app/blockchain-signer-vault-plugin /vault/plugins/blockchain-signer-vault-plugin
COPY --from=builder /app/SHA256SUM /vault/plugins/SHA256SUM

RUN apk add --no-cache ca-certificates 
RUN addgroup -S vault && adduser -S vault -G vault

# USER vault

ENTRYPOINT ["/vault/plugins/blockchain-signer-vault-plugin"]
