# Blockchain Signer Hashicorp Vault Plugin

Hashicorp Vault secrets plugin for storing blockchain signing keys and signing data without returning private key material. It uses Vault plugin multiplexing through `plugin.ServeMultiplex`.

Project inspired by [ConsenSys quorum-hashicorp-vault-plugin](https://github.com/ConsenSys/quorum-hashicorp-vault-plugin), which is no longer maintained.

## Supported signing

- Generic hashes, batches of hashes, and messages hashed with `sha256`, `keccak256`, `sha512`, or `sha3-256`.
- Ethereum legacy and EIP-1559 transactions.
- Ethereum EIP-712 typed data.
- Ethereum ERC-4337 UserOperations for EntryPoint versions 0.7, 0.8, and 0.9.

Ethereum signing requires a `secp256k1` key. Key generation also supports `ed25519` and `p256` for generic signing.

## Documentation

- Full HTTP API: [openapi.yaml](openapi.yaml)
- Ready-to-run HTTP client requests: [api.http](api.http)
- macOS Docker Compose example: [docker/docker-compose.macos.yaml](docker/docker-compose.macos.yaml)
- Linux container runtime example: [docker/docker-compose.linux.yaml](docker/docker-compose.linux.yaml)

## Requirements

- Docker, with Docker daemon running.
- Docker Compose v2, available as `docker compose`.
- [mise](https://mise.jdx.dev/) for project tasks.

## Run with Docker on macOS

Build image and start Vault:

```sh
mise run service:run --detach
```

Vault listens on `http://localhost:8200`. Default development token is `DevVaultToken`. Plugin is enabled at mount path `signer`.

Stop service:

```sh
mise run service:stop
```

Remove service and plugin volume:

```sh
mise run service:down
```

## Run with Vault Container Plugin Runtime on Linux

Linux Compose example starts Vault with Docker socket proxy, registers `runc` as a container plugin runtime, and registers image `vault-signer` as plugin `blockchain-signer-vault-plugin`.

Build image, then start stack:

```sh
mise run image
docker compose -f docker/docker-compose.linux.yaml up -d
```

Container Plugin Runtime setup currently targets Linux only. Docker daemon must be available on host.

## Deploy plugin to Vault

Build binary and SHA256 file:

```sh
docker build -t vault-signer:latest -f docker/Dockerfile .
```

Copy `/vault/plugins/blockchain-signer-vault-plugin` and `/vault/plugins/SHA256SUM` from image into Vault's configured plugin directory. Then register and enable plugin:

```sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<vault-token>

vault plugin register \
  -sha256="$(cat /path/to/SHA256SUM)" \
  secret blockchain-signer-vault-plugin

vault secrets enable -path=signer blockchain-signer-vault-plugin
```

Vault configuration must set `plugin_directory` to directory containing binary and `SHA256SUM`.

## Requests

Set Vault connection values:

```sh
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=DevVaultToken
```

Create a secp256k1 key:

```sh
curl --request POST "$VAULT_ADDR/v1/signer/keys" \
  --header "X-Vault-Token: $VAULT_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"id":"ethereum-main","curve":"secp256k1"}'
```

Sign a hash:

```sh
curl --request POST "$VAULT_ADDR/v1/signer/keys/ethereum-main/sign/hash" \
  --header "X-Vault-Token: $VAULT_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"hash":"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"}'
```

Sign an EIP-1559 Ethereum transaction:

```sh
curl --request POST "$VAULT_ADDR/v1/signer/keys/ethereum-main/sign/ethereum/transaction" \
  --header "X-Vault-Token: $VAULT_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{
    "type":"0x2",
    "nonce":"0x0",
    "to":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "value":"0xde0b6b3a7640000",
    "gas":"0x5208",
    "maxPriorityFeePerGas":"0x3b9aca00",
    "maxFeePerGas":"0x6fc23ac00",
    "chainId":"0x1"
  }'
```

See [api.http](api.http) for batch hashes, message hashing, EIP-712 typed data, ERC-4337 UserOperations, key listing, and deletion.
