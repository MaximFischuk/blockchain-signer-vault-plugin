package privatekeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	serviceErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
	operations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
)

func (c *controller) NewSignEthereumTypedDataOperation() *framework.PathOperation {
	successExample := Example200ResponseSignEthereumTypedData()
	return &framework.PathOperation{
		Callback:    c.signEthereumTypedDataHandler(),
		Summary:     "Sign EIP-712 typed data",
		Description: "Signs an eth_signTypedData_v4-compatible EIP-712 message using a secp256k1 key. The request body contains the standard types, primaryType, domain, and message fields.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a standard EIP-712 Mail message",
				Data:        exampleEIP712TypedData(),
				Response:    successExample,
			},
		},
		Responses: map[int][]framework.Response{
			200: {*successExample},
			400: {service.Example400Response()},
			404: {service.Example404Response()},
			500: {service.Example500Response()},
		},
	}
}

func (c *controller) signEthereumTypedDataHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError(service.IDLabel))
		}

		typedData, err := eip712TypedData(data)
		if err != nil {
			return serviceErrors.ErrorResponse(err)
		}

		ctx = log.Context(ctx, c.logger)
		signature, err := c.operations.SignEthereumTypedData().WithStorage(req.Storage).Execute(ctx, id, typedData)
		if err != nil {
			if isEthereumTypedDataClientError(err) {
				return serviceErrors.ErrorResponse(err)
			}
			var coreErr *coreErrors.Error
			if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
				return nil, nil
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return SignatureResponse(signature), nil
	}
}

func eip712TypedData(data *framework.FieldData) (apitypes.TypedData, error) {
	fields := []string{
		service.EIP712TypesLabel,
		service.EIP712PrimaryTypeLabel,
		service.EIP712DomainLabel,
		service.MessageLabel,
	}
	for _, field := range fields {
		if _, ok := data.GetOk(field); !ok {
			return apitypes.TypedData{}, coreErrors.MissingFieldError(field)
		}
	}

	payload, err := json.Marshal(map[string]any{
		service.EIP712TypesLabel:       data.Get(service.EIP712TypesLabel),
		service.EIP712PrimaryTypeLabel: data.Get(service.EIP712PrimaryTypeLabel),
		service.EIP712DomainLabel:      data.Get(service.EIP712DomainLabel),
		service.MessageLabel:           data.Get(service.MessageLabel),
	})
	if err != nil {
		return apitypes.TypedData{}, fmt.Errorf("encode EIP-712 typed data: %w", err)
	}

	var typedData apitypes.TypedData
	if err := json.Unmarshal(payload, &typedData); err != nil {
		return apitypes.TypedData{}, fmt.Errorf("decode EIP-712 typed data: %w", err)
	}
	return typedData, nil
}

func isEthereumTypedDataClientError(err error) bool {
	var typedDataErr *operations.InvalidEthereumTypedDataError
	if errors.As(err, &typedDataErr) {
		return true
	}
	return isSignClientError(err)
}

func exampleEIP712TypedData() map[string]any {
	return map[string]any{
		service.EIP712TypesLabel: map[string]any{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"Person": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "wallet", "type": "address"},
			},
			"Mail": []map[string]string{
				{"name": "from", "type": "Person"},
				{"name": "to", "type": "Person"},
				{"name": "contents", "type": "string"},
			},
		},
		service.EIP712PrimaryTypeLabel: "Mail",
		service.EIP712DomainLabel: map[string]any{
			"name":              "Ether Mail",
			"version":           "1",
			"chainId":           1,
			"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		},
		service.MessageLabel: map[string]any{
			"from": map[string]string{
				"name":   "Cow",
				"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
			},
			"to": map[string]string{
				"name":   "Bob",
				"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
			},
			"contents": "Hello, Bob!",
		},
	}
}
