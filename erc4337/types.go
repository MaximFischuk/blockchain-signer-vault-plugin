package erc4337

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethereumMath "github.com/ethereum/go-ethereum/common/math"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	packedUserOperationType = "PackedUserOperation(address sender,uint256 nonce,bytes32 initCode,bytes32 callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes32 paymasterAndData)"
	entryPointDomainName    = "ERC4337"
	entryPointDomainVersion = "1"

	paymasterDataOffset          = 52
	paymasterSignatureSuffixSize = 10
)

var (
	packedUserOperationTypeHash = ethereumCrypto.Keccak256Hash([]byte(packedUserOperationType))
	paymasterSignatureMagic     = []byte{0x22, 0xe3, 0x25, 0xa2, 0x97, 0x43, 0x96, 0x56}

	v07UserOperationHashArguments   = mustABIArguments("bytes32", "address", "uint256")
	v07PackedUserOperationArguments = mustABIArguments(
		"address",
		"uint256",
		"bytes32",
		"bytes32",
		"bytes32",
		"uint256",
		"bytes32",
		"bytes32",
	)
)

// UserOperation is the packed Solidity representation accepted by EntryPoint
// versions 0.7, 0.8, and 0.9.
type UserOperation struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   common.Hash
	PreVerificationGas *big.Int
	GasFees            common.Hash
	PaymasterAndData   []byte
	Signature          []byte
}

// RequestUserOperation is eth_sendUserOperation's ERC-7769 request payload.
// EIP-7702 authorization and signature fields are intentionally excluded.
type RequestUserOperation struct {
	Sender                        common.Address  `json:"sender"`
	Nonce                         *hexutil.Big    `json:"nonce"`
	Factory                       *common.Address `json:"factory,omitempty"`
	FactoryData                   hexutil.Bytes   `json:"factoryData,omitempty"`
	CallData                      hexutil.Bytes   `json:"callData"`
	CallGasLimit                  *hexutil.Big    `json:"callGasLimit"`
	VerificationGasLimit          *hexutil.Big    `json:"verificationGasLimit"`
	PreVerificationGas            *hexutil.Big    `json:"preVerificationGas"`
	MaxFeePerGas                  *hexutil.Big    `json:"maxFeePerGas"`
	MaxPriorityFeePerGas          *hexutil.Big    `json:"maxPriorityFeePerGas"`
	Paymaster                     *common.Address `json:"paymaster,omitempty"`
	PaymasterVerificationGasLimit *hexutil.Big    `json:"paymasterVerificationGasLimit,omitempty"`
	PaymasterPostOpGasLimit       *hexutil.Big    `json:"paymasterPostOpGasLimit,omitempty"`
	PaymasterData                 hexutil.Bytes   `json:"paymasterData,omitempty"`
}

// ToUserOperation packs an ERC-7769 request into EntryPoint's packed format.
func (request RequestUserOperation) ToUserOperation() (UserOperation, error) {
	for name, value := range map[string]*hexutil.Big{
		"nonce":                request.Nonce,
		"callGasLimit":         request.CallGasLimit,
		"verificationGasLimit": request.VerificationGasLimit,
		"preVerificationGas":   request.PreVerificationGas,
		"maxFeePerGas":         request.MaxFeePerGas,
		"maxPriorityFeePerGas": request.MaxPriorityFeePerGas,
	} {
		if value == nil {
			return UserOperation{}, fmt.Errorf("%s is required", name)
		}
	}

	accountGasLimits, err := packUint128Pair("verificationGasLimit", (*big.Int)(request.VerificationGasLimit), "callGasLimit", (*big.Int)(request.CallGasLimit))
	if err != nil {
		return UserOperation{}, err
	}
	gasFees, err := packUint128Pair("maxPriorityFeePerGas", (*big.Int)(request.MaxPriorityFeePerGas), "maxFeePerGas", (*big.Int)(request.MaxFeePerGas))
	if err != nil {
		return UserOperation{}, err
	}
	paymasterAndData, err := packPaymasterAndData(request)
	if err != nil {
		return UserOperation{}, err
	}

	return UserOperation{
		Sender:             request.Sender,
		Nonce:              (*big.Int)(request.Nonce),
		InitCode:           packInitCode(request.Factory, request.FactoryData),
		CallData:           request.CallData,
		AccountGasLimits:   common.BytesToHash(accountGasLimits[:]),
		PreVerificationGas: (*big.Int)(request.PreVerificationGas),
		GasFees:            common.BytesToHash(gasFees[:]),
		PaymasterAndData:   paymasterAndData,
	}, nil
}

// HashUserOperationV07 returns EntryPoint v0.7's canonical user operation hash.
func HashUserOperationV07(userOperation UserOperation, entryPoint common.Address, chainID *big.Int) (common.Hash, error) {
	if err := validateUserOperation(userOperation, chainID); err != nil {
		return common.Hash{}, err
	}

	packedHash, err := hashPackedUserOperation(userOperation, ethereumCrypto.Keccak256Hash(userOperation.PaymasterAndData))
	if err != nil {
		return common.Hash{}, fmt.Errorf("encode packed user operation: %w", err)
	}
	encoded, err := v07UserOperationHashArguments.Pack(packedHash, entryPoint, chainID)
	if err != nil {
		return common.Hash{}, fmt.Errorf("encode EntryPoint v0.7 user operation hash: %w", err)
	}
	return ethereumCrypto.Keccak256Hash(encoded), nil
}

// HashUserOperationV08 returns EntryPoint v0.8's EIP-712 user operation hash.
func HashUserOperationV08(userOperation UserOperation, entryPoint common.Address, chainID *big.Int) (common.Hash, error) {
	return hashUserOperationTypedData(userOperation, entryPoint, chainID, ethereumCrypto.Keccak256Hash(userOperation.PaymasterAndData))
}

// HashUserOperationV09 returns EntryPoint v0.9's EIP-712 user operation hash.
// When paymasterAndData has a valid v0.9 signature suffix, that signature is excluded.
func HashUserOperationV09(userOperation UserOperation, entryPoint common.Address, chainID *big.Int) (common.Hash, error) {
	return hashUserOperationTypedData(userOperation, entryPoint, chainID, hashPaymasterAndDataV09(userOperation.PaymasterAndData))
}

func hashUserOperationTypedData(userOperation UserOperation, entryPoint common.Address, chainID *big.Int, paymasterAndDataHash common.Hash) (common.Hash, error) {
	if err := validateUserOperation(userOperation, chainID); err != nil {
		return common.Hash{}, err
	}

	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"PackedUserOperation": {
				{Name: "sender", Type: "address"},
				{Name: "nonce", Type: "uint256"},
				{Name: "initCode", Type: "bytes32"},
				{Name: "callData", Type: "bytes32"},
				{Name: "accountGasLimits", Type: "bytes32"},
				{Name: "preVerificationGas", Type: "uint256"},
				{Name: "gasFees", Type: "bytes32"},
				{Name: "paymasterAndData", Type: "bytes32"},
			},
		},
		PrimaryType: "PackedUserOperation",
		Domain: apitypes.TypedDataDomain{
			Name:              entryPointDomainName,
			Version:           entryPointDomainVersion,
			ChainId:           (*ethereumMath.HexOrDecimal256)(chainID),
			VerifyingContract: entryPoint.Hex(),
		},
		Message: apitypes.TypedDataMessage{
			"sender":             userOperation.Sender.Bytes(),
			"nonce":              userOperation.Nonce,
			"initCode":           ethereumCrypto.Keccak256(userOperation.InitCode),
			"callData":           ethereumCrypto.Keccak256(userOperation.CallData),
			"accountGasLimits":   userOperation.AccountGasLimits.Bytes(),
			"preVerificationGas": userOperation.PreVerificationGas,
			"gasFees":            userOperation.GasFees.Bytes(),
			"paymasterAndData":   paymasterAndDataHash.Bytes(),
		},
	}
	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash EntryPoint typed data: %w", err)
	}
	return common.BytesToHash(digest), nil
}

func hashPackedUserOperation(userOperation UserOperation, paymasterAndDataHash common.Hash) (common.Hash, error) {
	encoded, err := v07PackedUserOperationArguments.Pack(
		userOperation.Sender,
		userOperation.Nonce,
		ethereumCrypto.Keccak256Hash(userOperation.InitCode),
		ethereumCrypto.Keccak256Hash(userOperation.CallData),
		userOperation.AccountGasLimits,
		userOperation.PreVerificationGas,
		userOperation.GasFees,
		paymasterAndDataHash,
	)
	if err != nil {
		return common.Hash{}, err
	}
	return ethereumCrypto.Keccak256Hash(encoded), nil
}

func hashPaymasterAndDataV09(paymasterAndData []byte) common.Hash {
	dataLength := len(paymasterAndData)
	if dataLength < paymasterDataOffset+paymasterSignatureSuffixSize ||
		!bytes.Equal(paymasterAndData[dataLength-len(paymasterSignatureMagic):], paymasterSignatureMagic) {
		return ethereumCrypto.Keccak256Hash(paymasterAndData)
	}

	signatureLength := int(binary.BigEndian.Uint16(paymasterAndData[dataLength-paymasterSignatureSuffixSize : dataLength-len(paymasterSignatureMagic)]))
	if signatureLength == 0 || signatureLength > dataLength-paymasterDataOffset-paymasterSignatureSuffixSize {
		return ethereumCrypto.Keccak256Hash(paymasterAndData)
	}

	signedLength := dataLength - signatureLength - paymasterSignatureSuffixSize
	signedData := make([]byte, signedLength+len(paymasterSignatureMagic))
	copy(signedData, paymasterAndData[:signedLength])
	copy(signedData[signedLength:], paymasterSignatureMagic)
	return ethereumCrypto.Keccak256Hash(signedData)
}

func validateUserOperation(userOperation UserOperation, chainID *big.Int) error {
	for name, value := range map[string]*big.Int{
		"chainID":            chainID,
		"nonce":              userOperation.Nonce,
		"preVerificationGas": userOperation.PreVerificationGas,
	} {
		if value == nil {
			return fmt.Errorf("%s is required", name)
		}
		if value.Sign() < 0 || value.BitLen() > 256 {
			return fmt.Errorf("%s must be an unsigned uint256", name)
		}
	}
	return nil
}

func mustABIArguments(types ...string) abi.Arguments {
	arguments := make(abi.Arguments, len(types))
	for index, typ := range types {
		abiType, err := abi.NewType(typ, "", nil)
		if err != nil {
			panic(fmt.Sprintf("create ABI type %q: %v", typ, err))
		}
		arguments[index] = abi.Argument{Type: abiType}
	}
	return arguments
}

func packInitCode(factory *common.Address, factoryData []byte) []byte {
	if factory == nil {
		return nil
	}
	return append(factory.Bytes(), factoryData...)
}

func packPaymasterAndData(request RequestUserOperation) ([]byte, error) {
	if request.Paymaster == nil {
		return nil, nil
	}
	verificationGasLimit := big.NewInt(0)
	if request.PaymasterVerificationGasLimit != nil {
		verificationGasLimit = (*big.Int)(request.PaymasterVerificationGasLimit)
	}
	postOpGasLimit := big.NewInt(0)
	if request.PaymasterPostOpGasLimit != nil {
		postOpGasLimit = (*big.Int)(request.PaymasterPostOpGasLimit)
	}
	gasLimits, err := packUint128Pair("paymasterVerificationGasLimit", verificationGasLimit, "paymasterPostOpGasLimit", postOpGasLimit)
	if err != nil {
		return nil, err
	}
	return append(append(request.Paymaster.Bytes(), gasLimits[:]...), request.PaymasterData...), nil
}

func packUint128Pair(leftName string, left *big.Int, rightName string, right *big.Int) ([32]byte, error) {
	var packed [32]byte
	if err := validateUint128(leftName, left); err != nil {
		return packed, err
	}
	if err := validateUint128(rightName, right); err != nil {
		return packed, err
	}
	left.FillBytes(packed[:16])
	right.FillBytes(packed[16:])
	return packed, nil
}

func validateUint128(name string, value *big.Int) error {
	if value == nil {
		return fmt.Errorf("%s is required", name)
	}
	if value.Sign() < 0 || value.BitLen() > 128 {
		return fmt.Errorf("%s must be an unsigned uint128", name)
	}
	return nil
}
