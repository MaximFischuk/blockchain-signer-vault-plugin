package erc4337

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestRequestUserOperationToUserOperation(t *testing.T) {
	factory := common.HexToAddress("0xfA00000000000000000000000000000000000001")
	paymaster := common.HexToAddress("0xPa00000000000000000000000000000000000001")
	request := RequestUserOperation{
		Sender:                        common.HexToAddress("0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD"),
		Nonce:                         hexBig(7),
		Factory:                       &factory,
		FactoryData:                   hexutil.Bytes{0xca, 0xfe},
		CallData:                      hexutil.Bytes{0xde, 0xad},
		CallGasLimit:                  hexBig(2),
		VerificationGasLimit:          hexBig(1),
		PreVerificationGas:            hexBig(50_000),
		MaxPriorityFeePerGas:          hexBig(3),
		MaxFeePerGas:                  hexBig(4),
		Paymaster:                     &paymaster,
		PaymasterVerificationGasLimit: hexBig(5),
		PaymasterPostOpGasLimit:       hexBig(6),
		PaymasterData:                 hexutil.Bytes{0xbe, 0xef},
	}

	userOperation, err := request.ToUserOperation()
	require.NoError(t, err)
	require.Equal(t, request.Sender, userOperation.Sender)
	require.Equal(t, big.NewInt(7), userOperation.Nonce)
	require.Equal(t, append(factory.Bytes(), request.FactoryData...), userOperation.InitCode)
	require.Equal(t, []byte{0xde, 0xad}, userOperation.CallData)
	require.Equal(t, common.HexToHash("0x0000000000000000000000000000000100000000000000000000000000000002"), userOperation.AccountGasLimits)
	require.Equal(t, big.NewInt(50_000), userOperation.PreVerificationGas)
	require.Equal(t, common.HexToHash("0x0000000000000000000000000000000300000000000000000000000000000004"), userOperation.GasFees)
	expectedPaymasterAndData := append(paymaster.Bytes(), make([]byte, 15)...)
	expectedPaymasterAndData = append(expectedPaymasterAndData, 5)
	expectedPaymasterAndData = append(expectedPaymasterAndData, make([]byte, 15)...)
	expectedPaymasterAndData = append(expectedPaymasterAndData, 6, 0xbe, 0xef)
	require.Equal(t, expectedPaymasterAndData, userOperation.PaymasterAndData)
	require.Nil(t, userOperation.Signature)
}

func TestRequestUserOperationToUserOperationRejectsGasLimitOverUint128(t *testing.T) {
	request := RequestUserOperation{
		Nonce:                hexBig(0),
		CallGasLimit:         hexBig(1),
		VerificationGasLimit: (*hexutil.Big)(new(big.Int).Lsh(big.NewInt(1), 128)),
		PreVerificationGas:   hexBig(0),
		MaxFeePerGas:         hexBig(0),
		MaxPriorityFeePerGas: hexBig(0),
	}

	_, err := request.ToUserOperation()
	require.EqualError(t, err, "verificationGasLimit must be an unsigned uint128")
}

func hexBig(value int64) *hexutil.Big {
	return (*hexutil.Big)(big.NewInt(value))
}

func TestRequestUserOperationJSON(t *testing.T) {
	request := RequestUserOperation{
		Sender:               common.HexToAddress("0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD"),
		Nonce:                hexBig(7),
		CallData:             hexutil.Bytes{0xca, 0xfe},
		CallGasLimit:         hexBig(1),
		VerificationGasLimit: hexBig(2),
		PreVerificationGas:   hexBig(3),
		MaxFeePerGas:         hexBig(4),
		MaxPriorityFeePerGas: hexBig(5),
	}

	encoded, err := json.Marshal(request)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"sender": "0x9f22f7c0c9d5a27881d1b4a29d14a7f88547ddbd",
		"nonce": "0x7",
		"callData": "0xcafe",
		"callGasLimit": "0x1",
		"verificationGasLimit": "0x2",
		"preVerificationGas": "0x3",
		"maxFeePerGas": "0x4",
		"maxPriorityFeePerGas": "0x5"
	}`, string(encoded))
}

func TestHashUserOperationV07(t *testing.T) {
	userOperation := testUserOperation()
	entryPoint := common.HexToAddress("0x0000000071727De22E5E9d8bAF0edAc6f37da032")
	chainID := big.NewInt(1)

	hash, err := HashUserOperationV07(userOperation, entryPoint, chainID)
	require.NoError(t, err)
	require.Equal(t, expectedV07Hash(t, userOperation, entryPoint, chainID), hash)
}

func TestHashUserOperationV08(t *testing.T) {
	userOperation := testUserOperation()
	entryPoint := common.HexToAddress("0x0000000071727De22E5E9d8bAF0edAc6f37da032")
	chainID := big.NewInt(1)

	hash, err := HashUserOperationV08(userOperation, entryPoint, chainID)
	require.NoError(t, err)
	require.Equal(t, expectedV08Hash(t, userOperation, entryPoint, chainID, ethereumCrypto.Keccak256Hash(userOperation.PaymasterAndData)), hash)
}

func TestHashUserOperationV09ExcludesPaymasterSignature(t *testing.T) {
	userOperation := testUserOperation()
	entryPoint := common.HexToAddress("0x0000000071727De22E5E9d8bAF0edAc6f37da032")
	chainID := big.NewInt(1)
	paymasterPrefix := make([]byte, paymasterDataOffset)
	for index := range paymasterPrefix {
		paymasterPrefix[index] = byte(index)
	}
	signature := make([]byte, 65)
	for index := range signature {
		signature[index] = byte(index + 1)
	}
	userOperation.PaymasterAndData = append(paymasterPrefix, signature...)
	userOperation.PaymasterAndData = append(userOperation.PaymasterAndData, 0, byte(len(signature)))
	userOperation.PaymasterAndData = append(userOperation.PaymasterAndData, paymasterSignatureMagic...)

	hash, err := HashUserOperationV09(userOperation, entryPoint, chainID)
	require.NoError(t, err)
	signedData := append(append([]byte{}, paymasterPrefix...), paymasterSignatureMagic...)
	require.Equal(t, expectedV08Hash(t, userOperation, entryPoint, chainID, ethereumCrypto.Keccak256Hash(signedData)), hash)
}

func TestHashUserOperationRejectsInvalidUint256(t *testing.T) {
	userOperation := testUserOperation()
	userOperation.Nonce = new(big.Int).Lsh(big.NewInt(1), 256)

	_, err := HashUserOperationV08(userOperation, common.Address{}, big.NewInt(1))
	require.EqualError(t, err, "nonce must be an unsigned uint256")
}

func testUserOperation() UserOperation {
	return UserOperation{
		Sender:             common.HexToAddress("0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD"),
		Nonce:              big.NewInt(7),
		InitCode:           []byte{0x60, 0x00, 0x60, 0x00, 0xf3},
		CallData:           []byte{0xca, 0xfe, 0xba, 0xbe},
		AccountGasLimits:   common.HexToHash("0x000000000000000000000000000186a0000000000000000000000000000249f0"),
		PreVerificationGas: big.NewInt(50_000),
		GasFees:            common.HexToHash("0x00000000000000000000000000000064000000000000000000000000000003e8"),
		PaymasterAndData:   []byte{0xde, 0xad, 0xbe, 0xef},
		Signature:          []byte{0x01, 0x02, 0x03},
	}
}

func expectedV07Hash(t *testing.T, userOperation UserOperation, entryPoint common.Address, chainID *big.Int) common.Hash {
	t.Helper()
	packed := pack(t, []string{"address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"},
		userOperation.Sender,
		userOperation.Nonce,
		ethereumCrypto.Keccak256Hash(userOperation.InitCode),
		ethereumCrypto.Keccak256Hash(userOperation.CallData),
		userOperation.AccountGasLimits,
		userOperation.PreVerificationGas,
		userOperation.GasFees,
		ethereumCrypto.Keccak256Hash(userOperation.PaymasterAndData),
	)
	return ethereumCrypto.Keccak256Hash(pack(t, []string{"bytes32", "address", "uint256"}, ethereumCrypto.Keccak256Hash(packed), entryPoint, chainID))
}

func expectedV08Hash(t *testing.T, userOperation UserOperation, entryPoint common.Address, chainID *big.Int, paymasterAndDataHash common.Hash) common.Hash {
	t.Helper()
	domainHash := ethereumCrypto.Keccak256Hash(pack(t, []string{"bytes32", "bytes32", "bytes32", "uint256", "address"},
		ethereumCrypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
		ethereumCrypto.Keccak256Hash([]byte(entryPointDomainName)),
		ethereumCrypto.Keccak256Hash([]byte(entryPointDomainVersion)),
		chainID,
		entryPoint,
	))
	structHash := ethereumCrypto.Keccak256Hash(pack(t, []string{"bytes32", "address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"},
		packedUserOperationTypeHash,
		userOperation.Sender,
		userOperation.Nonce,
		ethereumCrypto.Keccak256Hash(userOperation.InitCode),
		ethereumCrypto.Keccak256Hash(userOperation.CallData),
		userOperation.AccountGasLimits,
		userOperation.PreVerificationGas,
		userOperation.GasFees,
		paymasterAndDataHash,
	))
	return ethereumCrypto.Keccak256Hash([]byte{0x19, 0x01}, domainHash.Bytes(), structHash.Bytes())
}

func pack(t *testing.T, types []string, values ...interface{}) []byte {
	t.Helper()
	arguments := make(abi.Arguments, len(types))
	for index, typ := range types {
		abiType, err := abi.NewType(typ, "", nil)
		require.NoError(t, err)
		arguments[index] = abi.Argument{Type: abiType}
	}
	encoded, err := arguments.Pack(values...)
	require.NoError(t, err)
	return encoded
}
