package sign

type SignOperations interface {
	SignHash() SignHashOperation
	SignMessage() SignMessageOperation
	SignBatchHashes() SignBatchHashesOperation
	SignEthereumTransaction() SignEthereumTransactionOperation
	SignEthereumTypedData() SignEthereumTypedDataOperation
	SignEthereumUserOperation() SignEthereumUserOperationOperation
}
