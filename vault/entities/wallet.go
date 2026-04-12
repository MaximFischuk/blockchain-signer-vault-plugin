package entities

type Wallet struct {
	ID       string            `json:"id"`
	KeyID    string            `json:"key_id"`
	Chain    string            `json:"chain"`
	Address  string            `json:"address"`
	Metadata map[string]string `json:"metadata"`
}
