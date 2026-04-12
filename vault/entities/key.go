package entities

import "time"

type PrivateKey struct {
	ID         string            `json:"id"`
	KeyType    string            `json:"key_type"`
	Curve      string            `json:"curve"`
	PrivateKey string            `json:"private_key"`
	PublicKey  string            `json:"public_key"`
	Metadata   map[string]string `json:"metadata"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}
