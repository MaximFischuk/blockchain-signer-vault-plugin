package crypto

import "fmt"

// UnsupportedCurveError is returned when an operation is requested
// for a curve that is not supported by this plugin.
type UnsupportedCurveError string

func (e UnsupportedCurveError) Error() string {
	return fmt.Sprintf("unsupported curve: %q", string(e))
}

// KeyType classifies the mathematical family of a key pair.
// These align with the "kty" claim defined in RFC 7517 (JSON Web Key).
const (
	// KeyTypeEC represents Elliptic Curve keys used with ECDSA
	// (e.g. secp256k1, P-256).
	KeyTypeEC = "EC"

	// KeyTypeOKP represents Octet Key Pair keys used with EdDSA or ECDH
	// (e.g. Ed25519, X25519).
	KeyTypeOKP = "OKP"
)
