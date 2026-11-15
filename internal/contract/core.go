package contract

import "crypto"

const (
	ManifestSchema        = "minisign-manifest/v1"
	BundleSchema          = "minisign-bundle/v1"
	TrustSchema           = "minisign-trust/v1"
	MaxManifest           = 16 * 1024
	MaxBundle             = 64 * 1024
	MaxArtifactSize int64 = 9007199254740991
)

type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema    string   `json:"schema"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Algorithm string   `json:"algorithm"`
	KeyID     string   `json:"keyid"`
	Artifact  Artifact `json:"artifact"`
}

type Bundle struct {
	Schema       string `json:"schema"`
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
}

type Entry struct {
	KeyID        string   `json:"keyid"`
	Algorithm    string   `json:"algorithm"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Packages     []string `json:"packages"`
}

type Store struct {
	Schema string  `json:"schema"`
	Keys   []Entry `json:"keys"`
}

type Core interface {
	Generate(algorithm string) (privatePEM, publicPEM []byte, err error)
	LoadPrivate(pem []byte) (crypto.PrivateKey, string, string, error)
	LoadPublic(pem []byte) (crypto.PublicKey, string, string, error)
	Sign(algorithm string, key crypto.PrivateKey, message []byte) ([]byte, error)
	Verify(algorithm string, key crypto.PublicKey, message, signature []byte) bool
	StrictJSON(data []byte, target any) error
	ParseManifest(data []byte) (Manifest, error)
	CanonicalManifest(manifest Manifest) ([]byte, error)
	DecodeBase64(value string) ([]byte, error)
}

func Supported(algorithm string) bool {
	return algorithm == "rsa-pss-sha256" || algorithm == "ecdsa-p256-sha256" || algorithm == "ed25519"
}
