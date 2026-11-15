// Package contract berisi konstanta, tipe data JSON, dan interface Core yang
// dipakai bersama oleh CLI dan implementasi kriptografinya
package contract

import "crypto"

// Nilai schema dan batas ukuran dari spesifikasi
const (
	ManifestSchema        = "minisign-manifest/v1"
	BundleSchema          = "minisign-bundle/v1"
	TrustSchema           = "minisign-trust/v1"
	MaxManifest           = 16 * 1024        // batas manifest dalam byte (16 KiB)
	MaxBundle             = 64 * 1024        // batas bundle dalam byte (64 KiB)
	MaxArtifactSize int64 = 9007199254740991 // 2^53 - 1
)

// Artifact berisi data file yang ditandatangani
type Artifact struct {
	Name   string `json:"name"`   // regex ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$
	Size   int64  `json:"size"`   // 0 sampai MaxArtifactSize
	SHA256 string `json:"sha256"` // 64 hex huruf kecil
}

// Manifest adalah isi yang ditandatangani. Bentuk byte-nya harus canonical.
type Manifest struct {
	Schema    string   `json:"schema"`    // harus ManifestSchema
	Package   string   `json:"package"`   // regex ^[a-z0-9][a-z0-9._-]{0,63}$
	Version   string   `json:"version"`   // regex ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$
	Algorithm string   `json:"algorithm"` // nama profil, lihat Supported
	KeyID     string   `json:"keyid"`     // SHA-256 SPKI kunci publik, 64 hex huruf kecil
	Artifact  Artifact `json:"artifact"`
}

// Bundle adalah file hasil sign. Isinya manifest dan signature dalam Base64.
type Bundle struct {
	Schema       string `json:"schema"` // harus BundleSchema
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// Entry adalah satu kunci di trust store
type Entry struct {
	KeyID        string   `json:"keyid"`
	Algorithm    string   `json:"algorithm"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Packages     []string `json:"packages"` // paket yang boleh ditandatangani kunci ini
}

// Store adalah isi file trust store
type Store struct {
	Schema string  `json:"schema"` // harus TrustSchema
	Keys   []Entry `json:"keys"`
}

// Core berisi fungsi kripto dan format yang dipakai CLI. Implementasinya ada di paket core.
//
//   - Generate membuat pasangan kunci baru dalam PEM (PKCS#8 dan SPKI)
//   - LoadPrivate dan LoadPublic membaca kunci PEM, lalu mengembalikan kunci, nama profil, dan keyid
//   - Sign menandatangani message dengan algoritma yang diminta
//   - Verify bernilai true hanya kalau signature valid
//   - StrictJSON mem-parse JSON secara ketat ke target (pointer ke struct)
//   - ParseManifest mem-parse manifest dan menolak yang tidak canonical
//   - CanonicalManifest mengubah manifest ke bentuk canonical
//   - DecodeBase64 men-decode Base64 standar yang canonical
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

// Supported mengecek apakah algorithm didukung, yaitu "rsa-pss-sha256",
// "ecdsa-p256-sha256", atau "ed25519"
func Supported(algorithm string) bool {
	return algorithm == "rsa-pss-sha256" || algorithm == "ecdsa-p256-sha256" || algorithm == "ed25519"
}
