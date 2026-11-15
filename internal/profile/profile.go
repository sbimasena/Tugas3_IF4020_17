// Package profile berisi tiga profil tanda tangan: RSA-PSS SHA-256,
// ECDSA P-256 SHA-256, dan Ed25519
package profile

import (
	"crypto"
	"errors"
)

// Nama profil, sama dengan yang dipakai di manifest dan CLI
const (
	RSAPSS  = "rsa-pss-sha256"    // RSA 3072 bit, e = 65537, PSS salt 32 byte, signature 384 byte
	ECDSA   = "ecdsa-p256-sha256" // P-256, signature r‖s 64 byte
	Ed25519 = "ed25519"           // signature 64 byte
)

// ErrKey muncul kalau jenis atau ukuran kunci tidak sesuai profil
var ErrKey = errors.New("profile: unsupported key type or parameters")

// Profile adalah satu algoritma tanda tangan
//
//   - Name mengembalikan nama profil, misalnya "ed25519"
//   - GenerateKey membuat kunci privat baru
//   - CheckKey mengembalikan ErrKey kalau pub bukan kunci untuk profil ini
//   - Sign menandatangani message dan mengembalikan ErrKey kalau priv bukan kunci untuk profil ini
//   - Verify bernilai false (bukan error) kalau kunci beda profil,
//     panjang signature salah, atau signature tidak valid
type Profile interface {
	Name() string
	GenerateKey() (crypto.Signer, error)
	CheckKey(pub crypto.PublicKey) error
	Sign(priv crypto.PrivateKey, message []byte) ([]byte, error)
	Verify(pub crypto.PublicKey, message, signature []byte) bool
}

var registry = []Profile{rsaPSS{}, ecdsaP256{}, ed25519Profile{}}

// Get mencari profil dari namanya. ok bernilai false kalau namanya tidak dikenal.
func Get(name string) (Profile, bool) {
	for _, p := range registry {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

// ForKey mencari profil yang cocok dengan kunci publik pub. Mengembalikan ErrKey
// kalau tidak ada yang cocok, misalnya untuk RSA 2048 bit.
func ForKey(pub crypto.PublicKey) (Profile, error) {
	for _, p := range registry {
		if p.CheckKey(pub) == nil {
			return p, nil
		}
	}
	return nil, ErrKey
}

func checkPrivate(p Profile, priv crypto.PrivateKey) error {
	if signer, ok := priv.(crypto.Signer); ok && p.CheckKey(signer.Public()) == nil {
		return nil
	}
	return ErrKey
}
