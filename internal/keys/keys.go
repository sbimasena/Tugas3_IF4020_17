// Package keys berisi fungsi untuk membaca dan menulis kunci PEM serta menghitung keyid
package keys

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"kelompok17/internal/profile"
)

func decodePEM(data []byte, label string) ([]byte, error) {
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if block == nil || !bytes.HasPrefix(data, []byte("-----BEGIN")) || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("keys: expected exactly one PEM block")
	}
	if block.Type != label || len(block.Headers) != 0 {
		return nil, errors.New("keys: expected PEM label " + label)
	}
	return block.Bytes, nil
}

// KeyID menghitung SHA-256 dari DER SPKI kunci publik dan mengembalikannya dalam
// 64 karakter hex huruf kecil
func KeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), err
}

func identify(pub crypto.PublicKey) (string, string, error) {
	p, err := profile.ForKey(pub)
	if err != nil {
		return "", "", err
	}
	id, err := KeyID(pub)
	return p.Name(), id, err
}

// LoadPublic membaca kunci publik PEM "PUBLIC KEY" (SPKI), lalu mengembalikan kunci,
// nama profil (misalnya "ed25519"), dan keyid. data harus berisi tepat satu blok PEM
// tanpa header. Gagal kalau PEM tidak valid atau kuncinya tidak cocok dengan profil mana pun.
func LoadPublic(data []byte) (crypto.PublicKey, string, string, error) {
	der, err := decodePEM(data, "PUBLIC KEY")
	if err != nil {
		return nil, "", "", err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", "", err
	}
	name, id, err := identify(pub)
	return pub, name, id, err
}

// LoadPrivate sama seperti LoadPublic, tapi untuk kunci privat PEM "PRIVATE KEY"
// (PKCS#8). Nama profil dan keyid diambil dari kunci publiknya.
func LoadPrivate(data []byte) (crypto.PrivateKey, string, string, error) {
	der, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, "", "", err
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, "", "", err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, "", "", profile.ErrKey
	}
	name, id, err := identify(signer.Public())
	return priv, name, id, err
}

// Encode mengubah kunci privat ke PEM "PRIVATE KEY" (PKCS#8) dan kunci publiknya
// ke PEM "PUBLIC KEY" (SPKI)
func Encode(priv crypto.Signer) (privPEM, pubPEM []byte, err error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}
