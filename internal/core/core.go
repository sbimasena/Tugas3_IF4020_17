// Package core adalah implementasi contract.Core. Isinya cuma menyambungkan
// paket profile, keys, manifest, strictjson, dan b64.
package core

import (
	"crypto"
	"errors"

	"kelompok17/internal/b64"
	"kelompok17/internal/contract"
	"kelompok17/internal/keys"
	"kelompok17/internal/manifest"
	"kelompok17/internal/profile"
	"kelompok17/internal/strictjson"
)

// Core adalah implementasi contract.Core. Tidak perlu diinisialisasi, cukup core.Core{}.
type Core struct{}

var _ contract.Core = Core{}

// Generate membuat pasangan kunci baru untuk algorithm, lalu mengembalikan kunci
// privat (PEM PKCS#8) dan kunci publik (PEM SPKI). Gagal kalau algorithm tidak didukung.
func (Core) Generate(algorithm string) ([]byte, []byte, error) {
	p, ok := profile.Get(algorithm)
	if !ok {
		return nil, nil, errors.New("unsupported algorithm")
	}
	priv, err := p.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return keys.Encode(priv)
}

// Sign menandatangani message dengan key. Gagal kalau algorithm tidak didukung
// atau key bukan untuk algorithm itu.
func (Core) Sign(algorithm string, key crypto.PrivateKey, message []byte) ([]byte, error) {
	p, ok := profile.Get(algorithm)
	if !ok {
		return nil, errors.New("unsupported algorithm")
	}
	return p.Sign(key, message)
}

// Verify bernilai true hanya kalau algorithm didukung dan signature valid
func (Core) Verify(algorithm string, key crypto.PublicKey, message, signature []byte) bool {
	p, ok := profile.Get(algorithm)
	return ok && p.Verify(key, message, signature)
}

// LoadPrivate sama dengan keys.LoadPrivate
func (Core) LoadPrivate(pem []byte) (crypto.PrivateKey, string, string, error) {
	return keys.LoadPrivate(pem)
}

// LoadPublic sama dengan keys.LoadPublic
func (Core) LoadPublic(pem []byte) (crypto.PublicKey, string, string, error) {
	return keys.LoadPublic(pem)
}

// StrictJSON sama dengan strictjson.Unmarshal
func (Core) StrictJSON(data []byte, target any) error { return strictjson.Unmarshal(data, target) }

// ParseManifest sama dengan manifest.Parse
func (Core) ParseManifest(data []byte) (contract.Manifest, error) { return manifest.Parse(data) }

// CanonicalManifest sama dengan manifest.Canonical
func (Core) CanonicalManifest(m contract.Manifest) ([]byte, error) { return manifest.Canonical(m) }

// DecodeBase64 sama dengan b64.Decode
func (Core) DecodeBase64(value string) ([]byte, error) { return b64.Decode(value) }
