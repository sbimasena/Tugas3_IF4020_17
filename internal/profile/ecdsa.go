package profile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

type ecdsaP256 struct{}

func (ecdsaP256) Name() string { return ECDSA }

func (ecdsaP256) GenerateKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (ecdsaP256) CheckKey(pub crypto.PublicKey) error {
	if k, ok := pub.(*ecdsa.PublicKey); ok && k.Curve == elliptic.P256() {
		return nil
	}
	return ErrKey
}

func (p ecdsaP256) Sign(priv crypto.PrivateKey, message []byte) ([]byte, error) {
	if err := checkPrivate(p, priv); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	der, err := ecdsa.SignASN1(rand.Reader, priv.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		return nil, err
	}
	return DERToRaw(der)
}

func (p ecdsaP256) Verify(pub crypto.PublicKey, message, signature []byte) bool {
	if p.CheckKey(pub) != nil || len(signature) != 64 {
		return false
	}
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256(message)
	return ecdsa.Verify(pub.(*ecdsa.PublicKey), digest[:], r, s)
}

type ecdsaSig struct{ R, S *big.Int }

// DERToRaw mengubah signature ECDSA P-256 dari DER ke format r‖s 64 byte
// (r dan s masing-masing 32 byte). Gagal kalau DER tidak valid atau r, s di luar rentang.
func DERToRaw(der []byte) ([]byte, error) {
	var sig ecdsaSig
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 ||
		sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, errors.New("ecdsa: invalid DER signature")
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return raw, nil
}

// RawToDER kebalikan dari DERToRaw. Gagal kalau raw tidak 64 byte.
func RawToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, errors.New("ecdsa: raw signature must be 64 bytes")
	}
	return asn1.Marshal(ecdsaSig{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
}
