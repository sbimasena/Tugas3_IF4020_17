// Package b64 berisi encode dan decode Base64 standar (RFC 4648, pakai padding)
package b64

import (
	"encoding/base64"
	"errors"
)

// Encode mengubah data ke Base64 standar
func Encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// Decode mengubah s kembali ke byte. Gagal kalau s bukan Base64 yang valid atau tidak
// canonical, contohnya "QR==" atau ada spasi dan newline.
func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || Encode(data) != s {
		return nil, errors.New("base64: invalid or non-canonical encoding")
	}
	return data, nil
}
