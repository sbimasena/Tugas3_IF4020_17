package b64_test

import (
	"fmt"

	"kelompok17/internal/b64"
)

func ExampleDecode() {
	data, err := b64.Decode("QQ==")
	fmt.Println(string(data), err)
	_, err = b64.Decode("QR==")
	fmt.Println(err)
	// Output:
	// A <nil>
	// base64: invalid or non-canonical encoding
}
