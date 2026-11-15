package contract_test

import (
	"fmt"

	"kelompok17/internal/contract"
)

func ExampleSupported() {
	fmt.Println(contract.Supported("ed25519"), contract.Supported("rsa-sha1"))
	// Output: true false
}
