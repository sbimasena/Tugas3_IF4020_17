package trust_test

import (
	"fmt"
	"strings"

	"kelompok17/internal/contract"
	"kelompok17/internal/core"
	"kelompok17/internal/trust"
)

func ExampleAdd() {
	var s contract.Store
	e := contract.Entry{KeyID: strings.Repeat("ab", 32), Algorithm: "ed25519"}
	trust.Add(&s, e, "demo")
	trust.Add(&s, e, "tools")
	fmt.Println(len(s.Keys), s.Keys[0].Packages)
	fmt.Println(trust.Remove(&s, e.KeyID), len(s.Keys))
	fmt.Println(trust.Remove(&s, e.KeyID))
	// Output:
	// 1 [demo tools]
	// <nil> 0
	// keyid not found
}

func ExampleParse() {
	_, err := trust.Parse([]byte(`{"schema":"minisign-trust/v1","keys":[]}`), core.Core{})
	fmt.Println(err)
	_, err = trust.Parse([]byte(`{"schema":"lain","keys":[]}`), core.Core{})
	fmt.Println(err)
	// Output:
	// <nil>
	// invalid trust store schema or keys
}
