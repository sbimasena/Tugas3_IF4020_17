package manifest_test

import (
	"bytes"
	"fmt"
	"strings"

	"kelompok17/internal/contract"
	"kelompok17/internal/manifest"
)

var m = contract.Manifest{
	Schema:    contract.ManifestSchema,
	Package:   "demo",
	Version:   "1.0.0",
	Algorithm: "ed25519",
	KeyID:     strings.Repeat("ab", 32),
	Artifact: contract.Artifact{
		Name:   "hello.txt",
		Size:   5,
		SHA256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
	},
}

func ExampleCanonical() {
	out, _ := manifest.Canonical(m)
	fmt.Println(string(out))
	// Output: {"schema":"minisign-manifest/v1","package":"demo","version":"1.0.0","algorithm":"ed25519","keyid":"abababababababababababababababababababababababababababababababab","artifact":{"name":"hello.txt","size":5,"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}
}

func ExampleParse() {
	canonical, _ := manifest.Canonical(m)
	_, err := manifest.Parse(canonical)
	fmt.Println(err)
	spaced := bytes.Replace(canonical, []byte(`,"package"`), []byte(`, "package"`), 1)
	_, err = manifest.Parse(spaced)
	fmt.Println(err)
	// Output:
	// <nil>
	// manifest: not in canonical form
}
