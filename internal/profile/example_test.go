package profile_test

import (
	"fmt"

	"kelompok17/internal/profile"
)

func Example() {
	msg := []byte("halo")
	for _, name := range []string{profile.RSAPSS, profile.ECDSA, profile.Ed25519} {
		p, _ := profile.Get(name)
		priv, _ := p.GenerateKey()
		sig, _ := p.Sign(priv, msg)
		fmt.Println(name, len(sig), p.Verify(priv.Public(), msg, sig))
	}
	// Output:
	// rsa-pss-sha256 384 true
	// ecdsa-p256-sha256 64 true
	// ed25519 64 true
}

func ExampleGet() {
	p, ok := profile.Get(profile.Ed25519)
	fmt.Println(ok, p.Name())
	_, ok = profile.Get("rsa-sha1")
	fmt.Println(ok)
	// Output:
	// true ed25519
	// false
}

func ExampleRawToDER() {
	raw := make([]byte, 64)
	raw[31], raw[63] = 1, 2 // r = 1, s = 2
	der, _ := profile.RawToDER(raw)
	back, _ := profile.DERToRaw(der)
	fmt.Printf("%x %d\n", der, len(back))
	// Output: 3006020101020102 64
}
