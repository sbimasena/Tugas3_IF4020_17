package core_test

import (
	"fmt"

	"kelompok17/internal/core"
)

func ExampleCore() {
	var c core.Core
	msg := []byte("halo")
	privPEM, pubPEM, _ := c.Generate("ecdsa-p256-sha256")
	priv, alg, privID, _ := c.LoadPrivate(privPEM)
	sig, _ := c.Sign(alg, priv, msg)
	pub, _, pubID, _ := c.LoadPublic(pubPEM)
	fmt.Println(alg, privID == pubID)
	fmt.Println(c.Verify(alg, pub, msg, sig), c.Verify(alg, pub, []byte("lain"), sig))
	// Output:
	// ecdsa-p256-sha256 true
	// true false
}
