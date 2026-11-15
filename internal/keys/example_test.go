package keys_test

import (
	"fmt"

	"kelompok17/internal/keys"
	"kelompok17/internal/profile"
)

func ExampleLoadPublic() {
	p, _ := profile.Get(profile.Ed25519)
	priv, _ := p.GenerateKey()
	_, pubPEM, _ := keys.Encode(priv)
	_, name, keyid, err := keys.LoadPublic(pubPEM)
	fmt.Println(name, len(keyid), err)
	// Output: ed25519 64 <nil>
}
