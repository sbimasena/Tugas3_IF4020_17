package interop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kelompok17/internal/core"
	"kelompok17/internal/profile"
)

var (
	c       = core.Core{}
	message = []byte(`{"schema":"minisign-manifest/v1","package":"demo"}`)
	names   = []string{profile.RSAPSS, profile.ECDSA, profile.Ed25519}
	pss     = []string{"-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"}
	genArgs = map[string][]string{
		profile.RSAPSS:  {"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"},
		profile.ECDSA:   {"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"},
		profile.Ed25519: {"-algorithm", "ED25519"},
	}
)

func openssl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("openssl", args...).Output()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func files(t *testing.T, data map[string][]byte) func(string) string {
	dir := t.TempDir()
	for name, b := range data {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return func(name string) string { return filepath.Join(dir, name) }
}

func checkKeyID(t *testing.T, pubPath, want string) {
	sum := sha256.Sum256([]byte(openssl(t, "pkey", "-pubin", "-in", pubPath, "-outform", "DER")))
	if hex.EncodeToString(sum[:]) != want {
		t.Fatal("keyid differs from SHA256 of OpenSSL DER SPKI")
	}
}

func TestOursToOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
	for _, name := range names {
		privPEM, pubPEM, _ := c.Generate(name)
		key, _, keyid, _ := c.LoadPrivate(privPEM)
		sig, _ := c.Sign(name, key, message)
		if name == profile.ECDSA {
			sig, _ = profile.RawToDER(sig)
		}
		path := files(t, map[string][]byte{"key.pem": privPEM, "pub.pem": pubPEM, "msg": message, "sig": sig})

		block, _ := pem.Decode(pubPEM)
		if openssl(t, "pkey", "-in", path("key.pem"), "-pubout", "-outform", "DER") != string(block.Bytes) {
			t.Fatalf("%s: OpenSSL derived a different public key", name)
		}
		checkKeyID(t, path("pub.pem"), keyid)

		var out string
		switch name {
		case profile.RSAPSS:
			out = openssl(t, append(append([]string{"dgst", "-sha256"}, pss...), "-verify", path("pub.pem"), "-signature", path("sig"), path("msg"))...)
		case profile.ECDSA:
			out = openssl(t, "dgst", "-sha256", "-verify", path("pub.pem"), "-signature", path("sig"), path("msg"))
		case profile.Ed25519:
			out = openssl(t, "pkeyutl", "-verify", "-pubin", "-inkey", path("pub.pem"), "-rawin", "-in", path("msg"), "-sigfile", path("sig"))
		}
		t.Logf("%s: %s", name, strings.TrimSpace(out))
	}
}

func TestOpenSSLToOurs(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not in PATH")
	}
	for _, name := range names {
		path := files(t, map[string][]byte{"msg": message})
		openssl(t, append(append([]string{"genpkey"}, genArgs[name]...), "-out", path("key.pem"))...)
		openssl(t, "pkey", "-in", path("key.pem"), "-pubout", "-out", path("pub.pem"))
		switch name {
		case profile.RSAPSS:
			openssl(t, append(append([]string{"dgst", "-sha256"}, pss...), "-sign", path("key.pem"), "-out", path("sig"), path("msg"))...)
		case profile.ECDSA:
			openssl(t, "dgst", "-sha256", "-sign", path("key.pem"), "-out", path("sig"), path("msg"))
		case profile.Ed25519:
			openssl(t, "pkeyutl", "-sign", "-inkey", path("key.pem"), "-rawin", "-in", path("msg"), "-out", path("sig"))
		}

		privPEM, _ := os.ReadFile(path("key.pem"))
		pubPEM, _ := os.ReadFile(path("pub.pem"))
		sig, _ := os.ReadFile(path("sig"))
		_, privAlg, privID, err1 := c.LoadPrivate(privPEM)
		pub, pubAlg, pubID, err2 := c.LoadPublic(pubPEM)
		if err1 != nil || err2 != nil || privAlg != name || pubAlg != name || privID != pubID {
			t.Fatalf("%s: cannot load OpenSSL keys: %v %v", name, err1, err2)
		}
		checkKeyID(t, path("pub.pem"), pubID)
		if name == profile.ECDSA {
			sig, _ = profile.DERToRaw(sig)
		}
		ok := c.Verify(name, pub, message, sig)
		t.Logf("%s: OpenSSL signature verified by us: %v", name, ok)
		if !ok {
			t.Fatalf("%s: OpenSSL signature rejected", name)
		}
	}
}
