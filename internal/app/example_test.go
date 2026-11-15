package app_test

import (
	"fmt"
	"os"
	"path/filepath"

	"kelompok17/internal/app"
	"kelompok17/internal/core"
)

func Example() {
	dir, _ := os.MkdirTemp("", "app")
	defer os.RemoveAll(dir)
	path := func(name string) string { return filepath.Join(dir, name) }
	os.WriteFile(path("artifact.bin"), []byte("halo"), 0644)

	s := app.Service{Core: core.Core{}}
	info, _ := s.Keygen(app.KeygenOptions{Algorithm: "ed25519", Out: path("publisher")})
	s.TrustAdd(app.TrustAddOptions{Key: path("publisher.pub.pem"), Package: "demo", Store: path("trust.json")})
	s.Sign(app.SignOptions{File: path("artifact.bin"), Package: "demo", Version: "1.0.0", Key: path("publisher.key.pem"), Out: path("bundle.json")})

	opts := app.VerifyOptions{File: path("artifact.bin"), Bundle: path("bundle.json"), TrustStore: path("trust.json"), Package: "demo", Version: "1.0.0"}
	r, code := app.Verify(s.Core, opts)
	fmt.Println(r.Status, code, *r.KeyID == info.KeyID)
	opts.Version = "2.0.0"
	r, code = app.Verify(s.Core, opts)
	fmt.Println(r.Status, code)
	// Output:
	// OK 0 true
	// METADATA_MISMATCH 1
}
