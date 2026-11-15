package app

import (
	"errors"
	"fmt"
	"os"

	"kelompok17/internal/contract"
)

// Keygen membuat pasangan kunci baru lalu menyimpannya ke <Out>.key.pem (0600)
// dan <Out>.pub.pem (0644). Kalau salah satu file sudah ada, Keygen gagal kecuali
// Force diisi. Dengan Force, kalau penulisan gagal di tengah, file lama dikembalikan.
func (service Service) Keygen(options KeygenOptions) (KeyInfo, error) {
	if !contract.Supported(options.Algorithm) || options.Out == "" {
		return KeyInfo{}, fmt.Errorf("invalid algorithm or output prefix")
	}
	if service.Core == nil {
		return KeyInfo{}, ErrCoreUnavailable
	}
	paths := []string{options.Out + ".key.pem", options.Out + ".pub.pem"}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err == nil && (!options.Force || !info.Mode().IsRegular()) {
			return KeyInfo{}, fmt.Errorf("key output exists; use --force for regular files")
		}
		if err != nil && !os.IsNotExist(err) {
			return KeyInfo{}, err
		}
	}
	private, public, err := service.Core.Generate(options.Algorithm)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("key generation failed")
	}
	_, algorithm, keyid, err := service.Core.LoadPublic(public)
	if err != nil || algorithm != options.Algorithm {
		return KeyInfo{}, fmt.Errorf("generated public key is invalid")
	}
	if options.Force {
		err = replaceKeyPair(paths, [][]byte{private, public})
	} else {
		if err = writeNew(paths[0], private, 0600); err != nil {
			return KeyInfo{}, err
		}
		if err = writeNew(paths[1], public, 0644); err != nil {
			return KeyInfo{}, errors.Join(err, os.Remove(paths[0]))
		}
	}
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{KeyID: keyid, Algorithm: algorithm}, nil
}
