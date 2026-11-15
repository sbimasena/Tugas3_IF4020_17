package main

import (
	"github.com/spf13/cobra"
	"kelompok17/internal/app"
)

func newSBOMSign(service app.Service) *cobra.Command {
	var o app.SBOMSignOptions
	c := &cobra.Command{Use: "sbom-sign", Short: "sign a JSON SBOM and bind it to a release artifact", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return service.SignSBOM(o) }}
	requiredString(c, &o.SBOM, "sbom", "JSON SBOM path")
	requiredString(c, &o.Release, "release", "referenced release artifact path")
	requiredString(c, &o.Package, "package", "release package")
	requiredString(c, &o.Version, "version", "release version")
	requiredString(c, &o.Key, "key", "PKCS#8 private PEM path")
	requiredString(c, &o.Out, "out", "SBOM bundle output path")
	return c
}

func newSBOMVerify(service app.Service) *cobra.Command {
	var o app.SBOMVerifyOptions
	var asJSON bool
	c := &cobra.Command{Use: "sbom-verify", Short: "verify an SBOM bundle and its release binding", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, code := app.VerifySBOM(service.Core, o)
		return printResult(cmd, r, code, asJSON)
	}}
	requiredString(c, &o.SBOM, "sbom", "JSON SBOM path")
	requiredString(c, &o.Release, "release", "referenced release artifact path")
	requiredString(c, &o.Bundle, "bundle", "SBOM bundle path")
	requiredString(c, &o.TrustStore, "trust-store", "trusted store path")
	requiredString(c, &o.Package, "package", "expected package")
	requiredString(c, &o.Version, "version", "expected version")
	c.Flags().BoolVar(&asJSON, "json", false, "write verification JSON to stdout")
	return c
}
