package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"kelompok17/internal/app"
)

type exitStatus struct{ code int }

func (status *exitStatus) Error() string { return fmt.Sprintf("exit status %d", status.code) }

func execute(service app.Service, version string, args []string, out, stderr io.Writer) int {
	root := newRoot(service, version)
	root.SetOut(out)
	root.SetErr(stderr)
	root.SetArgs(args)
	cmd, err := root.ExecuteC()
	if err == nil {
		return 0
	}
	var status *exitStatus
	if errors.As(err, &status) {
		return status.code
	}
	if cmd != nil && cmd.Name() == "verify" {
		result := app.Result{Status: "INPUT_ERROR", Message: err.Error()}
		_ = printResult(cmd, result, 2, verificationJSON(cmd, args))
		return 2
	}
	fmt.Fprintln(stderr, err)
	return 2
}

func newRoot(service app.Service, version string) *cobra.Command {
	root := &cobra.Command{
		Use: "kelompok17", Short: "sign and verify release artifacts",
		Version: version, SilenceErrors: true, SilenceUsage: true,
		Args:              cobra.NoArgs,
		RunE:              func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newKeygen(service), newSign(service), newVerify(service), newTrust(service), newSBOMSign(service), newSBOMVerify(service))
	return root
}

func requiredString(cmd *cobra.Command, target *string, name, description string) {
	cmd.Flags().StringVar(target, name, "", description)
	_ = cmd.MarkFlagRequired(name)
}

func printResult(cmd *cobra.Command, result app.Result, code int, asJSON bool) error {
	if asJSON {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", result.Status, result.Message); err != nil {
		return err
	}
	if code != 0 {
		return &exitStatus{code: code}
	}
	return nil
}

func verificationJSON(cmd *cobra.Command, args []string) bool {
	// pflag read ulang kalo error sblm --json.
	flags := pflag.NewFlagSet("verify-output", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.ParseErrorsWhitelist.UnknownFlags = true
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		switch flag.Value.Type() {
		case "string":
			flags.String(flag.Name, "", "")
		case "bool":
			flags.Bool(flag.Name, false, "")
		}
	})
	_ = flags.Parse(args)
	asJSON, _ := flags.GetBool("json")
	return asJSON
}
