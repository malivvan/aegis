package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/malivvan/aegis/cmd/cui"
	"github.com/spf13/cobra"
)

const defaultKeyring = "~/.aegis.kdbx"

func New(version string) (root *cobra.Command) {

	root = &cobra.Command{
		Use:     "aegis",
		Short:   "all in one YubiKey management tool",
		Version: version,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			keyring := cmd.Flag("keyring").Value.String()
			if strings.HasPrefix(keyring, "~") {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				if err = cmd.Flag("keyring").Value.Set(filepath.Join(home, strings.TrimPrefix(keyring, "~"))); err != nil {
					return err
				}
			} else if !strings.HasPrefix(keyring, "/") {
				workdir, err := os.Getwd()
				if err != nil {
					return err
				}
				if err = cmd.Flag("keyring").Value.Set(filepath.Join(workdir, keyring)); err != nil {
					return err
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				if err := cui.Execute(version, cmd.Flag("keyring").Value.String()); err != nil {
					cmd.PrintErrf("error: %s\n", err)
					os.Exit(1)
				}
			}
		},
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "print version",
		Run: func(cmd *cobra.Command, args []string) {
			println(cmd.Parent().Version)
		},
	})
	keyring := os.Getenv("AEGIS_KDBX")
	if keyring == "" {
		keyring = defaultKeyring
	}
	root.CompletionOptions = cobra.CompletionOptions{DisableDefaultCmd: true}
	root.PersistentFlags().StringP("keyring", "k", keyring, "path to keyring file")
	return root
}
