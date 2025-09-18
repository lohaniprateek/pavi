// pavi/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/lohaniprateek/pavi/internal/utils"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pavi",
	Short: "Pavi is a fast and simple SSL/TLS certificate scanner.",
	Long: `
	
	A command-line tool built with Go to scan SSL/TLS certificates for given domains, checking for expiration dates and other details.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Add a persistent flag that will be available to all subcommands.
	rootCmd.PersistentFlags().BoolVarP(&utils.Verbose, "verbose", "v", false, "Enable verbose output for debugging.")
}
