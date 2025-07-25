// pavi/cmd/scan.go
package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lohaniprateek/pavi/pkg/scanner"
	"github.com/lohaniprateek/pavi/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	domainsStr string
	filePath   string
	timeout    time.Duration
)

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Scan SSL certificates for one or more domains",
	Long: `Scans SSL/TLS certificates to retrieve details like creation and expiration dates.
You can provide a single domain as an argument, multiple domains with the --domains flag, or a list of domains from a file with the --file flag.`,
	Args: cobra.MaximumNArgs(1), // Allow one optional domain as an argument
	Run: func(cmd *cobra.Command, args []string) {
		allDomains := make(map[string]bool)

		// 1. Collect domains from all sources (args, flags)
		if len(args) > 0 {
			allDomains[args[0]] = true
		}

		if domainsStr != "" {
			for _, d := range strings.Split(domainsStr, ",") {
				if domain := strings.TrimSpace(d); domain != "" {
					allDomains[domain] = true
				}
			}
		}

		if filePath != "" {
			fileDomains, err := utils.ReadDomainsFromJSON(filePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", filePath, err)
				os.Exit(1)
			}
			for _, d := range fileDomains {
				if domain := strings.TrimSpace(d); domain != "" {
					allDomains[domain] = true
				}
			}
		}

		if len(allDomains) == 0 {
			fmt.Println("Error: No domains provided. Use an argument, -d, or -f flag.")
			cmd.Help()
			os.Exit(1)
		}

		// Convert map keys to slice for scanning
		domainsToScan := make([]string, 0, len(allDomains))
		for d := range allDomains {
			domainsToScan = append(domainsToScan, d)
		}

		// 2. Execute the scan
		results := scanner.ScanDomains(domainsToScan, timeout)

		// 3. Print results in a clean table format
		printResults(results)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Add flags to the 'scan' command
	scanCmd.Flags().StringVarP(&domainsStr, "domains", "d", "", "Comma-separated list of domains to scan (e.g., 'example.com,google.com')")
	scanCmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to a JSON file containing a list of domains")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Timeout for each certificate fetch attempt")
}

// printResults formats the output in a clean, aligned table.
func printResults(results []scanner.ScanResult) {
	const format = "2006-01-02" // YYYY-MM-DD format for dates
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tISSUED ON\tEXPIRES ON\tSTATUS")
	fmt.Fprintln(w, "------\t---------\t----------\t------")

	for _, res := range results {
		if res.Error != nil {
			fmt.Fprintf(w, "%s\tN/A\tN/A\tERROR: %v\n", res.Domain, res.Error)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\tOK\n", res.Domain, res.IssuedOn.Format(format), res.ExpiresOn.Format(format))
		}
	}
	w.Flush()
}
