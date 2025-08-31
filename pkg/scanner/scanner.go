// pavi/pkg/scanner/scanner.go
package scanner

import (
	"sync"
	"time"
)

// ScanResult holds the outcome of a single domain scan.
type ScanResult struct {
	Domain    string
	IssuedOn  time.Time
	ExpiresOn time.Time
	DaysLeft  int
	Error     error
}

// ScanDomains takes a list of domains and scans them concurrently.
func ScanDomains(domains []string, timeout time.Duration) []ScanResult {
	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, len(domains))
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			certInfo, err := FetchCertificate(d, timeout)
			expYear := certInfo.Leaf.NotAfter
			now := time.Now()
			daysLeft := int(expYear.Sub(now).Hours() / 24)
			if err != nil {
				resultsChan <- ScanResult{Domain: d, Error: err}
				return
			}

			resultsChan <- ScanResult{
				Domain:    d,
				IssuedOn:  certInfo.Leaf.NotBefore,
				ExpiresOn: certInfo.Leaf.NotAfter,
				DaysLeft:  daysLeft,
				Error:     nil,
			}
		}(domain)
	}

	wg.Wait()
	close(resultsChan)

	var results []ScanResult
	for res := range resultsChan {
		results = append(results, res)
	}

	return results
}
