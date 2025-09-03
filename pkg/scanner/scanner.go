// pavi/pkg/scanner/scanner.go
package scanner

import (
	"crypto/x509"
	"sync"
	"time"
)

// ScanResult holds the outcome of a single domain scan.
type ScanResult struct {
	Domain        string
	IssuedOn      time.Time
	ExpiresOn     time.Time
	DaysLeft      int
	Validity      bool
	Signature     x509.SignatureAlgorithm
	PublicKeyAlgo x509.PublicKeyAlgorithm
	CName         []string
	Issuer        string
	Error         error
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
			if err != nil {
				resultsChan <- ScanResult{Domain: d, Error: err}
				return
			}
			resultsChan <- ScanResult{
				Domain:        d,
				IssuedOn:      certInfo.Leaf.NotBefore,
				ExpiresOn:     certInfo.Leaf.NotAfter,
				DaysLeft:      int(time.Until(certInfo.Leaf.NotAfter).Hours() / 24),
				Validity:      certInfo.Leaf.BasicConstraintsValid,
				Signature:     certInfo.Leaf.SignatureAlgorithm,
				PublicKeyAlgo: certInfo.Leaf.PublicKeyAlgorithm,
				CName:         certInfo.Leaf.DNSNames,
				Issuer:        certInfo.Leaf.Issuer.Organization[0],
				Error:         nil,
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
