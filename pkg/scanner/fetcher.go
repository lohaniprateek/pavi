// pavi/pkg/scanner/fetcher.go
package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lohaniprateek/pavi/pkg/utils"
)

// CertificateInfo holds the fetched leaf certificate and its chain.
type CertificateInfo struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
}

// FetchCertificate establishes a TLS connection to a domain to retrieve its certificate.
func FetchCertificate(domain string, timeout time.Duration) (*CertificateInfo, error) {
	utils.Debug("Fetching certificate for domain: %s", domain)

	addr := strings.TrimSpace(domain)
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "443")
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("connection to %s timed out", addr)
		}
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("server %s did not provide any certificates", addr)
	}

	certInfo := &CertificateInfo{
		Leaf:  peerCerts[0],
		Chain: peerCerts[1:],
	}

	return certInfo, nil
}
