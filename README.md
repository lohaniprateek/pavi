# Proacitve Alerting for validiting & Integrity  
PAVI is a CLI tool designed to monitor SSL/TLS certificates for domains, ensuring their validity, security, and compliance. It checks certificates for expiry, trustworthiness, chain completeness, supported protocol versions (e.g., TLS 1.2, 1.3), and weak ciphers, assigning an SSL grade (e.g., A+, B) inspired by SSL Labs. The tool supports automated scans, alerting, and reporting, with optional advanced features like Let’s Encrypt integration and Kubernetes webhooks.

### Key Features:

**Input**: Accepts domains via CLI arguments or files (CSV/JSON).
**Scanning**: Analyzes certificates for expiry, validity, trust chain, protocols, and ciphers.
**Scheduling**: Runs periodic scans (e.g., every 12/24 hours).
**Alerting**: Sends email or Slack notifications for expiring or invalid certificates.
**Reporting**: Generates reports in JSON, with optional historical data storage (PostgreSQL).



### JSON file format
[
  "google.com",
  "github.com",
  "stackoverflow.com",
  "aws.amazon.com",
  "microsoft.com"
]
