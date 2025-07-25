// pavi/pkg/utils/file.go
package utils

import (
	"encoding/json"
	"os"
)

// ReadDomainsFromJSON reads a file containing a JSON array of strings
// and returns them as a slice.
func ReadDomainsFromJSON(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}
