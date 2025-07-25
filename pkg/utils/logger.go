// pavi/pkg/utils/logger.go
package utils

import (
	"log"
	"os"
)

var (
	Verbose     bool
	debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
)

func Debug(format string, v ...interface{}) {
	if Verbose {
		debugLogger.Printf(format, v...)
	}
}
