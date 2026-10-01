package notify

import (
	"fmt"
	"os"
)

// Alert shows a user alert
func Alert(format string, args ...interface{}) {
	fmt.Printf("[ALERT] "+format+"\n", args...)
	// In real implementation: Windows Toast notification
}

// Error logs an error
func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

// Info logs info
func Info(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}