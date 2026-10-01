// Command holder is a test-only helper. It opens a file for reading and waits,
// so an end-to-end enforcement test can observe and (opt-in) terminate a
// realistic untrusted process. It is not part of the shipped product.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: holder <file>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Println("holder-ready")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-sig:
	case <-time.After(2 * time.Minute):
	}
}
