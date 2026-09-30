/*
nsecwalkr

reads in domains from stdin and attempts to dump the contents of the DNS zone
by walking NSEC records, if they're supported

*/

package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
)

var (
	maxConcurrency int
	isVerbose      bool
	dnsServer      string
	defaultPort    int
	domainQueue    = make(chan string, 500)
)

func main() {
	flag.IntVar(&maxConcurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&isVerbose, "v", false, "output more info on attempts")
	flag.IntVar(&defaultPort, "p", 53, "set the default DNS port")
	flag.StringVar(&dnsServer, "d", "", "specify a custom DNS resolver address")
	flag.Parse()

	if maxConcurrency < 1 {
		fmt.Fprintf(os.Stderr, "-c must be at least 1 (got %d)\n", maxConcurrency)
		os.Exit(2)
	}
	if defaultPort < 1 || defaultPort > 65535 {
		fmt.Fprintf(os.Stderr, "-p must be between 1 and 65535 (got %d)\n", defaultPort)
		os.Exit(2)
	}

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainQueue {
				domainWorker(domain)
			}
		}()
	}

	success, err := getUserInput()
	if !success || err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get user input:", err)
		os.Exit(1)
	}

	close(domainQueue)
	wg.Wait()

}
