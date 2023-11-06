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
	defaultPort    = 53
	nextCandidate  string
	domainQueue    = make(chan string, 500)
	recursiveQueue = make(chan string, 500)
	dnsResolvers   = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"}
)

func main() {
	flag.IntVar(&maxConcurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&isVerbose, "v", false, "output more info on attempts")
	flag.Parse()

	dnsServer = getRandomResolver()

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

	var rg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for domain := range recursiveQueue {
				// fmt.Printf("Doing recursive search on %s\n", domain)
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

	close(recursiveQueue)
	rg.Wait()
}
