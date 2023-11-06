/*
nsecwalkr

reads in domains from stdin and attempts to dump the contents of the DNS zone
by walking NSEC records, if they're supported

*/

package main

import (
	"context"
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
	dnsResolvers   []string
	domainQueue    = make(chan string, 500)
	recursiveQueue = make(chan string, 500)
	ctx, cancel    = context.WithCancel(context.Background())
)

func main() {
	flag.IntVar(&maxConcurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&isVerbose, "v", false, "output more info on attempts")
	flag.Parse()

	err := fetchDNSResolvers("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt")
	if err != nil {
		fmt.Println("Error fetching DNS resolvers:", err)
		return
	}

	dnsServer = getRandomResolver()

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainQueue {
				domainWorker(ctx, domain)
			}
		}()
	}

	var rg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for domain := range recursiveQueue {
				select {
				case <-ctx.Done():
					return
				default:
					domainWorker(ctx, domain)
				}
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

	cancel()

	rg.Wait()
	close(recursiveQueue)

}
