package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

/*
main worker function which takes a domain string as arg and attempts to walk the
NSEC range of records through searchNsecRange.
If NSEC is supported a 'prev' and 'next' domain are returned and the for loop will break
once all available records have been read. It's common in large zones to get
errors from the DNS resolver due to too many requests, hence retry logic is adopted which
selects an alternate resolver from the list
*/
func domainWorker(ctx context.Context, zone string) {
	nextCandidate := ""
	maxRetries := 5
	retryDelay := time.Second
	var currentDNSResolver string

	for {

		// either use custom resolver, or get a random trusted one
		if dnsServer == "" {
			currentDNSResolver = getRandomResolver()
		} else {
			if currentDNSResolver == "" {
				currentDNSResolver = dnsServer + ":" + strconv.Itoa(defaultPort)
			}
		}

		// enumerate the current range
		prev, next, err := searchNsecRange(currentDNSResolver, nextCandidate, zone)

		// retry logic includes using a different resolver if a custom one isn't used
		if err != nil {
			if err.Error() == "NSEC record not found" {
				if isVerbose {
					log.Printf("NSEC record not found for zone %s\n", zone)
				}
				break
			}
			if isVerbose {
				log.Printf("ERROR: %s\n", err)
			}
			maxRetries--
			if maxRetries <= 0 {
				if isVerbose {
					log.Printf("Max retries reached zone %s\n", nextCandidate+"."+zone)
				}
				break
			}

			// exponential backoff
			time.Sleep(retryDelay)
			retryDelay *= 2

			// reset the DNS resolver if we are not using a custom one
			if dnsServer == "" {
				currentDNSResolver = ""
			}

			continue
		}

		// assume there's a result to print
		if prev != "" {
			fmt.Printf("%s.%s\n", prev, zone)
		}

		// end of zone
		if next == "" || maxRetries <= 0 {
			break
		}

		// walk the zone using the next entry in the zone as the seed
		nextCandidate = next

		// send the next domain back to the domainWorker to recurse
		select {
		case <-ctx.Done():
			return
		case recursiveQueue <- next + "." + zone:
		}
	}
}

/*
using the current label and zone, generates a probeLabel
the probeLable is used to perform a dnssecQuery, the result
of which yields the prev and next NSEC zone
*/
func searchNsecRange(ns string, label string, zone string) (prev string, next string, err error) {

	probeLabel := generateProbeLabel(label)
	re := regexp.MustCompile(`^(([^\.]+\.)*([^\.]+)\.|)` + regexp.QuoteMeta(zone) + `\.*$`)

	const maxRetries = 3
	for retry := 0; retry < maxRetries; retry++ {
		var in *dns.Msg
		in, _, err := dnssecQuery(ns, probeLabel+"."+zone)
		if err != nil {
			if retry < maxRetries-1 {
				continue
			}
			return "", "", err
		}

		for _, rr := range in.Ns {
			if nsec, ok := rr.(*dns.NSEC); ok {
				prev = strings.ToLower(nsec.Header().Name)
				next = strings.ToLower(nsec.NextDomain)

				if !re.MatchString(prev) || !re.MatchString(next) {
					continue
				}
				prev = extractLabel(prev, re)
				next = extractLabel(next, re)

				if prev < probeLabel && (probeLabel < next || next == "") {
					return prev, next, nil
				}
			}
		}
	}
	return "", "", errors.New("NSEC record not found")
}

/*
returns the 3rd element from the NSEC record
*/
func extractLabel(fqdn string, re *regexp.Regexp) string {
	return re.ReplaceAllString(fqdn, "$3")
}

/*
reads in the current label and zone and generates what is hopefully
a label which will return an nxdomain. note subdomains can be up to 63 chars long
examples
foo.example.com becomes foo--.example.com
aaa[...snip...]aaaaaa.example.com becomes aaa[...snip...]aaaaab.example.com
aaa[...snip...]aaaaa-.example.com becomes aaa[...snip...]aaaa-0.example.com
*/
func generateProbeLabel(label string) string {
	probeLabel := strings.ToLower(label) + "--"
	if len(probeLabel) > 63 {
		c := probeLabel[62]

		switch c {
		case '-':
			probeLabel = probeLabel[:62] + "0"
		case '9':
			probeLabel = probeLabel[:62] + "a"
		default:
			probeLabel = probeLabel[:62] + string(c+1)
		}
	}
	return probeLabel
}

/*
performs the actual DNS request using the supplied ns and probeLabel
*/
func dnssecQuery(ns string, qn string) (r *dns.Msg, rtt time.Duration, err error) {

	c := new(dns.Client)
	c.Net = "udp"

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = false
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.CheckingDisabled = false
	m.MsgHdr.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	m.Rcode = dns.RcodeSuccess

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)

	m.Question[0] = dns.Question{Name: dns.Fqdn(qn), Qtype: dns.TypeA, Qclass: dns.ClassINET}

	r, rtt, err = c.Exchange(m, ns)

	if err != nil {
		if isVerbose {
			fmt.Printf(";; %s\n", err.Error())
		}
		return
	}

	if r.MsgHdr.Truncated {
		c.Net = "tcp"
		r, rtt, err = c.Exchange(m, ns)
	}

	return
}

/*
returns a random value from the slice of dnsResolvers using the default port
*/
func getRandomResolver() string {
	return dnsResolvers[rand.Intn(len(dnsResolvers))] + ":" + strconv.Itoa(defaultPort)
}

/*
reads user input either piped to the program or as the first argument
e.g.
cat domains.txt | nsecwalkr
echo example.com | nsecwalkr
nsecwalkr example.com
tracks and ignores duplicates
*/
func getUserInput() (bool, error) {
	seenDomains := make(map[string]bool)

	var input_domains io.Reader
	input_domains = os.Stdin

	arg_domain := flag.Arg(0)
	if arg_domain != "" {
		input_domains = strings.NewReader(arg_domain)
	}

	sc := bufio.NewScanner(input_domains)

	for sc.Scan() {

		domain := strings.ToLower(sc.Text())

		if _, alreadySeen := seenDomains[domain]; alreadySeen {
			continue
		}

		seenDomains[domain] = true
		domainQueue <- domain
	}

	if err := sc.Err(); err != nil {
		return false, err
	}

	return true, nil
}
