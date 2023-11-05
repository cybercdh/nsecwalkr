# nsecwalkr

nsecwalkr attempts to enumerate a DNS zone by walking any available NSEC records. This can be a valuable resource for perform recon on a large list of domains and often leads to subdomains that don't appear in other online sources. 

## Installation

Assuming Go is installed, run:

```bash
go install github.com/cybercdh/nsecwalkr@latest
```

## Usage

```bash
nsecwalkr example.com

echo example.com | nsecwalkr

cat domains.txt | nsecwalkr
```

## Options

```bash
Usage of nsecwalkr:
  -c int
    	set the concurrency level (default 20)
  -v	output more info on attempts
```
## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## Thanks
Much of the DNS request and probe-label logic came from [this excellent repo](https://github.com/hnw/go-dnssec-walker). nsecwalkr builds on this to handle multiple domains from user-input, applies more robust back-off and retry logic and uses Concurrency to speed up the overall process.

## License

[MIT](https://choosealicense.com/licenses/mit/)