package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [DOMAIN...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "A web crawler inspired by WayBackURL by @tomnomnom.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -d    Show fetch date in first column\n")
		fmt.Fprintf(os.Stderr, "  -t    <domain|file>  Target domain or file with list of domains\n")
		fmt.Fprintf(os.Stderr, "  -n    Exclude subdomains\n")
		fmt.Fprintf(os.Stderr, "  -o    <file>    Output file (default: stdout)\n")
		fmt.Fprintf(os.Stderr, "  -v    List crawled URL versions\n")
		fmt.Fprintf(os.Stderr, "  -vt   <key>     VirusTotal API key\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t domains.txt -o results.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d -n -t example.com\n", os.Args[0])
	}
}

func main() {
	targetFlag := flag.String("t", "", "Target domain or file with list of domains")
	outputFileFlag := flag.String("o", "", "Output file to write results (default: stdout)")
	showDatesFlag := flag.Bool("d", false, "Show date of fetch in the first column")
	noSubdomainsFlag := flag.Bool("n", false, "Don't include subdomains of the target domain")
	getVersionsFlag := flag.Bool("v", false, "List URLs for crawled versions of input URL(s)")
	virusTotalAPIKeyFlag := flag.String("vt", "", "VirusTotal API key for additional URL fetching")

	flag.Parse()

	if *targetFlag == "" && flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Error: either -t or a domain argument is required\n")
		flag.Usage()
		os.Exit(1)
	}

	domains, err := getDomains(*targetFlag, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *getVersionsFlag {
		if err := getVersionURLs(domains); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting version URLs: %v\n", err)
			os.Exit(1)
		}
		return
	}

	results, errs := fetchURLs(domains, *noSubdomainsFlag, *virusTotalAPIKeyFlag)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "Encountered %d errors while fetching URLs:\n", len(errs))
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		if len(results) == 0 {
			os.Exit(1)
		}
	}

	if err := writeOutput(results, *outputFileFlag, *showDatesFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}
}

func getDomains(target string, args []string) ([]string, error) {
	if target != "" {
		if strings.Contains(target, ".") && !strings.Contains(target, "/") {
			return []string{target}, nil
		}
		return readDomainsFromFile(target)
	}
	return args, nil
}
