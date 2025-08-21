package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds all command-line options
type Config struct {
	listFile    string
	outputFile  string
	showDates   bool
	excludeSubs bool
	getVersions bool
	silent      bool
	vtAPIKey    string
}

// URLResult represents a discovered URL with optional date
type URLResult struct {
	URL  string
	Date string
}

func main() {
	config := parseFlags()

	if shouldShowUsage(config) {
		showUsage()
		os.Exit(1)
	}

	domains := loadDomains(config)
	if len(domains) == 0 {
		if !config.silent {
			fmt.Fprintf(os.Stderr, "No domains provided\n")
		}
		os.Exit(1)
	}

	if config.vtAPIKey != "" {
		os.Setenv("VT_API_KEY", config.vtAPIKey)
	}

	if config.getVersions {
		processVersions(domains, config)
	} else {
		discoverURLs(domains, config)
	}
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.listFile, "l", "", "file containing domains")
	flag.StringVar(&config.outputFile, "o", "", "output file (default: stdout)")
	flag.BoolVar(&config.showDates, "date", false, "show discovery date")
	flag.BoolVar(&config.excludeSubs, "exclude-subdomains", false, "exclude subdomains")
	flag.BoolVar(&config.getVersions, "get-versions", false, "list archived versions")
	flag.BoolVar(&config.silent, "silent", false, "silent mode")
	flag.StringVar(&config.vtAPIKey, "vt-key", "", "VirusTotal API key")
	help := flag.Bool("h", false, "show help")

	flag.Usage = showUsage
	flag.Parse()

	if *help {
		showUsage()
		os.Exit(0)
	}

	return config
}

func shouldShowUsage(config Config) bool {
	// If no file specified, no command args, and no stdin data
	return config.listFile == "" && len(flag.Args()) == 0 && !hasStdinData()
}

func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func showUsage() {
	fmt.Printf(`Fast URL discovery from Wayback Machine, CommonCrawl and VirusTotal

Usage: %s [options] [domains...]

INPUT:
  -l file          Read domains from file
  domains...       Provide domains as arguments
  stdin            Read domains from standard input

OUTPUT:
  -o file          Write output to file (default: stdout)
  -date            Include discovery date in output
  -silent          Suppress error messages

FILTERS:
  -exclude-subdomains  Only return exact domain matches

SOURCES:
  -vt-key key      VirusTotal API key (or VT_API_KEY env)

SPECIAL:
  -get-versions    List archived versions of input URLs

EXAMPLES:
  %s example.com
  %s -l domains.txt -o results.txt
  %s -date -exclude-subdomains example.com
  echo example.com | %s -silent
  %s -get-versions https://example.com/page
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func loadDomains(config Config) []string {
	var domains []string

	// Load from file if specified
	if config.listFile != "" {
		fileDomains, err := readLinesFromFile(config.listFile)
		if err != nil {
			if !config.silent {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			}
			os.Exit(1)
		}
		domains = append(domains, fileDomains...)
	}

	// Add command line arguments
	domains = append(domains, flag.Args()...)

	// Read from stdin if no other input
	if len(domains) == 0 {
		domains = readLinesFromStdin()
	}

	return domains
}

func readLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return scanLines(file), nil
}

func readLinesFromStdin() []string {
	return scanLines(os.Stdin)
}

func scanLines(reader io.Reader) []string {
	var lines []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines
}

func processVersions(urls []string, config Config) {
	for _, u := range urls {
		versions, err := getWaybackVersions(u)
		if err != nil && !config.silent {
			fmt.Fprintf(os.Stderr, "Error getting versions for %s: %v\n", u, err)
			continue
		}

		for _, version := range versions {
			writeOutput(version, config.outputFile)
		}
	}
}

func discoverURLs(domains []string, config Config) {
	outputWriter := getOutputWriter(config.outputFile)
	defer func() {
		if outputWriter != os.Stdout {
			outputWriter.Close()
		}
	}()

	for _, domain := range domains {
		urls := fetchURLsFromAllSources(domain, config)

		seen := make(map[string]bool)
		for _, result := range urls {
			if seen[result.URL] {
				continue
			}
			seen[result.URL] = true

			if config.excludeSubs && isSubdomain(result.URL, domain) {
				continue
			}

			line := formatResult(result, config.showDates, config.silent)
			fmt.Fprintln(outputWriter, line)
		}
	}
}

func fetchURLsFromAllSources(domain string, config Config) []URLResult {
	var allResults []URLResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fetch from Wayback Machine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if results, err := fetchWaybackURLs(domain, config.excludeSubs); err == nil {
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		} else if !config.silent {
			fmt.Fprintf(os.Stderr, "Wayback error for %s: %v\n", domain, err)
		}
	}()

	// Fetch from CommonCrawl
	wg.Add(1)
	go func() {
		defer wg.Done()
		if results, err := fetchCommonCrawlURLs(domain, config.excludeSubs); err == nil {
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		} else if !config.silent {
			fmt.Fprintf(os.Stderr, "CommonCrawl error for %s: %v\n", domain, err)
		}
	}()

	// Fetch from VirusTotal
	wg.Add(1)
	go func() {
		defer wg.Done()
		if results, err := fetchVirusTotalURLs(domain); err == nil {
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		} else if !config.silent && err.Error() != "no API key" {
			fmt.Fprintf(os.Stderr, "VirusTotal error for %s: %v\n", domain, err)
		}
	}()

	wg.Wait()
	return allResults
}

func fetchWaybackURLs(domain string, excludeSubs bool) ([]URLResult, error) {
	wildcard := "*."
	if excludeSubs {
		wildcard = ""
	}

	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", wildcard, domain)

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []URLResult
	for i, row := range data {
		if i == 0 || len(row) < 3 { // Skip header and incomplete rows
			continue
		}
		results = append(results, URLResult{
			URL:  row[2],
			Date: row[1],
		})
	}

	return results, nil
}

func fetchCommonCrawlURLs(domain string, excludeSubs bool) ([]URLResult, error) {
	wildcard := "*."
	if excludeSubs {
		wildcard = ""
	}

	url := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", wildcard, domain)

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []URLResult
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		var item struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			continue
		}

		results = append(results, URLResult{
			URL:  item.URL,
			Date: item.Timestamp,
		})
	}

	return results, scanner.Err()
}

func fetchVirusTotalURLs(domain string) ([]URLResult, error) {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("no API key")
	}

	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		DetectedURLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []URLResult
	for _, item := range data.DetectedURLs {
		results = append(results, URLResult{URL: item.URL})
	}

	return results, nil
}

func getWaybackVersions(targetURL string) ([]string, error) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&output=json", targetURL)

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var versions []string
	seen := make(map[string]bool)

	for i, row := range data {
		if i == 0 || len(row) < 6 { // Skip header and incomplete rows
			continue
		}

		digest := row[5]
		if seen[digest] {
			continue
		}
		seen[digest] = true

		version := fmt.Sprintf("https://web.archive.org/web/%sif_/%s", row[1], row[2])
		versions = append(versions, version)
	}

	return versions, nil
}

func httpGet(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Get(url)
}

func isSubdomain(rawURL, domain string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func formatResult(result URLResult, showDates, silent bool) string {
	if showDates && result.Date != "" {
		if date, err := time.Parse("20060102150405", result.Date); err == nil {
			return fmt.Sprintf("%s %s", date.Format(time.RFC3339), result.URL)
		} else if !silent {
			fmt.Fprintf(os.Stderr, "Failed to parse date %s for URL %s\n", result.Date, result.URL)
		}
	}
	return result.URL
}

func getOutputWriter(filename string) *os.File {
	if filename == "" {
		return os.Stdout
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}

	return file
}

func writeOutput(line, filename string) {
	writer := getOutputWriter(filename)
	defer func() {
		if writer != os.Stdout {
			writer.Close()
		}
	}()

	fmt.Fprintln(writer, line)
}
