package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type WebURL struct {
	Date string
	URL  string
}

type fetchFunction func(string, bool, string) ([]WebURL, error)

func fetchURLs(domains []string, noSubdomains bool, virusTotalAPIKey string) ([]WebURL, []error) {
	fetchFunctions := []fetchFunction{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	var results []WebURL
	var errs []error
	var wg sync.WaitGroup
	resultsChan := make(chan []WebURL, len(domains)*len(fetchFunctions))
	errorsChan := make(chan error, len(domains)*len(fetchFunctions))

	for _, domain := range domains {
		for _, fn := range fetchFunctions {
			wg.Add(1)
			go func(d string, f fetchFunction) {
				defer wg.Done()
				resp, err := f(d, noSubdomains, virusTotalAPIKey)
				if err != nil {
					errorsChan <- fmt.Errorf("error fetching URLs for %s: %v", d, err)
					return
				}
				resultsChan <- resp
			}(domain, fn)
		}
	}

	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	for resp := range resultsChan {
		results = append(results, resp...)
	}

	for err := range errorsChan {
		errs = append(errs, err)
	}

	return results, errs
}

func getWaybackURLs(domain string, noSubdomains bool, _ string) ([]WebURL, error) {
	subsWildcard := "*."
	if noSubdomains {
		subsWildcard = ""
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Get(
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching from Wayback Machine: %v", err)
	}
	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading Wayback Machine response: %v", err)
	}

	var wrapper [][]string
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("error parsing Wayback Machine JSON: %v", err)
	}

	out := make([]WebURL, 0, len(wrapper))

	for i, urls := range wrapper {
		if i == 0 {
			continue // Skip the header row
		}
		out = append(out, WebURL{Date: urls[1], URL: urls[2]})
	}

	return out, nil
}

func getCommonCrawlURLs(domain string, noSubdomains bool, _ string) ([]WebURL, error) {
	subsWildcard := "*."
	if noSubdomains {
		subsWildcard = ""
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Get(
		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching from Common Crawl: %v", err)
	}
	defer res.Body.Close()

	sc := bufio.NewScanner(res.Body)

	var out []WebURL

	for sc.Scan() {
		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		if err := json.Unmarshal([]byte(sc.Text()), &wrapper); err != nil {
			continue
		}
		out = append(out, WebURL{Date: wrapper.Timestamp, URL: wrapper.URL})
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading Common Crawl response: %v", err)
	}

	return out, nil
}

func getVirusTotalURLs(domain string, noSubdomains bool, apiKey string) ([]WebURL, error) {
	if apiKey == "" {
		return nil, nil
	}

	fetchURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fetchURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching from VirusTotal: %v", err)
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("error parsing VirusTotal JSON: %v", err)
	}

	out := make([]WebURL, 0, len(wrapper.URLs))
	for _, u := range wrapper.URLs {
		out = append(out, WebURL{URL: u.URL})
	}

	return out, nil
}
