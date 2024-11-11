package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

func writeOutput(results []WebURL, outputFile string, showDates bool) error {
	var writer io.Writer = os.Stdout
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output file: %v", err)
		}
		defer file.Close()
		writer = file
	}

	for _, w := range results {
		if showDates {
			d, err := time.Parse("20060102150405", w.Date)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.Date, w.URL)
				continue
			}
			if _, err := fmt.Fprintf(writer, "%s %s\n", d.Format(time.RFC3339), w.URL); err != nil {
				return fmt.Errorf("error writing to output: %v", err)
			}
		} else {
			if _, err := fmt.Fprintln(writer, w.URL); err != nil {
				return fmt.Errorf("error writing to output: %v", err)
			}
		}
	}

	return nil
}

func getVersionURLs(domains []string) error {
	for _, u := range domains {
		versions, err := getVersions(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting versions for %s: %v\n", u, err)
			continue
		}
		for _, v := range versions {
			fmt.Println(v)
		}
	}
	return nil
}
