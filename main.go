// Created by Nemesis
// Contact: nemesisuks@protonmail.com

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/urfave/cli/v2"
)

// Defines regex patterns as global constants
const (
	urlPattern        = `https?://[^\s'"]+`
	emailPattern      = `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
	apiKeyPattern     = `(?i)\b[0-9a-f]{32,64}\b`
	ipAddressPattern  = `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`
	credentialPattern = `(?i)\b(?:username|password|token|secret)\b`
)

func main() {
	app := &cli.App{
		Name:  "JSRecon",
		Usage: "Scan and extract endpoint URLs and sensitive data from JS files on a website",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "url",
				Aliases:  []string{"u"},
				Usage:    "URL of the website to scan (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "keyword",
				Usage: "Keyword to search for in JavaScript code (optional)",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file to save the links (optional)",
			},
			&cli.BoolFlag{
				Name:  "show-as-domain",
				Usage: "Show results as domains instead of full URLs (optional)",
			},
			&cli.BoolFlag{
				Name:  "show-sensitive",
				Usage: "Show sensitive data found in JS files (optional)",
			},
			&cli.StringFlag{
				Name:  "cookie",
				Usage: "Custom cookie to include in the request (optional)",
			},
		},
		Action: func(c *cli.Context) error {
			websiteURL := c.String("url")
			keyword := c.String("keyword")
			showAsDomain := c.Bool("show-as-domain")
			outputFile := c.String("output")
			showSensitive := c.Bool("show-sensitive")
			customCookie := c.String("cookie")

			client := &http.Client{}
			crawlWebsite(client, websiteURL, keyword, outputFile, showAsDomain, showSensitive, customCookie)

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func crawlWebsite(client *http.Client, websiteURL, keyword, outputFile string, showAsDomain, showSensitive bool, customCookie string) {
	req, err := http.NewRequest("GET", websiteURL, nil)
	if err != nil {
		log.Fatal(err)
	}

	if customCookie != "" {
		req.Header.Add("Cookie", customCookie)
	}

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status code %d", response.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var links []string
	var sensitiveData []string
	var wg sync.WaitGroup

	// Defines regex patterns for sensitive data
	regexPatterns := map[*regexp.Regexp]string{
		regexp.MustCompile(emailPattern):      "Email Address",
		regexp.MustCompile(apiKeyPattern):     "API Key",
		regexp.MustCompile(ipAddressPattern):  "IP Address",
		regexp.MustCompile(credentialPattern): "Credential",
	}

	doc.Find("script").Each(func(index int, scriptElement *goquery.Selection) {
		wg.Add(1)
		go func(script *goquery.Selection) {
			defer wg.Done()
			scriptLinks, sensitiveScriptData := processScript(script, keyword, regexPatterns)
			links = append(links, scriptLinks...)
			sensitiveData = append(sensitiveData, sensitiveScriptData...)
		}(scriptElement)
	})

	wg.Wait()

	if outputFile != "" {
		dataToSave := make([]string, 0)

		if showSensitive {
			for _, data := range sensitiveData {
				dataToSave = append(dataToSave, data)
			}
		}

		for _, link := range links {
			if !showSensitive || (showSensitive && !strings.Contains(link, "@")) {
				if showAsDomain {
					parts := strings.Split(link, "//")
					if len(parts) > 1 {
						domainParts := strings.Split(parts[1], "/")
						if len(domainParts) > 0 {
							dataToSave = append(dataToSave, domainParts[0])
						}
					}
				} else {
					dataToSave = append(dataToSave, link)
				}
			}
		}

		if err := saveDataToFile(outputFile, dataToSave); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("\nData saved to %s\n", outputFile)
	}

	printJavaScriptLinks(outputFile, links, sensitiveData, showAsDomain, showSensitive)
}

func processScript(scriptElement *goquery.Selection, keyword string, regexPatterns map[*regexp.Regexp]string) ([]string, []string) {
	scriptText := scriptElement.Text()
	scriptLinks := findJavaScriptLinks(scriptText, keyword)
	sensitiveScriptData := extractSensitiveData(scriptText, regexPatterns)
	return scriptLinks, sensitiveScriptData
}

func extractSensitiveData(scriptText string, regexPatterns map[*regexp.Regexp]string) []string {
	var sensitiveData []string
	for pattern, dataType := range regexPatterns {
		matches := pattern.FindAllString(scriptText, -1)
		for _, match := range matches {
			cleanMatch := strings.Trim(match, `" '`)
			sensitiveData = append(sensitiveData, dataType+": "+cleanMatch)
		}
	}
	return sensitiveData
}

func findMatches(text string, pattern *regexp.Regexp) []string {
	matches := pattern.FindAllString(text, -1)
	var cleanMatches []string
	for _, match := range matches {
		cleanMatch := strings.Trim(match, `" '`)
		cleanMatches = append(cleanMatches, cleanMatch)
	}
	return cleanMatches
}

func saveDataToFile(filename string, data []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, entry := range data {
		_, err := writer.WriteString(entry + "\n")
		if err != nil {
			return err
		}
	}
	writer.Flush()

	return nil
}

func printJavaScriptLinks(outputFile string, links, sensitiveData []string, showAsDomain, showSensitive bool) {
	printedDomains := make(map[string]bool)
	uniqueLinks := make(map[string]bool)
	uniqueSensitiveData := make(map[string]bool)

	if showSensitive {
		for _, data := range sensitiveData {
			if !uniqueSensitiveData[data] {
				fmt.Println(data)
				uniqueSensitiveData[data] = true
			}
		}
	}

	for _, link := range links {
		if !showSensitive || (showSensitive && !strings.Contains(link, "@")) {
			if showAsDomain {
				parts := strings.Split(link, "//")
				if len(parts) > 1 {
					domainParts := strings.Split(parts[1], "/")
					if len(domainParts) > 0 && !printedDomains[domainParts[0]] {
						fmt.Println(domainParts[0])
						printedDomains[domainParts[0]] = true
					}
				}
			} else {
				if !uniqueLinks[link] {
					fmt.Println(link)
					uniqueLinks[link] = true
				}
			}
		}
	}
}

func findJavaScriptLinks(scriptText, keyword string) []string {
	re := regexp.MustCompile(urlPattern)
	matches := re.FindAllString(scriptText, -1)

	var links []string

	for _, match := range matches {
		if keyword == "" || strings.Contains(match, keyword) {
			cleanLink := strings.Trim(match, `" '`)
			links = append(links, cleanLink)
		}
	}

	return links
}
