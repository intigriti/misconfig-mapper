package main

/*
	PSEUDO:
		[X] Should accept a target name: "intigriti"
		[X] Should enumerate potential TLDs through permutations: "intigriti.com", "intigriti.eu", "intigriti.io", "..."
		[X] Loop over all fingerprints
		[ ] Generate potential PoC URLs
		[ ] Check against fingerprint data
		[ ] Return matched results
*/

import (
	"os"
	"fmt"
	"flag"
	"net/url"
	"strings"
	"encoding/json"
)

type Fingerprint struct {
	ID					int64		`bson:"id"`
	ServiceName			string 		`bson:"service"`
	Description			string	 	`bson:"description"`
	URL					any		 	`bson:"URL"`
	ReproductionSteps	any			`bson:"reproductionSteps"`
	Fingerprint			any			`bson:"fingerprint"`
	Reference			string		`bson:"reference"`
}

/*
	[
		{
			"id":					int64,
			"service":				string,
			"description":			string,
			"URL":					[]string | nil,
			"reproductionSteps":	[]string | nil,
			"fingerprint":			[]string | nil,
			"reference":			string
		}
	]
*/

var fingerprints []Fingerprint

var TLDs []string = []string{
	"com",
	"net",
	"org",
	"io",
	"fr",
	// Add more TLDs as needed
}

func LoadFingerprints() []Fingerprint {
	var technologies []Fingerprint

	file, err := os.Open("./fingerprints.json")
	if err != nil {
		fmt.Println("ERROR: Failed opening file \"./fingerprints.json\":", err)
		return technologies
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&technologies); err != nil {
		fmt.Println("ERROR: Failed decoding JSON file:", err)
		return technologies
	}

	return technologies
}

func ReturnPossibleDomains(target string) []string {
	var possibleDomains []string

	// Remove leading and trailing spaces and convert to lowercase
	target = strings.TrimSpace(strings.ToLower(target))

    // Generate domain names by combining the keyword with each TLD
	for _, TLD := range TLDs {
		domain := fmt.Sprintf("%s%s", target, TLD)
		possibleDomains = append(possibleDomains, domain)
	}

	// Other mutations??

	return possibleDomains
}

func ReturnServiceFingerprint(id string) any {
	for _, s := range fingerprints {
		if fmt.Sprintf("%s", s.ID) == id {
			return s
		}
	}

	return nil
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or Company name: Intigriti")
	serviceFlag := flag.String("service", "", "Specify the service ID you'd like to check for: \"1\" for Atlassian Jira Service Desk")
	servicesFlag := flag.String("services", "", "Print all services with their associated IDs")
	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag

	fingerprints = LoadFingerprints()

	if *servicesFlag {
		fmt.Printf("%v Services loaded!\n", len(fingerprints))
		fmt.Println(fingerprints)
		return
	}

	if (target == "" || service == "") {
		flag.Usage()
		return
	}

	fingerprint := ReturnServiceFingerprint(service)
	if fingerprint == nil {
		fmt.Errorf("Error: Service ID \"%v\" does not match any integrated service!\n", service)
		return
	}

	possibleDomains := ReturnPossibleDomains(target)

	for _, domain := range possibleDomains {
		targetURL := strings.Replace(fmt.Sprintf("%s", fingerprint.(Fingerprint).URL), "{TARGET}", fmt.Sprintf("%s", domain), -1)
		URL, err := url.Parse(targetURL)
		if err != nil {
			fmt.Errorf("Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
			continue
		}

		fmt.Println(URL)
	}
}