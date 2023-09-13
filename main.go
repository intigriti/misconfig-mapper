package main

/*
	PSEUDO:
		[X] Should accept a target name: "intigriti"
		[X] Should enumerate potential TLDs through permutations: "intigriti.com", "intigriti.eu", "intigriti.io", "..."
		[X] Loop over all fingerprints
		[X] Generate potential PoC URLs
		[ ] Check against fingerprint data
		[ ] Return matched results
*/

import (
	"os"
	"fmt"
	"flag"
	"strings"
	"net/url"
	"net/http"
	"encoding/json"
)

type Fingerprint struct {
	ID					int64		`json:"id"`
	ServiceName			string 		`json:"service"`
	Description			string	 	`json:"description"`
	URL					string		`json:"URL"`
	ReproductionSteps	[]string	`json:"reproductionSteps"`
	Fingerprints		[]string	`json:"fingerprint"`
	Reference			string		`json:"reference"`
}

type Result struct {
	URL					string
	IsVulnerable		bool
	ServiceId			int64
}

/*
	[
		{
			"id":					int64,
			"service":				string,
			"description":			string,
			"URL":					string,
			"reproductionSteps":	[]string,
			"fingerprint":			[]string,
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

func ParseRequestHeaders(rawHeaders string) map[string]string {
	requestHeaders := make(map[string]string)

	headers := strings.Split(rawHeaders, ";;")
		
	for _, header := range headers {
		var parts []string

		if strings.Contains(header, ": ") {
			parts = strings.SplitN(header, ": ", 2)
		} else if strings.Contains(header, ":") {
			parts = strings.SplitN(header, ":", 2)
		} else {
			continue
		}

		requestHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return requestHeaders
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
		if fmt.Sprintf("%v", s.ID) == id {
			return s
		}
	}

	return nil
}

func CheckResponse(URL string, result *Result, requestHeaders map[string]string, timeout float64) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", CNAME), nil)
	if err != nil {
		fmt.Printf("Request Error: %s (%s)\n", fmt.Sprintf("https://%s", CNAME), err)
	}

	for key, value := range requestHeaders {
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Response Error: %s (%s)\n", fmt.Sprintf("https://%s", CNAME), err)
		return false
	}
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)

	fmt.Printf("INFO: Response body: %s (%s)\n", string(body), utils.ParseRE(fingerprint))

	re := regexp.MustCompile(fmt.Sprintf(`%s`, utils.ParseRE(fingerprint))) // Transform array into regex pattern

	return !!re.MatchString(fmt.Sprintf("%s", string(body)))
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or Company name: Intigriti")
	serviceFlag := flag.String("service", "", "Specify the service ID you'd like to check for: \"1\" for Atlassian Jira Service Desk")
	requestHeadersFlag := flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookies: xyz...;;\"")
	timeoutFlag := flag.Float64Var("timeout", 7.0, "Specify a timeout for each request sent in seconds (default: \"7.0\").")
	servicesFlag := flag.Bool("services", false, "Print all services with their associated IDs")

	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag
	var requestHeaders map[string]string = ParseRequestHeaders(*requestHeadersFlag)
	var timeout float64 = *timeoutFlag

	fingerprints = LoadFingerprints()

	if *servicesFlag {
		fmt.Printf("%v Services loaded!\n", len(fingerprints))

		// Print the table header
		fmt.Println("| ID | Service                               ")
		fmt.Println("|----|---------------------------------------")

		// Print each row of the table
		for _, service := range fingerprints {
			fmt.Printf("| %-2d | %-7s\n", service.ID, service.ServiceName)
		}
		return
	}

	if (target == "" || service == "") {
		flag.Usage()
		return
	}

	selectedService := ReturnServiceFingerprint(service)
	if selectedService == nil {
		fmt.Printf("Error: Service ID \"%v\" does not match any integrated service!\n", service)
		return
	}

	possibleDomains := ReturnPossibleDomains(target)

	for _, domain := range possibleDomains {
		var result Result
		targetURL := strings.Replace(fmt.Sprintf("%v", selectedService.(Fingerprint).URL), "{TARGET}", fmt.Sprintf("%s", domain), -1)

		URL, err := url.Parse(targetURL)
		if err != nil {
			fmt.Printf("Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
			continue
		}

		CheckResponse(URL, selectedService, &result, requestHeaders, timeout)

		if result.IsVulnerable {
			fmt.Println("Is Vulnerable!")
		}
	}
}