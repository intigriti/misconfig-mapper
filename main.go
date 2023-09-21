package main

import (
	"os"
	"fmt"
	"flag"
	"time"
	"regexp"
	"strings"
	"net/url"
	"net/http"
	"io/ioutil"
	"crypto/tls"
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
	ServiceId			string
	Service				Fingerprint
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

func ParseFingerprints(v []string) string {
	x := strings.Join(v, `|`) // Split array entries with regex alternation
	x = strings.Replace(x, ".", `\.`, -1) // Escape dot characters
	x = fmt.Sprintf(`%s`, x)

	return x
}

func ReturnPossibleDomains(target string) []string {
	var possibleDomains []string

	// By default, always add target name
	possibleDomains = append(possibleDomains, target)

	// Remove leading and trailing spaces and convert to lowercase
	target = strings.TrimSpace(strings.ToLower(target))

    // Generate domain names by combining the keyword with each TLD
	for _, TLD := range TLDs {
		domain := fmt.Sprintf(`%s.%s`, target, TLD)
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

func CheckResponse(result *Result, service Fingerprint, requestHeaders map[string]string, timeout float64) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", result.URL, nil)
	if err != nil {
		fmt.Printf("[-] Error: Failed to request %s (%v)\n", result.URL, err)
		result.IsVulnerable = false
	}

	for key, value := range requestHeaders {
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] Error: Failed to read response for %s (%v)\n", result.URL, err)
		result.IsVulnerable = false
	}
	if res != nil {
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Printf("[-] Error: Failed to read response body for %s (%v)\n", result.URL, err)
		}

		//fmt.Printf("INFO: Response body: %s (%s)\n", string(body), ParseFingerprints(service.Fingerprints))

		pattern := fmt.Sprintf(`%s`, ParseFingerprints(service.Fingerprints)) // Transform array into regex pattern
		re := regexp.MustCompile(pattern)

		result.IsVulnerable = !!re.MatchString(fmt.Sprintf("%s", string(body)))
	}

	return
}

func PrintResult(result Result) {
	fmt.Println("[+] 1 Vulnerable result found!")
	fmt.Printf("URL: %s\n", result.URL)
	fmt.Printf("Issue: %s\n", result.Service.ServiceName)
	fmt.Printf("Description: %s\n", result.Service.Description)

	fmt.Println("\nReproduction Steps:")
	steps := result.Service.ReproductionSteps
	for _, step := range steps {
		fmt.Printf("\t- %s\n", step)
	}

	fmt.Println("\nReference:")
	fmt.Printf("\t- %s\n\n", result.Service.Reference)
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or Company name: Intigriti")
	serviceFlag := flag.String("service", "0", "Specify the service ID you'd like to check for: \"0\" for Atlassian Jira Service Desk.") // Add support for wildcards
	requestHeadersFlag := flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookies: xyz...;;\"")
	timeoutFlag := flag.Float64("timeout", 7.0, "Specify a timeout for each request sent in seconds (default: \"7.0\").")
	servicesFlag := flag.Bool("services", false, "Print all services with their associated IDs")

	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag
	var requestHeaders map[string]string = ParseRequestHeaders(*requestHeadersFlag)
	var timeout float64 = *timeoutFlag

	fingerprints = LoadFingerprints()

	if *servicesFlag {
		fmt.Printf("[+] %v Service(s) loaded!\n", len(fingerprints))

		// Print the table header
		fmt.Println("| ID | Service                               ")
		fmt.Println("|----|---------------------------------------")

		// Print each row of the table
		for _, service := range fingerprints {
			fmt.Printf("| %-2d | %-7s\n", service.ID, service.ServiceName)
		}
		return
	}

	if target == "" {
		flag.Usage()
		return
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	selectedService := ReturnServiceFingerprint(service)
	if selectedService == nil {
		fmt.Printf("[-] Error: Service ID \"%v\" does not match any integrated service!\n", service)
		return
	}

	possibleDomains := ReturnPossibleDomains(target)

	fmt.Printf("[+] Checking %v possible target URLs...\n", len(possibleDomains))

	for _, domain := range possibleDomains {
		var result Result
		targetURL := strings.Replace(fmt.Sprintf("%v", selectedService.(Fingerprint).URL), "{TARGET}", fmt.Sprintf("%s", domain), -1)

		URL, err := url.Parse(targetURL)
		if err != nil {
			fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
			continue // Skip invalid URLs and move on to the next one
		}

		result.URL = URL.String()
		result.ServiceId = service
		result.Service = selectedService.(Fingerprint)
		result.IsVulnerable = false // Default value

		CheckResponse(&result, selectedService.(Fingerprint), requestHeaders, timeout)

		if result.IsVulnerable {
			PrintResult(result)

			break
		} else {
			fmt.Println("[-] Not vulnerable", result.URL)
		}
	}
}