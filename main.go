package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
	"golang.org/x/time/rate"
)

/* /TYPES */

type Service struct {
	ID      int64 `json:"id"`
	Request struct {
		Method  string              `json:"method"`
		BaseURL string              `json:"baseURL"`
		Path    []string            `json:"path"`
		Headers []map[string]string `json:"headers"`
		Body    any                 `json:"body"`
	} `json:"request"`
	Response struct {
		StatusCode            int64    `json:"statusCode"`
		DetectionFingerprints []string `json:"detectionFingerprints"`
		Fingerprints          []string `json:"fingerprints"`
	} `json:"response"`
	Metadata struct {
		Service           string   `json:"service"`
		ServiceName       string   `json:"serviceName"`
		Description       string   `json:"description"`
		ReproductionSteps []string `json:"reproductionSteps"`
		References        []string `json:"references"`
	} `json:"metadata"`
}

type Result struct {
	URL        string  // Result URL
	Exists     bool    // Used to report back in case the instance exists
	Vulnerable bool    // Used to report back in case the instance is vulnerable
	ServiceId  string  // Service ID
	Service    Service // Service struct
}

type RequestContext struct {
	SkipChecks   bool
	Headers      map[string]string
	Timeout      int
	MaxRedirects int
	Verbose      bool
}

/* TYPES/ */

/*
	[
		{
			"id":							int64,
			"request": {
				"method":					string,
				"baseURL":					string,
				"path":						string
				"headers":					[]map[string]string
				"body":						string | nil
			},
			"response": {
				"statusCode":				int64,
				"detectionFingerprints":	[]string,
				"fingerprints":				[]string
			},
			"metadata": {
				"service":					string,
				"description":				string,
				"reproductionSteps":		[]string,
				"references":				[]string
			}
		}
	]
*/

var servicesPath string = `./templates/services.json`
var selectedServices []Service

var suffixes = []string{
	"com",
	"net",
	"org",
	"io",
	"fr",
	"org",
	"ltd",
	"app",
	"prod",
	"internal",
	"dev",
	"developement",
	"devops",
	"stage",
	"production",
	"dev-only",
	// Add more suffixes as needed
}

func loadTemplates() ([]Service, error) {
	var services []Service

	file, err := os.Open("./templates/services.json")
	if err != nil {
		fmt.Println("ERROR: Failed opening file \"./templates/services.json\":", err)
		return services, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&services); err != nil {
		fmt.Println("ERROR: Failed decoding JSON file:", err)
		return services, err
	}

	return services, nil
}

// Pull latest services from GitHub
func updateTemplates(path *string, update bool) *error {
	fmt.Printf("[+] Info: Pulling latest services and saving in %v\n", servicesPath)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(7000)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, `GET`, `https://raw.githubusercontent.com/intigriti/misconfig-mapper/main/templates/services.json`, nil)
	if err != nil {
		return &err
	}

	client := http.Client{}

	res, err := client.Do(req)
	if err != nil {
		return &err
	}
	if res != nil {
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return &err
		}

		var s *os.File
		if update {
			s, err = os.OpenFile(*path, os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println(1, err)
				return &err
			}
			defer s.Close()
		} else {
			fmt.Println("[+] Info: Creating templates directory...")

			// create "templates" directory
			_ = os.Mkdir(`./templates`, 0700)

			// Create "services.json" file
			s, err = os.Create(*path)
			if err != nil {
				return &err
			}
			defer s.Close()
		}

		_, err = io.Copy(s, bytes.NewReader(body))
		if err != nil {
			return &err
		}
	}

	fmt.Println("[+] Info: Successfully pulled the latest templates!")

	return nil
}

func parseRequestHeaders(rawHeaders string) map[string]string {
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

func parseRegex(v []string) string {
	x := strings.Join(v, `|`)             // Split array entries with regex alternation
	x = strings.Replace(x, ".", `\.`, -1) // Escape dot characters

	return x
}

func returnPossibleDomains(target string) []string {
	var possibleDomains []string

	// By default, always add target name
	possibleDomains = append(possibleDomains, target)

	// Remove leading and trailing spaces and convert to lowercase
	target = strings.TrimSpace(strings.ToLower(target))

	// Generate domain names by combining the keyword with each suffix
	for _, s := range suffixes {
		for _, c := range []string{".", "-", ""} {
			domain := fmt.Sprintf(`%s%s%s`, target, c, s) // {target}{character}{suffix}
			possibleDomains = append(possibleDomains, domain)
		}
	}

	return possibleDomains
}

func getTemplate(id string, services []Service) interface{} {
	var s []Service

	for _, x := range services {
		if (fmt.Sprintf(`%v`, x.ID) == id) || (fmt.Sprintf(`%v`, x.Metadata.Service) == id) {
			s = append(s, x)
		}
	}

	if len(s) > 0 {
		return s
	}

	return nil
}

func craftTargetURL(baseURL string, path string, domain string) string {
	var targetURL string

	// Normalize protocol as it is already defined in the template's "baseURL" field
	domain = regexp.MustCompile(`^http(s)?:\/\/`).ReplaceAllString(domain, "")
	targetURL = strings.Replace(fmt.Sprintf(`%v%v`, baseURL, path), "{TARGET}", domain, -1)

	return targetURL
}

func checkResponse(result *Result, service *Service, r *RequestContext) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.Timeout)*time.Millisecond)
	defer cancel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow max amount of specified redirects
			if len(via) >= r.MaxRedirects {
				return fmt.Errorf("[-] Error: Too many redirects encountered for %v", result.URL)
			}
			return nil
		},
		Timeout: time.Duration(r.Timeout) * time.Millisecond,
	}

	var requestBody io.Reader = nil
	if service.Request.Body != nil {
		requestBody = bytes.NewBuffer([]byte(fmt.Sprintf(`%v`, service.Request.Body)))
	}

	req, err := http.NewRequestWithContext(ctx, fmt.Sprintf(`%v`, service.Request.Method), result.URL, requestBody)
	if err != nil {
		if r.Verbose {
			fmt.Printf("[-] Error: Failed to request %s (%v)\n", result.URL, err)
		} else {
			fmt.Printf("[-] Error: Failed to request %s\n", result.URL)
		}
		result.Vulnerable = false
	}

	if req == nil {
		fmt.Printf("[-] Error: HTTP Request is empty")
		return
	}

	req = req.WithContext(ctx)

	if len(service.Request.Headers) > 0 {
		for _, header := range service.Request.Headers {
			for key, value := range header {
				req.Header.Set(key, value)
			}
		}
	}

	// Request headers set by CLI take preference over request headers specified in templates
	for key, value := range r.Headers {
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := client.Do(req)
	if err != nil {
		if r.Verbose {
			fmt.Printf("[-] Error: Failed to read response for %s (%v)\n", result.URL, err)
		} else {
			fmt.Printf("[-] Error: Failed to read response for %s\n", result.URL)
		}
		result.Exists = false
		result.Vulnerable = false
	}
	if res != nil {
		defer res.Body.Close()

		var statusCodeMatched bool = false
		if res.StatusCode == int(service.Response.StatusCode) {
			statusCodeMatched = true
		}

		var responseHeaders string = ""
		for key, values := range res.Header {
			for _, value := range values {
				responseHeaders += fmt.Sprintf(`%v: %v\n`, key, value)
			}
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			if r.Verbose {
				fmt.Printf("[-] Error: Failed to read response body for %s (%v)\n", result.URL, err)
			} else {
				fmt.Printf("[-] Error: Failed to read response body for %s\n", result.URL)
			}
		}

		if r.SkipChecks {
			expr := parseRegex(service.Response.DetectionFingerprints) // Transform array into regex pattern

			re, err := regexp.Compile(expr)
			if err != nil {
				fmt.Printf("[-] Error: Invalid detection expression supplied for service \"%v\" (error: %v)!\n", service.Metadata.ServiceName, err)
				return
			}

			result.Exists = re.MatchString(fmt.Sprintf(`%v %v`, responseHeaders, string(body)))

			return
		}

		expr := parseRegex(service.Response.Fingerprints) // Transform array into regex pattern

		re, err := regexp.Compile(expr)
		if err != nil {
			fmt.Printf("[-] Error: Invalid expression supplied for service \"%v\" (error: %v)!\n", service.Metadata.ServiceName, err)
			return
		}

		result.Vulnerable = (re.MatchString(fmt.Sprintf(`%v %v`, responseHeaders, string(body))) && statusCodeMatched)
	}
}

func handleResult(result *Result, reqCTX *RequestContext, width int) {
	fmt.Println(strings.Repeat("-", width))

	if reqCTX.SkipChecks {
		fmt.Printf("[+] 1 %s detected!\n", result.Service.Metadata.ServiceName)
	} else {
		fmt.Println("[+] 1 Vulnerable result found!")
	}

	fmt.Printf("URL: %s\n", result.URL)
	fmt.Printf("Service: %s\n", result.Service.Metadata.ServiceName)
	fmt.Printf("Description: %s\n", result.Service.Metadata.Description)

	if !reqCTX.SkipChecks {
		if len(result.Service.Metadata.ReproductionSteps) > 0 {
			fmt.Println("\nReproduction Steps:")
			for _, step := range result.Service.Metadata.ReproductionSteps {
				fmt.Printf("\t- %s\n", step)
			}
		}
	}

	if len(result.Service.Metadata.References) > 0 {
		fmt.Println("\nReferences:")
		for _, ref := range result.Service.Metadata.References {
			fmt.Printf("\t- %s\n", ref)
		}
	}

	fmt.Println(strings.Repeat("-", width))
}

func printServices(services []Service, verbose bool, width int) {
	if verbose {
		fmt.Printf("[+] %v Service(s) loaded!\n", len(services))
	}

	// Print the table header
	fmt.Println("| ID | Service")
	fmt.Printf(`|----|%v`, strings.Repeat("-", width-6))

	// Print each row of the table
	for _, service := range services {
		fmt.Printf("| %-2d | %-7s\n", service.ID, service.Metadata.ServiceName)
	}
}

func isFile(path string) bool {
	if filepath.Ext(path) == "" {
		return false
	}

	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func processInput(fileName string, input *[]string) {
	file, err := os.Open(fmt.Sprintf(`%v`, fileName))
	if err != nil {
		fmt.Printf("[-] Error: Failed to open file! (%v)", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		*input = append(*input, fmt.Sprintf(`%v`, scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Error: Failed to read file! (%v)", err)
		return
	}
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or company/organization name: \"intigriti.com\" or \"intigriti\" (files are also accepted)")
	serviceFlag := flag.String("service", "0", "Specify the service ID you'd like to check for: \"0\" for Atlassian Jira Open Signups. Wildcards are also accepted to check for all services.")
	skipChecksFlag := flag.String("skip-misconfiguration-checks", "false", "Only check for existing instances (and skip checks for potential security misconfigurations).")
	permutationsFlag := flag.String("permutations", "true", "Enable permutations and look for several other keywords of your target.")
	requestHeadersFlag := flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookie: xyz...;;\")")
	delayFlag := flag.Int("delay", 0, "Specify a delay between each request sent in milliseconds to enforce a rate limit.")
	timeoutFlag := flag.Int("timeout", 7000, "Specify a timeout for each request sent in milliseconds.")
	maxRedirectsFlag := flag.Int("max-redirects", 5, "Specify the max amount of redirects to follow.")
	listServicesFlag := flag.Bool("list-services", false, "Print all services with their associated IDs")
	updateServicesFlag := flag.Bool("update-templates", false, "Pull the latest templates & update your current services.json file")
	verboseFlag := flag.Bool("verbose", false, "Print verbose messages")

	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag
	var delay int = *delayFlag

	var reqCTX RequestContext = RequestContext{
		SkipChecks:   false,
		Headers:      parseRequestHeaders(*requestHeadersFlag),
		Timeout:      *timeoutFlag,
		MaxRedirects: *maxRedirectsFlag,
		Verbose:      *verboseFlag,
	}

	// Derrive terminal width
	fd := int(os.Stdout.Fd())
	width, _, _ := term.GetSize(fd)

	if *updateServicesFlag {
		// If "services.json" already exists, update the templates
		update := isFile(servicesPath)

		err := updateTemplates(&servicesPath, update)
		if err != nil {
			fmt.Printf("[-] Error: Failed to update templates! (%v)\n", *err)
		}

		os.Exit(0)
	}

	services, err := loadTemplates()
	if err != nil {
		fmt.Println("[-] Error: Failed to load services!")

		err := updateTemplates(&servicesPath, false)
		if err != nil {
			fmt.Printf("[-] Error: Failed to pull latest services! (%v)\n", *err)
			os.Exit(0)
		}

		// Reload new templates
		services, _ = loadTemplates()
	}

	if *listServicesFlag {
		printServices(services, reqCTX.Verbose, width)
		return
	}

	if target == "" {
		flag.Usage()
		return
	}

	// Initiate new rate limiter
	limiter := rate.NewLimiter(rate.Every(time.Duration(delay)*time.Millisecond), 1)

	// Allow insecure HTTP requests
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	if service == "*" {
		selectedServices = services
	} else {
		s := getTemplate(service, services)
		if s == nil || len(s.([]Service)) < 1 {
			fmt.Printf("[-] Error: Service ID \"%v\" does not match any integrated service!\n\nAvailable Services:\n", service)
			printServices(services, reqCTX.Verbose, width)
			return
		}

		if reqCTX.Verbose {
			fmt.Printf("[+] %v Services selected!\n", len(s.([]Service)))
		}

		selectedServices = append(selectedServices, s.([]Service)...)
	}

	// Parse "skip-misconfiguration-checks" CLI flag
	switch strings.ToLower(*skipChecksFlag) {
	case "y", "yes", "true", "on", "1", "enable":
		reqCTX.SkipChecks = true
	case "", "n", "no", "false", "off", "0", "disable":
		reqCTX.SkipChecks = false
	default:
		reqCTX.SkipChecks = false
		fmt.Printf("[-] Warning: Invalid skipChecks flag value supplied: \"%v\"\n", *skipChecksFlag)
	}

	// Parse "permutations" CLI flag
	var possibleDomains []string
	var permutations bool

	switch strings.ToLower(*permutationsFlag) {
	case "y", "yes", "true", "on", "1", "enable":
		permutations = true
	case "", "n", "no", "false", "off", "0", "disable":
		permutations = false
	default:
		permutations = false
		fmt.Printf("[-] Warning: Invalid permutations flag value supplied: \"%v\"\n", *permutationsFlag)
	}

	if isFile(target) {
		// Load all lines and loop over file
		var targets []string = []string{}
		processInput(target, &targets)

		if permutations {
			for _, e := range targets {
				possibleDomains = append(possibleDomains, returnPossibleDomains(e)...)
			}
		} else {
			possibleDomains = append(possibleDomains, targets...)
		}
	} else {
		// Treat target as a domain
		if permutations {
			// Perform permutations on target and scan all of them
			possibleDomains = returnPossibleDomains(target)
		} else {
			// Only perfom a scan on the supplied target flag value
			possibleDomains = append(possibleDomains, target)
		}
	}

	fmt.Printf("[+] Checking %v possible target URLs...\n", len(possibleDomains))

	for _, selectedService := range selectedServices {
		for _, domain := range possibleDomains {
			for _, path := range selectedService.Request.Path {
				var result Result
				var targetURL string

				limiter.Wait(context.Background())

				// Make sure we only request the baseURL when we're only looking if the technology exists
				if reqCTX.SkipChecks {
					path = "/"
				}

				// Crafting URL
				targetURL = craftTargetURL(selectedService.Request.BaseURL, path, domain)

				URL, err := url.Parse(targetURL)
				if err != nil {
					if reqCTX.Verbose {
						fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
					} else {
						fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping...\n", targetURL)
					}
					continue // Skip invalid URLs and move on to the next one
				}

				if !permutations && (URL.Scheme == "") {
					URL.Scheme = "https"
				}

				result.URL = URL.String()
				result.ServiceId = service
				result.Service = selectedService
				result.Exists = false     // Default value
				result.Vulnerable = false // Default value

				checkResponse(&result, &selectedService, &reqCTX)

				if result.Exists || result.Vulnerable {
					handleResult(&result, &reqCTX, width)
					break
				} else {
					if !result.Exists {
						if reqCTX.SkipChecks {
							fmt.Printf("[-] No %s instance found (%s)\n", result.Service.Metadata.ServiceName, result.URL)
						} else {
							fmt.Printf("[-] No vulnerable %s instance found (%s)\n", result.Service.Metadata.ServiceName, result.URL)
						}

						continue
					}

					if !result.Exists && !result.Vulnerable {
						fmt.Printf("[-] %s instance is not vulnerable (%s)\n", result.Service.Metadata.ServiceName, result.URL)
					}
				}
			}
		}
	}
}
