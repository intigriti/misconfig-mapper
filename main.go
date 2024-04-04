package main

import (
	"io"
	"os"
	"fmt"
	"flag"
	"time"
	"bytes"
	"regexp"
	"context"
	"strings"
	"net/url"
	"net/http"
	"io/ioutil"
	"crypto/tls"
	"encoding/json"
	"golang.org/x/time/rate"
	"golang.org/x/crypto/ssh/terminal"
)

/* /TYPES */

type Service struct {
	ID					int64		`json:"id"`
	Service				string		`json:"service"`
	Request				struct		{
		Method				string		`json:"method"`
		BaseURL				string		`json:"baseURL"`
		Path				string		`json:"path"`
		Body				any			`json:"body"`
	}	`json:"request"`
	Response			struct		{
		StatusCode			int64		`json:"statusCode"`
		Passive				[]string	`json:"passive"`
		Active				[]string	`json:"active"`
	}	`json:"response"`
	Metadata			struct		{
		ServiceName			string 		`json:"serviceName"`
		Description			string	 	`json:"description"`
		ReproductionSteps	[]string	`json:"reproductionSteps"`
		References			[]string	`json:"references"`
	}	`json:"metadata"`
}

type Result struct {
	URL					string		// Result URL
	Exists				bool		// Used to report back in case the instance exists
	Vulnerable			bool		// Used to report back in case the instance is vulnerable
	ServiceId			string		// Service ID
	Service				Service		// Service struct
}

/* TYPES/ */

/*
	[
		{
			"id":						int64,
			"request": {
				"method":				string,
				"baseURL":				string,
				"path":					string
			},
			"response": {
				"statusCode":			int64,
				"passive":				[]string,
				"active":				[]string
			},
			"metadata": {
				"service":				string,
				"description":			string,
				"reproductionSteps":	[]string,
				"references":			[]string
			}
		}
	]
*/

var services []Service
var selectedServices []Service

var suffixes []string = []string{
	"com",
	"net",
	"org",
	"io",
	"fr",
	"org",
	"ltd",
	"app",
	// Add more TLDs as needed
}

func LoadServices() ([]Service, error) {
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

func ParseRegex(v []string) string {
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

    // Generate domain names by combining the keyword with each suffix
	for _, s := range suffixes {
		for _, c := range []string{".", "-", ""} {
			domain := fmt.Sprintf(`%s%s%s`, target, c, s) // {target}{character}{suffix}
			possibleDomains = append(possibleDomains, domain)
		}
	}

	return possibleDomains
}

func GetService(id string, services []Service) interface{} {
	s := []Service{}

	for _, x := range services {
		if (fmt.Sprintf("%v", x.ID) == id) || (fmt.Sprintf("%v", x.Service) == id) {
			s = append(s, x)
		}
	}

	if len(s) > 0 {
		return s
	}

	return nil
}

func CheckResponse(result *Result, service Service, passiveOnly bool, requestHeaders map[string]string, timeout int, maxRedirects int, verbose bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout) * time.Millisecond)
	defer cancel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow max amount of specified redirects
			if len(via) >= maxRedirects {
				return fmt.Errorf("[-] Error: Too many redirects encountered for %v\n", result.URL)
			}
			return nil
		},
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	var requestBody io.Reader = nil
	if service.Request.Body != nil {
		requestBody = bytes.NewBuffer([]byte(fmt.Sprintf(`%v`, service.Request.Body)))
	}

	req, err := http.NewRequest(fmt.Sprintf(`%v`, service.Request.Method), result.URL, requestBody)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Error: Failed to request %s (%v)\n", result.URL, err)
		} else {
			fmt.Printf("[-] Error: Failed to request %s\n", result.URL)
		}
		result.Vulnerable = false
	}

	req.WithContext(ctx)

	for key, value := range requestHeaders {
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Error: Failed to read response for %s (%v)\n", result.URL, err)
		} else {
			fmt.Printf("[-] Error: Failed to read response for %s\n", result.URL)
		}
		result.Exists = false
		result.Vulnerable = false
	}
	if res != nil {
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			if verbose {
				fmt.Printf("[-] Error: Failed to read response body for %s (%v)\n", result.URL, err)
			} else {
				fmt.Printf("[-] Error: Failed to read response body for %s\n", result.URL)
			}
		}

		var statusCodeMatched bool = false
		if res.StatusCode == int(service.Response.StatusCode) {
			statusCodeMatched = true
		}

		if passiveOnly {
			pattern := fmt.Sprintf(`%s`, ParseRegex(service.Response.Passive)) // Transform array into regex pattern
			result.Exists = !!regexp.MustCompile(pattern).MatchString(fmt.Sprintf("%s", string(body))) && statusCodeMatched

			return
		}

		pattern := fmt.Sprintf(`%s`, ParseRegex(service.Response.Active)) // Transform array into regex pattern
		result.Vulnerable = !!regexp.MustCompile(pattern).MatchString(fmt.Sprintf("%s", string(body))) && statusCodeMatched
	}

	return
}

func PrintResult(result Result, passiveOnly bool, width int) {
	fmt.Println(strings.Repeat("-", width))

	if passiveOnly {
		fmt.Printf("[+] 1 %s Instance found!\n", result.Service.Metadata.ServiceName)
	} else {
		fmt.Println("[+] 1 Vulnerable result found!")
	}

	fmt.Printf("URL: %s\n", result.URL)
	fmt.Printf("Service: %s\n", result.Service.Metadata.ServiceName)
	fmt.Printf("Description: %s\n", result.Service.Metadata.Description)

	if len(result.Service.Metadata.ReproductionSteps) > 0 {
		fmt.Println("\nReproduction Steps:")
		for _, step := range result.Service.Metadata.ReproductionSteps {
			fmt.Printf("\t- %s\n", step)
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

func PrintServices(services []Service, verbose bool, width int) {
	if verbose {
		fmt.Printf("[+] %v Service(s) loaded!\n", len(services))
	}

	// Print the table header
	fmt.Println("| ID | Service                               ")
	fmt.Printf(`|----|%v`, strings.Repeat("-", width - 6))

	// Print each row of the table
	for _, service := range services {
		fmt.Printf("| %-2d | %-7s\n", service.ID, service.Metadata.ServiceName)
	}
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or company/organization name: \"intigriti.com\" or \"intigriti\"")
	serviceFlag := flag.String("service", "0", "Specify the service ID you'd like to check for: \"0\" for Atlassian Jira Open Signups. Wildcards are also accepted to check for all services.")
	passiveOnlyFlag := flag.String("passive-only", "", "Only check for existing instances (don't check for misconfigurations).")
	permutationsFlag := flag.String("permutations", "true", "Enable permutations and look for several other keywords of your target.")
	requestHeadersFlag := flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookie: xyz...;;\"")
	delayFlag := flag.Int("delay", 0, "Specify a delay between each request sent in milliseconds to enforce a rate limit.")
	timeoutFlag := flag.Int("timeout", 7000, "Specify a timeout for each request sent in milliseconds.")
	maxRedirectsFlag := flag.Int("max-redirects", 3, "Specify the max amount of redirects to follow.")
	listServicesFlag := flag.Bool("list-services", false, "Print all services with their associated IDs")
	verboseFlag := flag.Bool("verbose", false, "Print verbose messages")

	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag
	var requestHeaders map[string]string = ParseRequestHeaders(*requestHeadersFlag)
	var delay int = *delayFlag
	var timeout int = *timeoutFlag
	var maxRedirects int = *maxRedirectsFlag
	var verbose bool = *verboseFlag

	// Derrive terminal width
	fd := int(os.Stdout.Fd())
	width, _, _ := terminal.GetSize(fd)

	services, err := LoadServices()
	if err != nil {
		fmt.Println("[-] Error: Failed to load services.")
		os.Exit(0)
	}

	if *listServicesFlag {
		PrintServices(services, verbose, width)
		return
	}

	if target == "" {
		flag.Usage()
		return
	}

	limiter := rate.NewLimiter(rate.Every(time.Duration(delay) * time.Millisecond), 1)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	if service == "*" {
		selectedServices = services
	} else {
		s := GetService(service, services)
		if s == nil || len(s.([]Service)) < 1 {
			fmt.Printf("[-] Error: Service ID \"%v\" does not match any integrated service!\n\nAvailable Services:\n", service)
			PrintServices(services, verbose, width)
			return
		}

		if verbose {
			fmt.Printf("[+] %v Services selected!\n", len(s.([]Service)))
		}
	
		selectedServices = append(selectedServices, s.([]Service)...)
	}

	// Parse "passive-only" CLI flag
	var passiveOnly bool = false

	switch strings.ToLower(*passiveOnlyFlag) {
		case "", "y", "yes", "true", "on", "1":
			passiveOnly = true
			break
		case "n", "no", "false", "off", "0":
			passiveOnly = false
			break
		default:
			passiveOnly = false
			break
	}

	// Parse "permutations" CLI flag
	var possibleDomains []string
	var permutations bool

	switch strings.ToLower(*permutationsFlag) {
		case "", "y", "yes", "true", "on", "1":
			permutations = true
			break
		case "n", "no", "false", "off", "0":
			permutations = false
			break
		default:
			permutations = false
			break
    }

    if permutations {
    	// Perform permutations on target and scan all of them
		possibleDomains = ReturnPossibleDomains(target)
    } else {
    	// Only perfom scan on the supplied target flag value
		possibleDomains = append(possibleDomains, target)
    }

	fmt.Printf("[+] Checking %v possible target URLs...\n", len(possibleDomains))

	for _, selectedService := range selectedServices {
		for _, domain := range possibleDomains {
			var result Result
			var targetURL string

			limiter.Wait(context.Background())
			
			if permutations {
				targetURL = strings.Replace(fmt.Sprintf("%v%v", selectedService.Request.BaseURL, selectedService.Request.Path), "{TARGET}", fmt.Sprintf("%s", domain), -1)
			} else {
				targetURL = fmt.Sprintf("%v%v", domain, selectedService.Request.Path)
			}

			URL, err := url.Parse(targetURL)
			if err != nil {
				if verbose {
					fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
				} else {
					fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping...\n", targetURL)
				}
				continue // Skip invalid URLs and move on to the next one
			}

			if !permutations {
				if URL.Scheme == "" {
					URL.Scheme = "https"
				}
			}

			result.URL = URL.String()
			result.ServiceId = service
			result.Service = selectedService
			result.Exists = false // Default value
			result.Vulnerable = false // Default value

			CheckResponse(&result, selectedService, passiveOnly, requestHeaders, timeout, maxRedirects, verbose)

			if result.Exists || result.Vulnerable {
				PrintResult(result, passiveOnly, width)

				break
			} else {
				if !result.Exists {
					fmt.Printf("[-] No %s instance vulnerable found (%s)\n", result.Service.Metadata.ServiceName, result.URL)
					continue
				}

				if (!result.Exists && !result.Vulnerable) {
					fmt.Printf("[-] %s instance is not vulnerable (%s)\n", result.Service.Metadata.ServiceName, result.URL)
				}
			}
		}
	}
}