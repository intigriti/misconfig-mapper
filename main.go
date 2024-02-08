package main

import (
	"os"
	"fmt"
	"flag"
	"time"
	"regexp"
	"context"
	"strings"
	"net/url"
	"net/http"
	"io/ioutil"
	"crypto/tls"
	"encoding/json"
)

/* /TYPES */

type Service struct {
	ID					int64		`json:"id"`
	BaseURL				string		`json:"baseURL"`
	Path				string		`json:"path"`
	Service				string		`json:"service"`
	ServiceName			string 		`json:"serviceName"`
	Description			string	 	`json:"description"`
	ReproductionSteps	[]string	`json:"reproductionSteps"`
	Passive				[]string	`json:"passive"`
	Active				[]string	`json:"active"`
	References			[]string	`json:"references"`
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
			"id":					int64,
			"baseURL":				string,
			"path":					string,
			"service":				string,
			"description":			string,
			"reproductionSteps":	[]string,
			"passive":				[]string,
			"active":				[]string,
			"references":			[]string
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

	file, err := os.Open("./services.json")
	if err != nil {
		fmt.Println("ERROR: Failed opening file \"./services.json\":", err)
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

func CheckResponse(result *Result, service Service, passiveOnly bool, requestHeaders map[string]string, timeout int, verbose bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout) * time.Millisecond)
	defer cancel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow max 4 redirects
			if len(via) >= 4 {
				return fmt.Errorf("[-] Error: Too many redirects encountered for %v\n", result.URL)
			}
			return nil
		},
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	req, err := http.NewRequest("GET", result.URL, nil)
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

		if passiveOnly {
			pattern := fmt.Sprintf(`%s`, ParseRegex(service.Passive)) // Transform array into regex pattern
			re := regexp.MustCompile(pattern)

			result.Exists = !!re.MatchString(fmt.Sprintf("%s", string(body)))
			return
		}

		pattern := fmt.Sprintf(`%s`, ParseRegex(service.Active)) // Transform array into regex pattern
		re := regexp.MustCompile(pattern)

		result.Vulnerable = !!re.MatchString(fmt.Sprintf("%s", string(body)))
	}

	return
}

func PrintResult(result Result, passiveOnly bool) {
	if passiveOnly {
		fmt.Printf("[+] 1 %s Instance found!\n", result.Service.ServiceName)
	} else {
		fmt.Println("[+] 1 Vulnerable result found!")
	}

	fmt.Printf("URL: %s\n", result.URL)
	fmt.Printf("Service: %s\n", result.Service.ServiceName)
	fmt.Printf("Description: %s\n", result.Service.Description)

	fmt.Println("\nReproduction Steps:")
	for _, step := range result.Service.ReproductionSteps {
		fmt.Printf("\t- %s\n", step)
	}

	fmt.Println("\nReference:")
	for _, ref := range result.Service.References {
		fmt.Printf("\t- %s\n", ref)
	}
}

func PrintServices(services []Service, verbose bool) {
	if verbose {
		fmt.Printf("[+] %v Service(s) loaded!\n", len(services))
	}

	// Print the table header
	fmt.Println("| ID | Service                               ")
	fmt.Println("|----|---------------------------------------")

	// Print each row of the table
	for _, service := range services {
		fmt.Printf("| %-2d | %-7s\n", service.ID, service.ServiceName)
	}
}

func main() {
	targetFlag := flag.String("target", "", "Specify your target domain name or company/organization name: \"intigriti.com\" or \"intigriti\"")
	serviceFlag := flag.String("service", "0", "Specify the service ID you'd like to check for: \"0\" for Atlassian Jira Open Signups. Wildcards are also accepted to check for all services.")
	passiveOnlyFlag := flag.Bool("passive-only", false, "Only check for existing instances (don't check for misconfigurations). Default: \"false\"")
	permutationsFlag := flag.Bool("permutations", true, "Enable permutations and look for several other keywords of your target. Default: \"true\"")
	requestHeadersFlag := flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookie: xyz...;;\"")
	delayFlag := flag.Int("delay", 0, "Specify a delay between each request sent in milliseconds to enforce a rate limit (default: \"0\").")
	timeoutFlag := flag.Int("timeout", 7000, "Specify a timeout for each request sent in milliseconds.")
	servicesFlag := flag.Bool("services", false, "Print all services with their associated IDs")
	verboseFlag := flag.Bool("verbose", false, "Print verbose messages")

	flag.Parse()

	var target string = *targetFlag
	var service string = *serviceFlag
	var passiveOnly bool = *passiveOnlyFlag
	var permutations bool = *permutationsFlag
	var requestHeaders map[string]string = ParseRequestHeaders(*requestHeadersFlag)
	var delay int = *delayFlag
	var timeout int = *timeoutFlag
	var verbose bool = *verboseFlag

	services, err := LoadServices()
	if err != nil {
		fmt.Println("[-] Error: Failed to load services.")
		os.Exit(0)
	}

	if *servicesFlag {
		PrintServices(services, verbose)
		return
	}

	if target == "" {
		flag.Usage()
		return
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	if service == "*" {
		selectedServices = services
	} else {
		s := GetService(service, services)
		if s == nil || len(s.([]Service)) < 1 {
			fmt.Printf("[-] Error: Service ID \"%v\" does not match any integrated service!\n\nAvailable Services:\n", service)
			PrintServices(services, verbose)
			return
		}

		if verbose {
			fmt.Printf("[+] %v Services selected!\n", len(s.([]Service)))
		}
	
		selectedServices = append(selectedServices, s.([]Service)...)
	}

	var possibleDomains []string

	if !!permutations {
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
			targetURL := strings.Replace(fmt.Sprintf("%v%v", selectedService.BaseURL, selectedService.Path), "{TARGET}", fmt.Sprintf("%s", domain), -1)

			URL, err := url.Parse(targetURL)
			if err != nil {
				if verbose {
					fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping... (%v)\n", targetURL, err)
				} else {
					fmt.Printf("[-] Error: Invalid Target URL \"%s\"... Skipping...\n", targetURL)
				}
				continue // Skip invalid URLs and move on to the next one
			}

			result.URL = URL.String()
			result.ServiceId = service
			result.Service = selectedService
			result.Exists = false // Default value
			result.Vulnerable = false // Default value

			time.Sleep(time.Duration(delay) * time.Millisecond)

			CheckResponse(&result, selectedService, passiveOnly, requestHeaders, timeout, verbose)

			if result.Exists || result.Vulnerable {
				PrintResult(result, passiveOnly)

				break
			} else {
				if !result.Exists {
					fmt.Printf("[-] No %s instance vulnerable found (%s)\n", result.Service.ServiceName, result.URL)
					continue
				}

				if (!result.Exists && !result.Vulnerable) {
					fmt.Printf("[-] %s instance is not vulnerable (%s)\n", result.Service.ServiceName, result.URL)
				}
			}
		}
	}
}