package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/intigriti/misconfig-mapper/internal/types"
)

// Config represents the application configuration
type Config struct {
	Target          string
	AsDomain        bool
	ServiceID       string
	SkipChecks      bool
	EnablePerms     bool
	RequestHeaders  map[string]string
	Delay           int
	Timeout         int
	MaxRedirects    int
	SkipSSL         bool
	ListServices    bool
	ListTemplates   bool
	TemplatesPath   string
	UpdateTemplates bool
	JSONLines       bool
	Verbosity       types.VerbosityLevel
}

// ParseConfig parses command line arguments and returns a Config
func ParseConfig() (*Config, error) {
	var (
		targetFlag         = flag.String("target", "", "Specify your target company/organization name: \"intigriti\" (files are also accepted). If the target is a domain, add -as-domain")
		asDomainFlag       = flag.String("as-domain", "false", "Treat the target as if its a domain. This flag cannot be used with -permutations.")
		serviceFlag        = flag.String("service", "0", "Specify the service ID you'd like to check for. For example, \"0\" for Atlassian Jira Open Signups. Use comma seperated values for multiple (i.e. \"0,1\" for two services). Use \"*\" to check for all services.")
		skipChecksFlag     = flag.String("skip-misconfiguration-checks", "false", "Only check for existing instances (and skip checks for potential security misconfigurations).")
		permutationsFlag   = flag.String("permutations", "true", "Enable permutations and look for several other keywords of your target. This flag cannot be used with -as-domain.")
		requestHeadersFlag = flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookie: xyz...;;\")")
		delayFlag          = flag.Int("delay", 0, "Specify a delay between each request sent in milliseconds to enforce a rate limit.")
		timeoutFlag        = flag.Int("timeout", 7000, "Specify a timeout for each request sent in milliseconds.")
		maxRedirectsFlag   = flag.Int("max-redirects", 5, "Specify the max amount of redirects to follow.")
		skipSSL            = flag.Bool("skip-ssl", false, "Skip SSL/TLS verification (exercise caution!)")
		listServicesFlag   = flag.Bool("list-services", false, "Print all services with their associated IDs")
		listTemplatesFlag  = flag.Bool("list-templates", false, "Print all services with their associated IDs (alias for -list-services)")
		templatesPath      = flag.String("templates", "./templates", "Specify the templates folder location")
		updateServicesFlag = flag.Bool("update-templates", false, "Pull the latest templates & update your current services.json file")
		jsonLinesFlag      = flag.Bool("output-json", false, "Format output in JSON")
		verbosityFlag      = flag.Int("verbose", 2, "Set output verbosity level. Levels: 0 (=silent, only display vulnerabilities), 1 (=default, suppress non-vulnerable results), 2 (=verbose, log all messages)")
	)

	flag.Parse()

	// Validate verbosity level
	if *verbosityFlag < 0 || *verbosityFlag > 2 {
		fmt.Fprintf(os.Stderr, "[-] Error: invalid verbosity level: %d (must be 0, 1, or 2)... Falling back to default verbosity level!\n", *verbosityFlag)
		*verbosityFlag = 2
	}

	config := &Config{
		Target:          *targetFlag,
		ServiceID:       *serviceFlag,
		Delay:           *delayFlag,
		Timeout:         *timeoutFlag,
		MaxRedirects:    *maxRedirectsFlag,
		SkipSSL:         *skipSSL,
		ListServices:    *listServicesFlag || *listTemplatesFlag,
		TemplatesPath:   *templatesPath,
		UpdateTemplates: *updateServicesFlag,
		JSONLines:       *jsonLinesFlag,
		Verbosity:       types.VerbosityLevel(*verbosityFlag),
		RequestHeaders:  parseRequestHeaders(*requestHeadersFlag),
	}

	// Parse "skip-misconfiguration-checks" CLI flag
	switch strings.ToLower(*skipChecksFlag) {
	case "y", "yes", "true", "on", "1", "enable":
		config.SkipChecks = true
	case "", "n", "no", "false", "off", "0", "disable":
		config.SkipChecks = false
	default:
		config.SkipChecks = false
		fmt.Fprintf(os.Stderr, "[-] Warning: Invalid skipChecks flag value supplied: %q\n", *skipChecksFlag)
	}

	// Parse "permutations" CLI flag
	switch strings.ToLower(*permutationsFlag) {
	case "y", "yes", "true", "on", "1", "enable":
		config.EnablePerms = true
	case "", "n", "no", "false", "off", "0", "disable":
		config.EnablePerms = false
	default:
		config.EnablePerms = false
		fmt.Fprintf(os.Stderr, "[-] Warning: Invalid permutations flag value supplied: %q\n", *permutationsFlag)
	}

	// Parse "as-domain" CLI flag
	switch strings.ToLower(*asDomainFlag) {
	case "y", "yes", "true", "on", "1", "enable":
		config.AsDomain = true
	case "", "n", "no", "false", "off", "0", "disable":
		config.AsDomain = false
	default:
		config.AsDomain = false
		fmt.Fprintf(os.Stderr, "[-] Warning: Invalid as-domain flag value supplied: %q\n", *asDomainFlag)
	}

	// Validate that -as-domain and -permutations are not both enabled
	if config.EnablePerms && config.AsDomain {
		return nil, fmt.Errorf("cannot set both -as-domain and -permutations flag simultaneously")
	}

	return config, nil
}

// parseRequestHeaders parses the headers string from the command line
func parseRequestHeaders(rawHeaders string) map[string]string {
	requestHeaders := make(map[string]string)

	// Using a double semicolon as a delimiter between request headers
	headers := strings.SplitSeq(rawHeaders, ";;")

	for header := range headers {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}

		var parts []string
		if strings.Contains(header, ": ") {
			parts = strings.SplitN(header, ": ", 2)
		} else if strings.Contains(header, ":") {
			parts = strings.SplitN(header, ":", 2)
		} else {
			continue
		}

		if len(parts) == 2 {
			requestHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return requestHeaders
}
