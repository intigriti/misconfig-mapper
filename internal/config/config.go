package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		asDomainFlag       = flag.Bool("as-domain", false, "Treat the target as if its a domain. This flag cannot be used with -permutations.")
		serviceFlag        = flag.String("service", "0", "Specify the service ID you'd like to check for. For example, \"0\" for Atlassian Jira Open Signups. Use comma seperated values for multiple (i.e. \"0,1\" for two services). Use \"*\" to check for all services.")
		skipChecksFlag     = flag.Bool("skip-misconfiguration-checks", false, "Only check for existing instances (and skip checks for potential security misconfigurations).")
		permutationsFlag   = flag.Bool("permutations", true, "Enable permutations and look for several other keywords of your target. This flag cannot be used with -as-domain.")
		requestHeadersFlag = flag.String("headers", "", "Specify request headers to send with requests (separate each header with a double semi-colon: \"User-Agent: xyz;; Cookie: xyz...;;\" )")
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

	// Validate and sanitize templates path
	tmplPath := filepath.Clean(*templatesPath)
	if !isAllowedPath(tmplPath) {
		tmplPath = "./templates"
		fmt.Fprintf(os.Stderr, "[-] Warning: templates path not allowed, using default ./templates\n")
	}

	// Validate delay bounds
	delay := *delayFlag
	if delay < 0 {
		delay = 0
	}
	if delay > 60000 {
		delay = 60000
		fmt.Fprintf(os.Stderr, "[-] Warning: delay capped at 60000ms\n")
	}

	// Validate timeout bounds
	timeout := *timeoutFlag
	if timeout < 1000 {
		timeout = 1000
		fmt.Fprintf(os.Stderr, "[-] Warning: timeout minimum 1000ms\n")
	}
	if timeout > 30000 {
		timeout = 30000
		fmt.Fprintf(os.Stderr, "[-] Warning: timeout maximum 30000ms\n")
	}

	// Validate maxRedirects bounds
	maxRedirects := *maxRedirectsFlag
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	if maxRedirects > 10 {
		maxRedirects = 10
		fmt.Fprintf(os.Stderr, "[-] Warning: max-redirects capped at 10\n")
	}

	config := &Config{
		Target:          sanitizeTarget(*targetFlag),
		ServiceID:       *serviceFlag,
		Delay:           delay,
		Timeout:         timeout,
		MaxRedirects:    maxRedirects,
		SkipSSL:         *skipSSL,
		ListServices:    *listServicesFlag || *listTemplatesFlag,
		TemplatesPath:   tmplPath,
		UpdateTemplates: *updateServicesFlag,
		JSONLines:       *jsonLinesFlag,
		Verbosity:       types.VerbosityLevel(*verbosityFlag),
		RequestHeaders:  parseRequestHeaders(*requestHeadersFlag),
	}

	// Parse boolean flags
	config.SkipChecks = *skipChecksFlag
	config.EnablePerms = *permutationsFlag
	config.AsDomain = *asDomainFlag

	// Validate that -as-domain and -permutations are not both enabled
	if config.EnablePerms && config.AsDomain {
		return nil, fmt.Errorf("cannot set both -as-domain and -permutations flag simultaneously")
	}

	// Validate target is provided when needed
	if config.Target == "" && !config.ListServices && !config.UpdateTemplates {
		return nil, fmt.Errorf("no target specified, use -target flag")
	}

	// Limit permutation count - check raw target length before sanitization
	if config.EnablePerms {
		// Rough estimate: target × suffixes (30) × connectors (3) ≈ 90 per target
		if len(*targetFlag) > 100 {
			return nil, fmt.Errorf("target too long (max 100 chars)")
		}
	}

	return config, nil
}

func isAllowedPath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	cwd, _ := os.Getwd()
	return strings.HasPrefix(abs, cwd) || strings.HasPrefix(abs, "/tmp/")
}

func sanitizeTarget(target string) string {
	// Remove any path traversal attempts
	target = strings.ReplaceAll(target, "..", "")
	target = strings.TrimSpace(target)
	// Limit length
	if len(target) > 255 {
		target = target[:255]
	}
	return target
}

// parseRequestHeaders parses the headers string from the command line
func parseRequestHeaders(rawHeaders string) map[string]string {
	requestHeaders := make(map[string]string)

	headers := strings.Split(rawHeaders, ";;")

	for _, header := range headers {
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
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Sanitize: remove newlines, limit length
			key = strings.ReplaceAll(key, "\n", "")
			key = strings.ReplaceAll(key, "\r", "")
			value = strings.ReplaceAll(value, "\n", "")
			value = strings.ReplaceAll(value, "\r", "")
			if len(key) > 100 || len(value) > 1000 {
				continue
			}
			requestHeaders[key] = value
		}
	}

	return requestHeaders
}