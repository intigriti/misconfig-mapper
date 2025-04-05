package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/intigriti/misconfig-mapper/internal/types"
	"github.com/intigriti/misconfig-mapper/pkg/client"
	"github.com/intigriti/misconfig-mapper/pkg/templates"
	"golang.org/x/time/rate"
)

// Common domain suffixes for permutation generation
// TODO: Add more suffixes
var suffixes = []string{
	"com", "net", "org", "io", "fr", "ltd", "app", "prod", "internal",
	"dev", "development", "devops", "logs", "logging", "admin", "log",
	"stage", "staging", "stg", "production", "dev-only", "cicd",
	"employee-only", "testing", "secret", "kibana", "employees",
	"partners", "sso", "saml", "tickets", "issues", "oauth2",
}

// Scanner manages the scanning process
type Scanner struct {
	Target           string
	AsDomain         bool
	EnablePerms      bool
	SkipChecks       bool
	Client           *client.HTTPClient
	JSONLines        bool
	TerminalWidth    int
	Verbosity        types.VerbosityLevel
	RateLimiter      *rate.Limiter
	SelectedServices []types.Service
}

// NewScanner creates a new scanner
func NewScanner(
	target string,
	asDomain bool,
	enablePerms bool,
	skipChecks bool,
	httpClient *client.HTTPClient,
	jsonLines bool,
	width int,
	verbosity types.VerbosityLevel,
	delay int,
) *Scanner {
	// Create a rate limiter if delay is specified
	var limiter *rate.Limiter
	if delay > 0 {
		limiter = rate.NewLimiter(rate.Every(time.Duration(delay)*time.Millisecond), 1)
	}

	return &Scanner{
		Target:        target,
		AsDomain:      asDomain,
		EnablePerms:   enablePerms,
		SkipChecks:    skipChecks,
		Client:        httpClient,
		JSONLines:     jsonLines,
		TerminalWidth: width,
		Verbosity:     verbosity,
		RateLimiter:   limiter,
	}
}

// SetSelectedServices sets the services to scan
func (s *Scanner) SetSelectedServices(services []types.Service) {
	s.SelectedServices = services
}

// GenerateTargets generates potential target domains based on the input
func (s *Scanner) GenerateTargets() ([]string, error) {
	var possibleTargets []string

	// Check if target is a file
	if templates.IsFile(s.Target) {
		// Load targets from file
		targets, err := s.loadTargetsFromFile(s.Target)
		if err != nil {
			return nil, err
		}

		if s.EnablePerms {
			for _, target := range targets {
				possibleTargets = append(possibleTargets, s.generatePermutations(target)...)
			}
		} else {
			possibleTargets = targets
		}
	} else {
		// Generate targets from a single target
		if s.EnablePerms {
			possibleTargets = s.generatePermutations(s.Target)
		} else {
			possibleTargets = []string{s.Target}
		}
	}

	if s.Verbosity >= types.Verbose {
		fmt.Printf("[+] Checking %v possible target URLs...\n", len(possibleTargets))
	}

	return possibleTargets, nil
}

// loadTargetsFromFile loads target domains from a file
func (s *Scanner) loadTargetsFromFile(filePath string) ([]string, error) {
	var targets []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return targets, nil
}

// generatePermutations generates domain permutations for a target
func (s *Scanner) generatePermutations(target string) []string {
	var permutations []string

	// Always add original target
	permutations = append(permutations, target)

	// Clean target
	target = strings.TrimSpace(strings.ToLower(target))

	// Generate domain combinations
	for _, suffix := range suffixes {
		for _, connector := range []string{".", "-", ""} {
			domain := fmt.Sprintf("%s%s%s", target, connector, suffix)
			permutations = append(permutations, domain)
		}
	}

	return permutations
}

// craftTargetURL creates the full URL to test
func (s *Scanner) craftTargetURL(baseURL, path, domain string) (string, error) {
	var targetURL string

	if s.EnablePerms || !s.AsDomain {
		// Normalize domain (remove protocol)
		domain = regexp.MustCompile(`^https?://`).ReplaceAllString(domain, "")
		// Use the template's base URL with the target as a parameter
		targetURL = strings.Replace(fmt.Sprintf("%v%v", baseURL, path), "{TARGET}", domain, -1)
	} else {
		// Use the target as the base URL
		if !strings.HasPrefix(domain, "http") {
			domain = fmt.Sprintf("https://%v", domain)
		}

		// Parse and construct the URL
		u, err := url.Parse(domain)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		u.Path = path
		targetURL = u.String()
	}

	return targetURL, nil
}

// ScanTargets performs the scan operation across all services and targets
func (s *Scanner) ScanTargets() error {
	targets, err := s.GenerateTargets()
	if err != nil {
		return fmt.Errorf("failed to generate targets: %w", err)
	}

	for _, service := range s.SelectedServices {
		for _, target := range targets {
			for _, path := range service.Request.Path {
				// Apply rate limiting if configured
				if s.RateLimiter != nil {
					_ = s.RateLimiter.Wait(context.Background())
				}

				// Skip unnecessary paths for detection-only
				if s.SkipChecks {
					path = "/"
				}

				// Craft target URL
				targetURL, err := s.craftTargetURL(service.Request.BaseURL, path, target)
				if err != nil {
					if s.Verbosity >= types.Verbose {
						fmt.Fprintf(os.Stderr, "[-] Error: Failed to craft target URL %q: %v\n", target, err)
					} else if s.Verbosity >= types.Normal {
						fmt.Fprintf(os.Stderr, "[-] Error: Failed to craft target URL %q\n", target)
					}
					continue
				}

				// Validate URL
				parsedURL, err := url.Parse(targetURL)
				if err != nil {
					if s.Verbosity >= types.Verbose {
						fmt.Fprintf(os.Stderr, "[-] Error: Invalid target URL %q: %v\n", targetURL, err)
					} else if s.Verbosity >= types.Normal {
						fmt.Fprintf(os.Stderr, "[-] Error: Invalid target URL %q\n", targetURL)
					}
					continue
				}

				// Prepare result
				result := types.Result{
					URL:        parsedURL.String(),
					ServiceId:  fmt.Sprintf("%d", service.ID),
					Service:    service,
					Exists:     false,
					Vulnerable: false,
				}

				// Perform scan
				s.Client.CheckResponse(&result, &service)

				// Handle result
				if result.Exists || result.Vulnerable {
					s.handleResult(&result)
					break // Found a result for this service, move to the next service
				} else if s.Verbosity >= types.Verbose {
					if s.SkipChecks {
						fmt.Printf("[-] No %s instance found (%s)\n",
							result.Service.Metadata.ServiceName, result.URL)
					} else {
						fmt.Printf("[-] No vulnerable %s instance found (%s)\n",
							result.Service.Metadata.ServiceName, result.URL)
					}
				}
			}
		}
	}

	return nil
}

// handleResult processes and displays a scan result
func (s *Scanner) handleResult(result *types.Result) {
	// Output as JSON if requested
	if s.JSONLines {
		d, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal result %v", err)
			return
		}
		fmt.Println(string(d))
		return
	}

	// Output in human-readable format
	fmt.Println(strings.Repeat("-", s.TerminalWidth))

	if s.SkipChecks {
		fmt.Printf("[+] 1 %s detected!\n", result.Service.Metadata.ServiceName)
	} else {
		fmt.Println("[+] 1 Vulnerable result found!")
	}

	fmt.Printf("URL: %s\n", result.URL)
	fmt.Printf("Service: %s\n", result.Service.Metadata.ServiceName)
	fmt.Printf("Description: %s\n", result.Service.Metadata.Description)

	if !s.SkipChecks && len(result.Service.Metadata.ReproductionSteps) > 0 {
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

	fmt.Println(strings.Repeat("-", s.TerminalWidth))
}
