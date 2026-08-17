package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/intigriti/misconfig-mapper/internal/types"
	"github.com/intigriti/misconfig-mapper/pkg/client"
	"github.com/intigriti/misconfig-mapper/pkg/templates"
	"golang.org/x/time/rate"
)

// Common domain suffixes for permutation generation
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
	// Retry config
	maxRetries    int
	retryDelay    time.Duration
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
	var limiter *rate.Limiter
	if delay > 0 {
		limiter = rate.NewLimiter(rate.Every(time.Duration(delay)*time.Millisecond), 1)
	}

	return &Scanner{
		Target:        sanitizeTarget(target),
		AsDomain:      asDomain,
		EnablePerms:   enablePerms,
		SkipChecks:    skipChecks,
		Client:        httpClient,
		JSONLines:     jsonLines,
		TerminalWidth: width,
		Verbosity:     verbosity,
		RateLimiter:   limiter,
		maxRetries:    3,
		retryDelay:    1 * time.Second,
	}
}

func sanitizeTarget(target string) string {
	target = strings.ReplaceAll(target, "..", "")
	target = strings.TrimSpace(target)
	if len(target) > 255 {
		target = target[:255]
	}
	return target
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
		if s.EnablePerms {
			possibleTargets = s.generatePermutations(s.Target)
		} else {
			possibleTargets = []string{s.Target}
		}
	}

	// Cap total targets to prevent runaway
	const maxTargets = 5000
	if len(possibleTargets) > maxTargets {
		if s.Verbosity >= types.Verbose {
			fmt.Printf("[!] Warning: Generated %d targets, capping at %d\n", len(possibleTargets), maxTargets)
		}
		possibleTargets = possibleTargets[:maxTargets]
	}

	if s.Verbosity >= types.Verbose {
		fmt.Printf("[+] Checking %v possible target URLs...\n", len(possibleTargets))
	}

	return possibleTargets, nil
}

// loadTargetsFromFile loads target domains from a file
func (s *Scanner) loadTargetsFromFile(filePath string) ([]string, error) {
	filePath = filepath.Clean(filePath)
	// Validate path
	if !isAllowedFilePath(filePath) {
		return nil, fmt.Errorf("file path not allowed: %s", filePath)
	}

	var targets []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Limit line length
	const maxLineLength = 512
	buf := make([]byte, maxLineLength)
	scanner.Buffer(buf, maxLineLength)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, sanitizeTarget(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return targets, nil
}

func isAllowedFilePath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	cwd, _ := os.Getwd()
	return strings.HasPrefix(abs, cwd) || strings.HasPrefix(abs, "/tmp/")
}

// generatePermutations generates domain permutations for a target
func (s *Scanner) generatePermutations(target string) []string {
	var permutations []string

	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		return permutations
	}

	// Always add original target
	permutations = append(permutations, target)

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

		u, err := url.Parse(domain)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		u.Path = path
		targetURL = u.String()
	}

	// Validate URL is not pointing to private IPs
	if u, err := url.Parse(targetURL); err == nil {
		host := u.Hostname()
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if isPrivateIP(ip) {
					return "", fmt.Errorf("blocked: target resolves to private IP %s", ip)
				}
			}
		}
	}

	return targetURL, nil
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
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

				// Perform scan with retry
				var lastErr error
				for attempt := 0; attempt <= s.maxRetries; attempt++ {
					if attempt > 0 {
						time.Sleep(s.retryDelay * time.Duration(attempt)) // Exponential backoff
						if s.Verbosity >= types.Verbose {
							fmt.Printf("[*] Retry %d/%d for %s\n", attempt, s.maxRetries, targetURL)
						}
					}

					s.Client.CheckResponse(&result, &service)

					if result.Exists || result.Vulnerable || attempt == s.maxRetries {
						break
					}
					lastErr = fmt.Errorf("no result")
				}

				if lastErr != nil && s.Verbosity >= types.Verbose {
					fmt.Fprintf(os.Stderr, "[-] Failed after %d retries: %v\n", s.maxRetries, lastErr)
				}

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