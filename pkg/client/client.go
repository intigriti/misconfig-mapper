package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/intigriti/misconfig-mapper/internal/types"
	"github.com/intigriti/misconfig-mapper/pkg/templates"
)

// HTTPClient handles HTTP requests to services
type HTTPClient struct {
	Client     *http.Client
	Timeout    int
	Headers    map[string]string
	SkipChecks bool
	Verbosity  types.VerbosityLevel
}

// Private IP ranges to block (SSRF protection)
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",      // Link-local
		"::1/128",               // IPv6 loopback
		"fe80::/10",             // IPv6 link-local
		"fc00::/7",              // IPv6 ULA
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// NewHTTPClient creates a new HTTP client with SSRF protection
func NewHTTPClient(timeout, maxRedirects int, headers map[string]string, skipChecks bool, verbosity types.VerbosityLevel, skipSSL bool) *HTTPClient {
	// Validate timeout bounds
	if timeout < 1000 {
		timeout = 1000
	}
	if timeout > 30000 {
		timeout = 30000
	}
	// Validate maxRedirects bounds
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	if maxRedirects > 10 {
		maxRedirects = 10
	}

	// Custom dialer with SSRF protection
	dialer := &net.Dialer{
		Timeout:   time.Duration(timeout) * time.Millisecond,
		KeepAlive: 30 * time.Second,
	}

	// Custom DialContext that blocks private IPs
	customDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if isPrivateIP(ip) {
				return nil, fmt.Errorf("blocked: connection to private IP %s", ip)
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects encountered")
			}
			// Also validate redirect target
			if len(via) > 0 {
				redirectURL := req.URL.String()
				if u, err := url.Parse(redirectURL); err == nil {
					if ips, err := net.LookupIP(u.Hostname()); err == nil {
						for _, ip := range ips {
							if isPrivateIP(ip) {
								return fmt.Errorf("blocked: redirect to private IP %s", ip)
							}
						}
					}
				}
			}
			return nil
		},
		Timeout: time.Duration(timeout) * time.Millisecond,
		Transport: &http.Transport{
			DialContext:           customDialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipSSL},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
		},
	}

	return &HTTPClient{
		Client:     client,
		Timeout:    timeout,
		Headers:    headers,
		SkipChecks: skipChecks,
		Verbosity:  verbosity,
	}
}

// CheckResponse checks if a service is vulnerable
func (c *HTTPClient) CheckResponse(result *types.Result, service *types.Service) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Millisecond)
	defer cancel()

	var requestBody io.Reader = nil
	if service.Request.Body != nil {
		requestBody = bytes.NewBuffer([]byte(fmt.Sprintf("%v", service.Request.Body)))
	}

	req, err := http.NewRequestWithContext(ctx, fmt.Sprintf("%v", service.Request.Method), result.URL, requestBody)
	if err != nil {
		if c.Verbosity >= types.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to request %s (%v)\n", result.URL, err)
		} else if c.Verbosity >= types.Normal {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to request %s\n", result.URL)
		}
		result.Vulnerable = false
		return
	}

	// Add headers from service template
	if len(service.Request.Headers) > 0 {
		for _, header := range service.Request.Headers {
			for key, value := range header {
				req.Header.Set(key, value)
			}
		}
	}

	// Add custom headers (these take precedence)
	for key, value := range c.Headers {
		// Sanitize header values
		value = strings.ReplaceAll(value, "\n", "")
		value = strings.ReplaceAll(value, "\r", "")
		req.Header.Set(key, value)
	}

	req.Header.Set("Connection", "close")

	res, err := c.Client.Do(req)
	if err != nil {
		if c.Verbosity >= types.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to read response for %s (%v)\n", result.URL, err)
		} else if c.Verbosity >= types.Normal {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to read response for %s\n", result.URL)
		}
		result.Exists = false
		result.Vulnerable = false
		return
	}
	if res == nil {
		fmt.Fprint(os.Stderr, "[-] Error: HTTP Response is empty")
		return
	}
	defer res.Body.Close()

	// Check if status code matches
	var statusCodeMatched bool
	if statusCodes, ok := service.Response.StatusCode.([]interface{}); ok {
		for _, c := range statusCodes {
			if int(c.(float64)) == res.StatusCode {
				statusCodeMatched = true
				break
			}
		}
	} else {
		if res.StatusCode == int(service.Response.StatusCode.(float64)) {
			statusCodeMatched = true
		}
	}

	// Extract response headers
	var responseHeaders strings.Builder
	for key, values := range res.Header {
		for _, value := range values {
			responseHeaders.WriteString(fmt.Sprintf("%v: %v\n", key, value))
		}
	}

	// Read response body with size limit (10MB)
	limitedReader := io.LimitReader(res.Body, 10*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		if c.Verbosity >= types.Verbose {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to read response body for %s (%v)\n", result.URL, err)
		} else if c.Verbosity >= types.Normal {
			fmt.Fprintf(os.Stderr, "[-] Error: Failed to read response body for %s\n", result.URL)
		}
		return
	}

	// Check exclusion patterns first
	if len(service.Response.ExclusionPatterns) > 0 {
		exclusionExpr := templates.ParseRegex(service.Response.ExclusionPatterns)
		exclusionRe, err := regexp.Compile(exclusionExpr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: Invalid exclusion pattern supplied for service %q (error: %v)!\n",
				service.Metadata.ServiceName, err)
			return
		}

		if exclusionRe.MatchString(string(body)) {
			if c.Verbosity >= types.Verbose {
				fmt.Printf("[-] Info: Excluded %s due to matching exclusion pattern\n", result.URL)
			}
			result.Exists = false
			result.Vulnerable = false
			return
		}
	}

	fullResponse := fmt.Sprintf("%v %v", responseHeaders.String(), string(body))

	if c.SkipChecks {
		expr := templates.ParseRegex(service.Response.DetectionFingerprints)
		re, err := safeRegexCompile(expr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: Invalid detection expression supplied for service %q (error: %v)!\n",
				service.Metadata.ServiceName, err)
			return
		}
		result.Exists = re.MatchString(fullResponse)
		return
	}

	// Check for vulnerability
	expr := templates.ParseRegex(service.Response.Fingerprints)
	re, err := safeRegexCompile(expr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: Invalid expression supplied for service %q (error: %v)!\n",
			service.Metadata.ServiceName, err)
		return
	}

	result.Vulnerable = (re.MatchString(fullResponse) && statusCodeMatched)
}

// safeRegexCompile compiles regex with timeout protection against ReDoS
func safeRegexCompile(pattern string) (*regexp.Regexp, error) {
	// For Go, we can't easily add timeout to regexp.Compile
	// Alternative: use RE2 (github.com/google/re2) or validate pattern complexity
	// For now, add basic complexity check
	if len(pattern) > 1000 {
		return nil, fmt.Errorf("regex pattern too long (>1000 chars)")
	}
	// Check for potentially dangerous patterns
	nesting := 0
	for _, ch := range pattern {
		if ch == '(' {
			nesting++
			if nesting > 10 {
				return nil, fmt.Errorf("regex nesting too deep")
			}
		} else if ch == ')' {
			nesting--
		}
	}
	return regexp.Compile(pattern)
}