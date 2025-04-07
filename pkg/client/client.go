package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
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

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(timeout, maxRedirects int, headers map[string]string, skipChecks bool, verbosity types.VerbosityLevel, skipSSL bool) *HTTPClient {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow max amount of specified redirects
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects encountered")
			}
			return nil
		},
		Timeout: time.Duration(timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipSSL,
			},
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
		// Multiple status codes
		for _, c := range statusCodes {
			if int(c.(float64)) == res.StatusCode {
				statusCodeMatched = true
				break
			}
		}
	} else {
		// Single status code
		if res.StatusCode == int(service.Response.StatusCode.(float64)) {
			statusCodeMatched = true
		}
	}

	// Extract response headers
	var responseHeaders string
	for key, values := range res.Header {
		for _, value := range values {
			responseHeaders += fmt.Sprintf("%v: %v\n", key, value)
		}
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
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

		// If any exclusion pattern matches, consider this a false positive
		if exclusionRe.MatchString(string(body)) {
			if c.Verbosity >= types.Verbose {
				fmt.Printf("[-] Info: Excluded %s due to matching exclusion pattern\n", result.URL)
			}
			result.Exists = false
			result.Vulnerable = false
			return
		}
	}

	fullResponse := fmt.Sprintf("%v %v", responseHeaders, string(body))

	if c.SkipChecks {
		// Only check for detection
		expr := templates.ParseRegex(service.Response.DetectionFingerprints)
		re, err := regexp.Compile(expr)
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
	re, err := regexp.Compile(expr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: Invalid expression supplied for service %q (error: %v)!\n",
			service.Metadata.ServiceName, err)
		return
	}

	result.Vulnerable = (re.MatchString(fullResponse) && statusCodeMatched)
}
