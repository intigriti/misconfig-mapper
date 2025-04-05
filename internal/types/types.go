package types

// Service represents a service configuration from the template file
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
		StatusCode            interface{} `json:"statusCode"`
		DetectionFingerprints []string    `json:"detectionFingerprints"`
		Fingerprints          []string    `json:"fingerprints"`
		ExclusionPatterns     []string    `json:"exclusionPatterns,omitempty"`
	} `json:"response"`
	Metadata struct {
		Service           string   `json:"service"`
		ServiceName       string   `json:"serviceName"`
		Description       string   `json:"description"`
		ReproductionSteps []string `json:"reproductionSteps"`
		References        []string `json:"references"`
	} `json:"metadata"`
}

// Result represents a scan result
type Result struct {
	URL        string  `json:"url"`        // Result URL
	Exists     bool    `json:"exists"`     // Used to report back in case the instance exists
	Vulnerable bool    `json:"vulnerable"` // Used to report back in case the instance is vulnerable
	ServiceId  string  `json:"serviceid"`  // Service ID
	Service    Service `json:"service"`    // Service struct
}

// VerbosityLevel represents the level of output detail
type VerbosityLevel int

const (
	// Silent suppresses all non-essential output
	Silent VerbosityLevel = iota
	// Normal shows positive findings and errors
	Normal
	// Verbose shows all messages
	Verbose
)
