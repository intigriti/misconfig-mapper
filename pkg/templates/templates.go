package templates

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/intigriti/misconfig-mapper/internal/types"
)

const (
	templatesURL = "https://raw.githubusercontent.com/intigriti/misconfig-mapper/main/templates/services.json"
	maxTemplateSize = 5 * 1024 * 1024 // 5MB max
)

// Manager handles loading and updating service templates
type Manager struct {
	TemplatesDir string
	ServicesPath string
	Verbosity    types.VerbosityLevel
}

// ServiceSchema defines the expected structure for validation
type ServiceSchema struct {
	ID       int64  `json:"id"`
	Request  RequestSchema  `json:"request"`
	Response ResponseSchema `json:"response"`
	Metadata MetadataSchema `json:"metadata"`
}

type RequestSchema struct {
	Method  string              `json:"method"`
	BaseURL string              `json:"baseURL"`
	Path    []string            `json:"path"`
	Headers []map[string]string `json:"headers"`
	Body    interface{}         `json:"body"`
}

type ResponseSchema struct {
	StatusCode            interface{} `json:"statusCode"`
	DetectionFingerprints []string    `json:"detectionFingerprints"`
	Fingerprints          []string    `json:"fingerprints"`
	ExclusionPatterns     []string    `json:"exclusionPatterns,omitempty"`
}

type MetadataSchema struct {
	Service           string   `json:"service"`
	ServiceName       string   `json:"serviceName"`
	Description       string   `json:"description"`
	ReproductionSteps []string `json:"reproductionSteps"`
	References        []string `json:"references"`
}

// NewManager creates a new template manager
func NewManager(templatesDir string, verbosity types.VerbosityLevel) *Manager {
	// Sanitize path
	templatesDir = filepath.Clean(templatesDir)
	// Ensure it's within allowed directories
	if !isAllowedPath(templatesDir) {
		templatesDir = "./templates"
	}
	return &Manager{
		TemplatesDir: templatesDir,
		ServicesPath: filepath.Join(templatesDir, "services.json"),
		Verbosity:    verbosity,
	}
}

func isAllowedPath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Allow only under current working directory or /tmp
	cwd, _ := os.Getwd()
	return strings.HasPrefix(abs, cwd) || strings.HasPrefix(abs, "/tmp/")
}

// validateService validates a single service struct
func validateService(s ServiceSchema) error {
	// Required fields
	if s.ID < 0 {
		return fmt.Errorf("invalid service ID: %d", s.ID)
	}
	if s.Request.Method == "" {
		return fmt.Errorf("missing request method")
	}
	if s.Request.BaseURL == "" {
		return fmt.Errorf("missing baseURL")
	}
	if len(s.Request.Path) == 0 {
		return fmt.Errorf("missing request path")
	}
	// Validate BaseURL format - either baseURL or path must contain {TARGET}
	if !strings.Contains(s.Request.BaseURL, "{TARGET}") {
		hasTargetInPath := false
		for _, p := range s.Request.Path {
			if strings.Contains(p, "{TARGET}") {
				hasTargetInPath = true
				break
			}
		}
		if !hasTargetInPath {
			return fmt.Errorf("baseURL or path must contain {TARGET} placeholder")
		}
	}
	// Validate HTTP method
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	if !validMethods[s.Request.Method] {
		return fmt.Errorf("invalid HTTP method: %s", s.Request.Method)
	}
	// Validate response fields
	if len(s.Response.Fingerprints) == 0 && len(s.Response.DetectionFingerprints) == 0 {
		return fmt.Errorf("missing fingerprints")
	}
	// Validate regex patterns aren't too complex
	for _, fp := range s.Response.Fingerprints {
		if len(fp) > 500 {
			return fmt.Errorf("fingerprint pattern too long")
		}
	}
	for _, fp := range s.Response.DetectionFingerprints {
		if len(fp) > 500 {
			return fmt.Errorf("detection fingerprint pattern too long")
		}
	}
	for _, fp := range s.Response.ExclusionPatterns {
		if len(fp) > 500 {
			return fmt.Errorf("exclusion pattern too long")
		}
	}
	return nil
}

// LoadTemplates loads service templates from the services.json file
func (m *Manager) LoadTemplates() ([]types.Service, error) {
	var services []types.Service

	// Check file size before opening
	info, err := os.Stat(m.ServicesPath)
	if err != nil {
		return services, fmt.Errorf("failed to stat file '%s': %w", m.ServicesPath, err)
	}
	if info.Size() > maxTemplateSize {
		return services, fmt.Errorf("template file too large (%d bytes, max %d)", info.Size(), maxTemplateSize)
	}

	file, err := os.Open(m.ServicesPath)
	if err != nil {
		return services, fmt.Errorf("failed opening file '%s': %w", m.ServicesPath, err)
	}
	defer file.Close()

	// Use limited reader
	limitedReader := io.LimitReader(file, maxTemplateSize)
	decoder := json.NewDecoder(limitedReader)
	decoder.DisallowUnknownFields() // Strict parsing

	if err := decoder.Decode(&services); err != nil {
		return services, fmt.Errorf("failed decoding JSON file: %w", err)
	}

	// Validate each service
	for i, svc := range services {
		// Convert to schema for validation
		schema := ServiceSchema{
			ID:       svc.ID,
			Request:  RequestSchema{Method: svc.Request.Method, BaseURL: svc.Request.BaseURL, Path: svc.Request.Path, Headers: svc.Request.Headers, Body: svc.Request.Body},
			Response: ResponseSchema{StatusCode: svc.Response.StatusCode, DetectionFingerprints: svc.Response.DetectionFingerprints, Fingerprints: svc.Response.Fingerprints, ExclusionPatterns: svc.Response.ExclusionPatterns},
			Metadata: MetadataSchema{Service: svc.Metadata.Service, ServiceName: svc.Metadata.ServiceName, Description: svc.Metadata.Description, ReproductionSteps: svc.Metadata.ReproductionSteps, References: svc.Metadata.References},
		}
		if err := validateService(schema); err != nil {
			return services, fmt.Errorf("service[%d] validation failed: %w", i, err)
		}
	}

	return services, nil
}

// UpdateTemplates updates the templates from the GitHub repository
func (m *Manager) UpdateTemplates(update bool) error {
	if m.Verbosity >= types.Normal {
		fmt.Printf("[+] Info: Pulling latest services and saving in %v\n", m.ServicesPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", templatesURL, nil)
	if err != nil {
		return err
	}
	// Pin TLS config for security
	req.Header.Set("User-Agent", "misconfig-mapper/1.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("empty response received")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, res.Status)
	}

	// Read with size limit
	limitedReader := io.LimitReader(res.Body, maxTemplateSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	// Validate before writing
	var testServices []types.Service
	if err := json.Unmarshal(body, &testServices); err != nil {
		return fmt.Errorf("downloaded template invalid JSON: %w", err)
	}
	// Validate each
	for i, svc := range testServices {
		schema := ServiceSchema{
			ID:       svc.ID,
			Request:  RequestSchema{Method: svc.Request.Method, BaseURL: svc.Request.BaseURL, Path: svc.Request.Path, Headers: svc.Request.Headers, Body: svc.Request.Body},
			Response: ResponseSchema{StatusCode: svc.Response.StatusCode, DetectionFingerprints: svc.Response.DetectionFingerprints, Fingerprints: svc.Response.Fingerprints, ExclusionPatterns: svc.Response.ExclusionPatterns},
			Metadata: MetadataSchema{Service: svc.Metadata.Service, ServiceName: svc.Metadata.ServiceName, Description: svc.Metadata.Description, ReproductionSteps: svc.Metadata.ReproductionSteps, References: svc.Metadata.References},
		}
		if err := validateService(schema); err != nil {
			return fmt.Errorf("downloaded service[%d] validation failed: %w", i, err)
		}
	}

	// Ensure directory exists with safe permissions
	if err := os.MkdirAll(m.TemplatesDir, 0750); err != nil {
		return fmt.Errorf("failed to create templates directory: %w", err)
	}

	// Write atomically
	tmpPath := m.ServicesPath + ".tmp"
	if err := os.WriteFile(tmpPath, body, 0640); err != nil {
		return fmt.Errorf("failed to write temp services file: %w", err)
	}
	if err := os.Rename(tmpPath, m.ServicesPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename services file: %w", err)
	}

	if m.Verbosity >= types.Normal {
		fmt.Println("[+] Info: Successfully pulled the latest templates!")
	}

	return nil
}

// GetService returns services by ID or name
func (m *Manager) GetService(ids string, services []types.Service) []types.Service {
	if ids == "*" {
		return services
	}

	var result []types.Service
	parsed := strings.Split(ids, ",")

	for _, service := range services {
		for _, id := range parsed {
			id = strings.TrimSpace(id)
			if (fmt.Sprintf("%v", service.ID) == id) ||
				(strings.EqualFold(fmt.Sprintf("%v", service.Metadata.Service), id)) {
				result = append(result, service)
				break
			}
		}
	}

	return result
}

// PrintServices prints the list of available services
func (m *Manager) PrintServices(services []types.Service, width int) {
	if m.Verbosity >= types.Verbose {
		fmt.Printf("[+] %v Service(s) loaded!\n", len(services))
	}

	fmt.Println("| ID | Service")
	fmt.Printf("|----|--%s\n", strings.Repeat("-", width-6))

	for _, service := range services {
		fmt.Printf("| %-2d | %-7s\n", service.ID, service.Metadata.ServiceName)
	}
}

// IsFile checks if a path is a file
func IsFile(path string) bool {
	path = filepath.Clean(path)
	if filepath.Ext(path) == "" {
		return false
	}

	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// ParseRegex transforms an array of patterns into a regex string
func ParseRegex(v []string) string {
	x := strings.Join(v, "|")             // Split array entries with regex alternation
	x = strings.Replace(x, ".", `\.`, -1) // Escape dot characters
	// Limit length
	if len(x) > 2000 {
		x = x[:2000]
	}
	return x
}