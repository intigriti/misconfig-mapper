package templates

import (
	"context"
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
)

// Manager handles loading and updating service templates
type Manager struct {
	TemplatesDir string
	ServicesPath string
	Verbosity    types.VerbosityLevel
}

// NewManager creates a new template manager
func NewManager(templatesDir string, verbosity types.VerbosityLevel) *Manager {
	return &Manager{
		TemplatesDir: templatesDir,
		ServicesPath: filepath.Join(templatesDir, "services.json"),
		Verbosity:    verbosity,
	}
}

// LoadTemplates loads service templates from the services.json file
func (m *Manager) LoadTemplates() ([]types.Service, error) {
	var services []types.Service

	file, err := os.Open(m.ServicesPath)
	if err != nil {
		return services, fmt.Errorf("failed opening file '%s': %w", m.ServicesPath, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&services); err != nil {
		return services, fmt.Errorf("failed decoding JSON file: %w", err)
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

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("empty response received")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var s *os.File
	if update {
		// Update existing file
		s, err = os.OpenFile(m.ServicesPath, os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open services file: %w", err)
		}
		defer s.Close()
	} else {
		// Create new file
		if m.Verbosity >= types.Normal {
			fmt.Println("[+] Info: Creating templates directory...")
		}

		// Create templates directory if it doesn't exist
		if err := os.MkdirAll(m.TemplatesDir, 0755); err != nil {
			return fmt.Errorf("failed to create templates directory: %w", err)
		}

		// Create services.json file
		s, err = os.Create(m.ServicesPath)
		if err != nil {
			return fmt.Errorf("failed to create services file: %w", err)
		}
		defer s.Close()
	}

	// Write the content to file
	if _, err := s.Write(body); err != nil {
		return fmt.Errorf("failed to write services file: %w", err)
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
				break // Found a match, move to the next service
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

	// Print the table header
	fmt.Println("| ID | Service")
	fmt.Printf("|----|--%s\n", strings.Repeat("-", width-6))

	// Print each row of the table
	for _, service := range services {
		fmt.Printf("| %-2d | %-7s\n", service.ID, service.Metadata.ServiceName)
	}
}

// IsFile checks if a path is a file
func IsFile(path string) bool {
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
	return x
}
