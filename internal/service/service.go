package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/intigriti/misconfig-mapper/internal/config"
	"github.com/intigriti/misconfig-mapper/internal/scanner"
	"github.com/intigriti/misconfig-mapper/internal/types"
	"github.com/intigriti/misconfig-mapper/pkg/client"
	"github.com/intigriti/misconfig-mapper/pkg/templates"
	"golang.org/x/term"
)

// MisconfigMapper represents the application service
type MisconfigMapper struct {
	Config    *config.Config
	Templates *templates.Manager
}

// NewMisconfigMapper creates a new MisconfigMapper instance
func NewMisconfigMapper(cfg *config.Config) *MisconfigMapper {
	return &MisconfigMapper{
		Config:    cfg,
		Templates: templates.NewManager(cfg.TemplatesPath, cfg.Verbosity),
	}
}

// GetTerminalWidth returns the width of the terminal
func (m *MisconfigMapper) GetTerminalWidth() int {
	fd := int(os.Stdout.Fd())
	width, _, _ := term.GetSize(fd)
	if width <= 0 {
		width = 80 // Default width
	}
	return width
}

// Run executes the main application logic
func (m *MisconfigMapper) Run() error {
	termWidth := m.GetTerminalWidth()

	// Update templates if requested
	if m.Config.UpdateTemplates {
		serviceFilePath := filepath.Join(m.Config.TemplatesPath, "services.json")
		fileExists := templates.IsFile(serviceFilePath)
		if err := m.Templates.UpdateTemplates(fileExists); err != nil {
			return fmt.Errorf("failed to update templates: %w", err)
		}
		return nil
	}

	// Load templates
	services, err := m.Templates.LoadTemplates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: Failed to load services!\n")

		// Try to update templates
		if err := m.Templates.UpdateTemplates(false); err != nil {
			return fmt.Errorf("failed to pull latest services: %w", err)
		}

		// Reload templates
		services, err = m.Templates.LoadTemplates()
		if err != nil {
			return fmt.Errorf("failed to load services: %w", err)
		}
	}

	// List services if requested
	if m.Config.ListServices {
		m.Templates.PrintServices(services, termWidth)
		return nil
	}

	// Check that a target is specified
	if m.Config.Target == "" {
		return fmt.Errorf("no target specified, use -target flag to specify a target")
	}

	// Get selected services
	selectedServices := m.Templates.GetService(m.Config.ServiceID, services)
	if len(selectedServices) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Error: Service ID %q does not match any integrated service!\n\nAvailable Services:\n",
			m.Config.ServiceID)
		m.Templates.PrintServices(services, termWidth)
		return fmt.Errorf("no services selected")
	}

	if m.Config.Verbosity >= types.Verbose {
		fmt.Printf("[+] %v Services selected!\n", len(selectedServices))
	}

	// Create HTTP client
	httpClient := client.NewHTTPClient(
		m.Config.Timeout,
		m.Config.MaxRedirects,
		m.Config.RequestHeaders,
		m.Config.SkipChecks,
		m.Config.Verbosity,
		m.Config.SkipSSL,
	)

	// Create scanner
	scn := scanner.NewScanner(
		m.Config.Target,
		m.Config.AsDomain,
		m.Config.EnablePerms,
		m.Config.SkipChecks,
		httpClient,
		m.Config.JSONLines,
		termWidth,
		m.Config.Verbosity,
		m.Config.Delay,
	)
	scn.SetSelectedServices(selectedServices)

	// Run the scan
	return scn.ScanTargets()
}
