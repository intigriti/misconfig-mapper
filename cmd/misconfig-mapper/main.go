package main

import (
	"fmt"
	"os"

	"github.com/intigriti/misconfig-mapper/internal/config"
	"github.com/intigriti/misconfig-mapper/internal/service"
)

func main() {
	// Parse command line flags
	cfg, err := config.ParseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}

	// Create service
	svc := service.NewMisconfigMapper(cfg)

	// Run the service
	if err := svc.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}
