package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/mcp-hub-corp/mcp-cage/internal/sandbox"
)

func runDoctor() error {
	info := sandbox.Diagnose()

	if doctorFlags.jsonOutput {
		return outputDoctorJSON(&info)
	}
	return outputDoctorText(&info)
}

func outputDoctorText(info *sandbox.DiagnosticInfo) error {
	// Header
	fmt.Printf("MCP Client Diagnostics\n")
	fmt.Printf("======================\n\n")

	// System Information
	fmt.Printf("System Information:\n")
	fmt.Printf("  OS:          %s\n", info.OS)
	fmt.Printf("  Arch:        %s\n", info.Arch)
	fmt.Printf("  Go Version:  %s\n", runtime.Version())
	if info.RunningAsRoot {
		fmt.Printf("  Running as:  root/admin\n")
	} else {
		fmt.Printf("  Running as:  non-root user\n")
	}
	fmt.Println()

	// Capabilities
	fmt.Printf("Sandbox Capabilities:\n")
	caps := info.Capabilities

	printCapability("CPU Limiting", caps.CPULimit)
	printCapability("Memory Limiting", caps.MemoryLimit)
	printCapability("PID Limiting", caps.PIDLimit)
	printCapability("File Descriptor Limiting", caps.FDLimit)
	printCapability("Network Isolation", caps.NetworkIsolation)
	printCapability("Filesystem Isolation", caps.FilesystemIsolation)
	printCapability("Cgroups", caps.Cgroups)
	printCapability("Namespaces", caps.Namespaces)
	printCapability("Seccomp", caps.SupportsSeccomp)
	printCapability("Landlock", caps.SupportsLandlock)
	printCapability("sandbox-exec (macOS)", caps.SupportsSandboxExec)
	printCapability("Process Isolation (Job Objects)", caps.ProcessIsolation)
	fmt.Println()

	// Platform-specific information
	if info.OS == "linux" {
		fmt.Printf("Linux-Specific Information:\n")
		fmt.Printf("  Cgroups Version: %s\n", info.CgroupsVersion)
		fmt.Println()
	}

	// Warnings
	if len(info.Warnings) > 0 {
		fmt.Printf("Warnings:\n")
		for _, w := range info.Warnings {
			fmt.Printf("  [!] %s\n", w)
		}
		fmt.Println()
	}

	// Recommendations
	if len(info.Recommendations) > 0 {
		fmt.Printf("Recommendations:\n")
		for _, r := range info.Recommendations {
			fmt.Printf("  [*] %s\n", r)
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("Summary:\n")
	enabledCount := countEnabledCapabilities(caps)
	totalCapabilities := 12 // CPU, Memory, PID, FD, Network, FS, Cgroups, NS, Seccomp, Landlock, SandboxExec, ProcessIsolation
	fmt.Printf("  %d/%d features available\n", enabledCount, totalCapabilities)

	return nil
}

func outputDoctorJSON(info *sandbox.DiagnosticInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}

func printCapability(name string, enabled bool) {
	status := "✗"
	if enabled {
		status = "✓"
	}
	fmt.Printf("  [%s] %s\n", status, name)
}

func countEnabledCapabilities(caps sandbox.Capabilities) int {
	count := 0
	if caps.CPULimit {
		count++
	}
	if caps.MemoryLimit {
		count++
	}
	if caps.PIDLimit {
		count++
	}
	if caps.FDLimit {
		count++
	}
	if caps.NetworkIsolation {
		count++
	}
	if caps.FilesystemIsolation {
		count++
	}
	if caps.Cgroups {
		count++
	}
	if caps.Namespaces {
		count++
	}
	if caps.SupportsSeccomp {
		count++
	}
	if caps.SupportsLandlock {
		count++
	}
	if caps.SupportsSandboxExec {
		count++
	}
	if caps.ProcessIsolation {
		count++
	}
	return count
}
