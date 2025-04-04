// Enhanced TCP Port Scanner
// Description: Concurrent port scanner with CLI flags, progress reporting, and JSON output

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult stores individual port scan results
type ScanResult struct {
	Port   int    `json:"port"`
	State  string `json:"state"`
	Banner string `json:"banner,omitempty"`
}

// ScanSummary contains scan metadata and results
type ScanSummary struct {
	Target       string        `json:"target"`
	OpenPorts    int           `json:"open_ports"`
	ScannedPorts int           `json:"scanned_ports"`
	TimeTaken    time.Duration `json:"time_taken_ms"`
	Ports        []ScanResult  `json:"ports,omitempty"`
}

func main() {

	// Custom Target Flag (-target)
	target := flag.String("target", "scanme.nmap.org", "Target hostname or IP to scan")

	// Configurable Port Range (-start-port, -end-port)
	startPort := flag.Int("start-port", 1, "First port in range")
	endPort := flag.Int("end-port", 1024, "Last port in range")

	// Worker Count Flag (-workers)
	workers := flag.Int("workers", 100, "Number of concurrent scanners")

	// Timeout Flag (-timeout)
	timeoutSec := flag.Int("timeout", 5, "Connection timeout in seconds")

	// Banner Grabbing (-banner)
	banner := flag.Bool("banner", false, "Attempt to grab service banners")

	// Multiple Targets (-targets)
	targets := flag.String("targets", "", "Comma-separated target list")

	// JSON Output (-json)
	jsonOut := flag.Bool("json", false, "Output results in JSON format")

	// Specific Ports (-ports)
	portsList := flag.String("ports", "", "Comma-separated port list")

	flag.Parse()

	// Validate port ranges
	if *startPort < 1 || *endPort > 65535 || *startPort > *endPort {
		fmt.Println("Invalid port range")
		os.Exit(1)
	}

	// Process targets
	scanTargets := parseTargets(*target, *targets)

	// Process ports
	portsToScan := parsePorts(*portsList, *startPort, *endPort)

	for _, host := range scanTargets {
		results := scanHost(host, portsToScan, *workers, time.Duration(*timeoutSec)*time.Second, *banner)
		generateOutput(results, *jsonOut)
	}
}

/* Core Scanning Functions */
func scanHost(host string, ports []int, workers int, timeout time.Duration, grabBanner bool) ScanSummary {
	start := time.Now()
	tasks := make(chan int, workers)
	results := make(chan ScanResult, len(ports))
	progress := make(chan int, workers)

	var wg sync.WaitGroup
	var openPorts []ScanResult

	// Start worker pool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range tasks {
				res := scanPort(host, port, timeout, grabBanner)
				results <- res
				progress <- port
			}
		}()
	}

	// Feed ports to workers
	go func() {
		for _, port := range ports {
			tasks <- port
		}
		close(tasks)
	}()

	// Progress monitor
	go func() {
		for range progress {
			fmt.Printf("\rScanning: %d/%d ports", len(results), len(ports))
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
		close(progress)
	}()

	// Process results
	for res := range results {
		if res.State == "open" {
			openPorts = append(openPorts, res)
		}
	}

	return ScanSummary{
		Target:       host,
		OpenPorts:    len(openPorts),
		ScannedPorts: len(ports),
		TimeTaken:    time.Since(start),
		Ports:        openPorts,
	}
}

func scanPort(host string, port int, timeout time.Duration, grabBanner bool) ScanResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)

	result := ScanResult{
		Port:  port,
		State: "closed",
	}

	if err != nil {
		return result
	}
	defer conn.Close()

	result.State = "open"

	if grabBanner {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			result.Banner = strings.TrimSpace(string(buf[:n]))
		}
	}

	return result
}

/* Helper Functions */
func parseTargets(defaultTarget, targetList string) []string {
	if targetList == "" {
		return []string{defaultTarget}
	}
	return strings.Split(targetList, ",")
}

func parsePorts(portList string, start, end int) []int {
	if portList != "" {
		var ports []int
		for _, p := range strings.Split(portList, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
		return ports
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

func generateOutput(summary ScanSummary, jsonFormat bool) {
	if jsonFormat {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Println("Error generating JSON:", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Printf("\n\n=== Scan Results for %s ===\n", summary.Target)
	fmt.Printf("Scanned ports: %d\n", summary.ScannedPorts)
	fmt.Printf("Open ports: %d\n", summary.OpenPorts)
	fmt.Printf("Scan duration: %v\n\n", summary.TimeTaken.Round(time.Millisecond))

	if len(summary.Ports) > 0 {
		fmt.Println("OPEN PORTS:")
		for _, port := range summary.Ports {
			output := fmt.Sprintf("%d/tcp %s", port.Port, port.State)
			if port.Banner != "" {
				output += fmt.Sprintf(" | %s", port.Banner)
			}
			fmt.Println(output)
		}
	}
}
