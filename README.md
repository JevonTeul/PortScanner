# Enhanced TCP Port Scanner

## Overview
This is an enhanced TCP port scanner written in Go. It supports concurrent scanning, configurable port ranges, multiple targets, banner grabbing, and outputs results in both plain text and JSON formats. The tool is designed to be flexible and user-friendly, making it ideal for both quick scans and integration into larger automation scripts.

## Features
- **Custom Target(s):** Use the `-target` flag to specify a single target or the `-targets` flag for a comma-separated list of targets.
- **Configurable Port Range:** Set the starting and ending ports using the `-start-port` and `-end-port` flags.
- **Adjustable Worker Count:** Control the number of concurrent scanning workers with the `-workers` flag.
- **Timeout Option:** Define a connection timeout (in seconds) with the `-timeout` flag.
- **Banner Grabbing:** Enable banner grabbing on open ports with the `-banner` flag.
- **JSON Output:** Output the scan results in JSON format using the `-json` flag for easy integration with other tools.
- **Specific Ports:** Scan a specific list of ports using the `-ports` flag with a comma-separated list.

## Requirements
- Go 1.16 or later

## Building and Running

### Step 1: Navigate to the Project Folder
Open your terminal and navigate to the `test1` folder where your project resides by typing:
  
`cd test1`

### Step 2: Running the Code

**Option 1: Using go run**  
Run the following command to execute the port scanner directly without building an executable:  
`go run main.go -target scanme.nmap.org -start-port 1 -end-port 1024 -workers 100 -timeout 5 -banner -json`

**Option 2: Building an Executable**  
1. Build the executable by typing:  
`go build -o portscanner main.go`

2. Run the executable with your desired flags by typing:  
`./portscanner -target scanme.nmap.org -start-port 1 -end-port 1024 -workers 100 -timeout 5 -banner -json`

### Command-Line Flags Description
- `-target`: Single target hostname or IP (default: "scanme.nmap.org")
- `-targets`: Comma-separated list of targets
- `-start-port`: Starting port number in range (default: 1)
- `-end-port`: Ending port number in range (default: 1024)
- `-workers`: Number of concurrent scanning workers (default: 100)
- `-timeout`: Connection timeout in seconds (default: 5)
- `-banner`: Enable banner grabbing from open ports
- `-json`: Output the scan results in JSON format
- `-ports`: Comma-separated list of specific ports to scan

## Author
Jevon Teul

