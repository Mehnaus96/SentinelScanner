# SentinelScanner
# 🔐 TCP Port Scanner

A Python-based TCP port scanner built from scratch to understand **network service discovery, TCP connections, protocol probing, service identification, and basic security analysis**.

The project goes beyond simply checking whether a port is open. It attempts to identify the service running on discovered open ports, extract available service/version information, generate security-oriented observations, summarize the scan, and produce a persistent security report.

> **Purpose:** Educational and authorized security testing on systems you own or have permission to assess.

---

## 📌 Overview

A TCP port represents a logical endpoint through which a network service can communicate.

A port scanner attempts to establish a TCP connection to a target IP address and port to determine whether that port is reachable and accepting connections.

This project implements that process from scratch using Python's built-in networking capabilities.

The scanner can:

* Scan a user-defined TCP port range
* Identify ports as `OPEN`, `REFUSED`, or `TIMEOUT`
* Detect common services such as HTTP, HTTPS, and SSH
* Perform protocol-specific probing
* Extract service banners and version information when available
* Generate security-oriented observations
* Generate basic analyst review findings
* Produce a scan summary
* Generate a `.txt` security report

The project was designed to understand the complete path from:

```text
Network Connection
        ↓
Port Discovery
        ↓
Service Identification
        ↓
Information Extraction
        ↓
Security Observation
        ↓
Analyst Review
        ↓
Report Generation
```

---

# 🎯 Project Objectives

The primary objective was not to build a feature-heavy scanner, but to understand the fundamentals behind network reconnaissance and how a raw TCP connection result can be transformed into useful security information.

### Learning objectives

* Understand IPv4 TCP sockets
* Understand TCP connection attempts
* Understand ports and services
* Handle connection errors and timeouts
* Understand protocol-specific communication
* Perform basic HTTP/HTTPS/SSH detection
* Extract service banners
* Separate network state from service identification
* Convert technical results into analyst-oriented observations
* Generate structured scan summaries
* Create a persistent security report

---

# ⚙️ Features

## 1. TCP Port Scanning

The scanner accepts:

* Target IP/hostname
* Starting port
* Ending port

Example:

```bash
python port_scanner.py 127.0.0.1 7998 8003
```

Each port is tested using a TCP connection attempt.

Possible states are:

```text
OPEN
REFUSED
TIMEOUT
```

---

## 2. Connection Timing

The scanner measures how long each TCP connection attempt takes.

Example:

```text
8000    OPEN      0.0009s
8001    REFUSED  0.0003s
8002    TIMEOUT  2.0024s
```

This provides additional context about the connection attempt.

---

## 3. Service Identification

When an open port is discovered, the scanner attempts to determine what service is communicating on that port.

Currently supported detection includes:

```text
HTTP
HTTPS
SSH
UNKNOWN
```

Known ports can be associated with their expected protocols, while unknown ports can be probed to determine whether they respond using supported protocols.

---

## 4. Protocol Probing

The scanner does not treat every open port as HTTP.

Instead, it uses protocol-specific communication.

### HTTP

The scanner sends an HTTP request:

```http
GET / HTTP/1.1
Host: target
Connection: close
```

It then checks whether the response resembles an HTTP response and looks for the `Server` header.

Example:

```text
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.7
```

---

### HTTPS

For HTTPS services, the scanner establishes a TCP connection and then creates a TLS-secured connection using Python's `ssl` module.

It then performs an HTTP request over the secure connection.

---

### SSH

For SSH, the scanner waits for the server's initial banner.

Example:

```text
SSH-2.0-OpenSSH_9.x
```

---

## 5. Banner and Version Extraction

When a service voluntarily exposes identifying information, the scanner attempts to capture it.

For example:

```text
Server: SimpleHTTP/0.6 Python/3.14.7
```

is extracted into:

```text
SimpleHTTP/0.6 Python/3.14.7
```

SSH banners are also preserved when detected.

> Banner information is not guaranteed to be accurate or complete. A banner represents information exposed by the service and should be treated as an observation rather than proof of a specific vulnerability.

---

# 🔎 Security Analyst Layer

The scanner contains a basic analyst-oriented interpretation layer.

Instead of stopping at:

```text
Port 8000 → OPEN
```

the scanner can produce:

```text
Port       : 8000
State      : OPEN
Service    : HTTP
Observation: HTTP service exposed
Finding    : Review HTTP exposure
```

This creates a bridge between **technical network information** and **security investigation**.

### Example findings

| Service | Review Finding              |
| ------- | --------------------------- |
| HTTP    | Review HTTP exposure        |
| HTTPS   | Review TLS configuration    |
| SSH     | Review SSH access controls  |
| UNKNOWN | Investigate unknown service |
| N/A     | N/A                         |

These findings are intentionally conservative.

An open port or detected service **does not automatically mean that a vulnerability exists**.

Actual security severity would require additional information such as:

* Network exposure
* Service configuration
* Authentication controls
* Encryption configuration
* Asset importance
* Known vulnerabilities
* Environmental context

---

# 🏗️ Architecture

```text
                    TARGET
                      │
                      ▼
              ┌───────────────┐
              │  TCP Scanner  │
              └───────┬───────┘
                      │
                      ▼
             Connection Attempt
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        OPEN       REFUSED      TIMEOUT
          │
          ▼
   Service Identification
          │
     ┌────┼─────┬────────┐
     ▼    ▼     ▼        ▼
    HTTP HTTPS  SSH    UNKNOWN
     │    │     │        │
     └────┴─────┴────────┘
              │
              ▼
       Banner / Version
          Extraction
              │
              ▼
        Observation
              │
              ▼
      Analyst Review
          Finding
              │
              ▼
        Scan Summary
              │
              ▼
       Security Report
```

---

# 🧠 Core Design

The project separates different responsibilities instead of putting everything inside one large scanning loop.

### `scan_port()`

Responsible for:

* Creating the TCP socket
* Setting the timeout
* Attempting the connection
* Measuring connection time
* Returning the connection state

---

### `identify_service()`

Responsible for determining which protocol/service appears to be running.

---

### `probe_http()`

Attempts HTTP communication and extracts available HTTP server information.

---

### `probe_https()`

Establishes a TLS connection and attempts HTTP communication over HTTPS.

---

### `probe_ssh()`

Attempts to identify SSH from the server's initial banner.

---

### `grab_banner()`

Provides a generic fallback when a service cannot be identified using the supported protocol probes.

---

### `get_service_name()`

Converts the discovered information into a normalized service name:

```text
HTTP
HTTPS
SSH
UNKNOWN
```

---

### `extract_version()`

Extracts useful identifying information from the service response.

---

### `get_observation()`

Converts the scan state and detected service into a human-readable observation.

Example:

```text
OPEN + HTTP
        ↓
HTTP service exposed
```

---

### `get_finding()`

Creates a basic analyst review point.

Example:

```text
HTTP
 ↓
Review HTTP exposure
```

---

### `generate_summary()`

Calculates:

* Total ports scanned
* Open ports
* Refused ports
* Timed-out ports
* HTTP services
* HTTPS services
* SSH services
* Unknown services

---

### `generate_report()`

Creates a persistent text report containing:

* Target
* Port range
* Individual scan results
* Service information
* Observations
* Findings
* Scan summary

---

# 🛠️ Technology Stack

### Programming Language

**Python**

### Standard Library

| Module   | Purpose                        |
| -------- | ------------------------------ |
| `socket` | TCP networking and connections |
| `ssl`    | TLS/HTTPS communication        |
| `sys`    | Command-line arguments         |
| `time`   | Connection timing              |
| File I/O | Security report generation     |

No external Python packages are required.

---

# 📂 Project Structure

```text
tcp-port-scanner/
│
├── README.md
├── port_scanner.py
└── sample_report.txt
```

### `README.md`

Project documentation, architecture, usage instructions, and technical explanation.

### `port_scanner.py`

Complete scanner implementation.

### `sample_report.txt`

Example output generated by the scanner.

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone <repository-url>
```

Move into the project directory:

```bash
cd tcp-port-scanner
```

No additional Python packages are required.

Verify Python:

```bash
python --version
```

---

# ▶️ Usage

The scanner accepts three command-line arguments:

```text
python port_scanner.py <target> <start_port> <end_port>
```

### Example

```bash
python port_scanner.py 127.0.0.1 7998 8003
```

This scans:

```text
7998
7999
8000
8001
8002
8003
```

The ending port is included.

---

# 🧪 Local Testing

A simple way to test the scanner is to run a local HTTP server.

In one terminal:

```bash
python -m http.server 8000
```

This creates a local HTTP service on:

```text
127.0.0.1:8000
```

Then, in another terminal:

```bash
python port_scanner.py 127.0.0.1 7998 8003
```

The scanner should be able to identify port `8000` as an HTTP service.

Example:

```text
8000    OPEN    HTTP    SimpleHTTP/0.6 Python/3.14.7
```

---

# 📊 Example Output

```text
==============================================================================================================
PORT    STATE       SERVICE     VERSION                         OBSERVATION                    FINDING
==============================================================================================================
7998    TIMEOUT     N/A         N/A                             Connection timed out           N/A
7999    REFUSED    N/A         N/A                             Connection refused            N/A
8000    OPEN        HTTP        SimpleHTTP/0.6 Python/3.14.7   HTTP service exposed          Review HTTP exposure
8001    REFUSED    N/A         N/A                             Connection refused            N/A
==============================================================================================================

==================================================
SCAN SUMMARY
==================================================
Ports scanned : 4
Open          : 1
Refused       : 2
Timeout       : 1

SERVICES
--------------------------------------------------
HTTP          : 1
HTTPS         : 0
SSH           : 0
Unknown       : 0
==================================================

============================================================
SCAN COMPLETED
Report generated successfully.
Check the report for further inspection.
============================================================
```

---

# 📄 Generated Security Report

After the scan completes, the program generates:

```text
port_scan_report.txt
```

The report contains the scan results and summary in a persistent format.

Example:

```text
========================================
       TCP PORT SCAN SECURITY REPORT
========================================

Target     : 127.0.0.1
Port Range : 7998 - 8003

----------------------------------------
SCAN RESULTS
----------------------------------------

Port: 8000
State: OPEN
Service: HTTP
Version: SimpleHTTP/0.6 Python/3.14.7
Observation: HTTP service exposed
Finding: Review HTTP exposure
Time: 0.0009s
```

The report can then be reviewed separately from the terminal output.

---

# 🧑‍💻 Security Analyst Use Case

A SOC or security analyst can use a tool like this during an initial investigation to obtain a quick view of exposed TCP services on an authorized target.

A basic workflow could be:

```text
1. Identify target
        ↓
2. Scan selected TCP ports
        ↓
3. Identify open ports
        ↓
4. Determine available services
        ↓
5. Review banners/version information
        ↓
6. Examine analyst findings
        ↓
7. Investigate relevant services further
```

For example:

```text
Port 8000
    ↓
OPEN
    ↓
HTTP detected
    ↓
Server banner obtained
    ↓
HTTP service exposed
    ↓
Review HTTP exposure
```

The scanner therefore acts as an **initial discovery and triage tool**, rather than a complete vulnerability scanner.

---

# ⚠️ Limitations

This project intentionally has a limited scope.

It currently does not perform:

* Full vulnerability scanning
* CVE identification
* Exploit execution
* Web application vulnerability testing
* Password testing
* Authentication attacks
* Deep protocol fingerprinting
* UDP scanning
* Operating-system fingerprinting
* Comprehensive TLS security auditing

An open port should not automatically be interpreted as a vulnerability.

The scanner provides **technical observations and review points**, which would require further investigation by a security analyst.

---

# 🔐 Responsible Use

This tool should only be used against:

* Systems you own
* Local test environments
* Lab environments
* Systems for which you have explicit authorization to perform security testing

Unauthorized scanning can violate organizational policies or applicable laws.

---

# 📚 What I Learned

Building this project helped me understand several concepts from the ground up:

* How TCP connection attempts work
* How Python sockets represent network connections
* IPv4 addressing through `AF_INET`
* TCP stream communication through `SOCK_STREAM`
* Connection timeouts
* Connection refusal
* Protocol-specific communication
* HTTP request/response structure
* TLS-wrapped communication
* SSH banners
* Service identification
* Banner/version extraction
* Security-oriented result interpretation
* Structured scan summaries
* Automated report generation

Most importantly, the project helped connect:

```text
Networking
     +
Programming
     +
Security Analysis
```

into one practical workflow.

---

# 🔮 Future Improvements

Possible future improvements include:

* Concurrent/asynchronous scanning
* Better protocol fingerprinting
* More protocol probes
* Structured JSON reports
* HTML report generation
* More detailed TLS inspection
* CVE/database integration
* Configuration-based scanning
* Logging
* Exporting results for SIEM ingestion

These are intentionally outside the current scope so that the core networking and security concepts remain clear.

---

# 👨‍💻 Project Status

**Status:** Completed — Version 1

The current version focuses on building a strong foundation in:

> **TCP scanning → Service identification → Basic security analysis → Reporting**

---

## ⭐ Key Takeaway

This project started as a simple question:

> **"Is this TCP port accepting connections?"**

and evolved into:

```text
Is the port open?
        ↓
What service is there?
        ↓
What information does it expose?
        ↓
What should an analyst review?
        ↓
Can we preserve the result as a report?
```

That progression represents the primary learning goal of this project.
