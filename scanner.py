import socket
import sys
import time
import ssl


def scan_port(target, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    start = time.time()

    try:
        sock.connect((target, port))
        elapsed = time.time() - start

        return "OPEN", elapsed, sock

    except ConnectionRefusedError:
        elapsed = time.time() - start
        sock.close()

        return "REFUSED", elapsed, None

    except socket.timeout:
        elapsed = time.time() - start
        sock.close()

        return "TIMEOUT", elapsed, None
 
def generate_report(target, startport, endport, results, summary):

    with open("port_scan_report.txt", "w") as file:

        file.write("=" * 80 + "\n")
        file.write("          TCP PORT SCAN SECURITY REPORT\n")
        file.write("=" * 80 + "\n\n")

        file.write(f"Target     : {target}\n")
        file.write(f"Port Range : {startport} - {endport}\n\n")

        file.write("-" * 80 + "\n")
        file.write("SCAN RESULTS\n")
        file.write("-" * 80 + "\n\n")

        for result in results:

            file.write(
                f"Port: {result['port']}\n"
                f"State: {result['state']}\n"
                f"Service: {result['service']}\n"
                f"Version: {result['version']}\n"
                f"Observation: {result['observation']}\n"
                f"Finding: {result['finding']}\n"
                f"Time: {result['time']:.4f}s\n"
                + "-" * 40 + "\n"
            )

        file.write("\n")
        file.write("=" * 80 + "\n")
        file.write("SCAN SUMMARY\n")
        file.write("=" * 80 + "\n\n")

        file.write(f"Ports scanned : {summary['total_ports']}\n")
        file.write(f"Open          : {summary['open_ports']}\n")
        file.write(f"Refused       : {summary['refused_ports']}\n")
        file.write(f"Timeout       : {summary['timeout_ports']}\n\n")

        file.write("SERVICES\n")
        file.write("-" * 40 + "\n")

        file.write(f"HTTP          : {summary['http']}\n")
        file.write(f"HTTPS         : {summary['https']}\n")
        file.write(f"SSH           : {summary['ssh']}\n")
        file.write(f"Unknown       : {summary['unknown']}\n")

        file.write("\n" + "=" * 80 + "\n")

    print("\nReport generated: port_scan_report.txt")
 
def get_finding(service):

    if service == "HTTP":
        return "Review HTTP exposure"

    if service == "HTTPS":
        return "Review TLS configuration"

    if service == "SSH":
        return "Review SSH access controls"

    if service == "UNKNOWN":
        return "Investigate unknown service"

    return "N/A"

def get_observation(state, service):

    if state == "TIMEOUT":
        return "Connection timed out"

    if state == "REFUSED":
        return "Connection refused"

    if state == "OPEN":

        if service == "HTTP":
            return "HTTP service exposed"

        if service == "HTTPS":
            return "HTTPS service detected"

        if service == "SSH":
            return "SSH service exposed"

        if service == "UNKNOWN":
            return "Unknown service exposed"

    return "N/A"
 
def generate_summary(results):

    total_ports = len(results)

    open_ports = 0
    refused_ports = 0
    timeout_ports = 0

    http_count = 0
    https_count = 0
    ssh_count = 0
    unknown_count = 0

    for result in results:

        if result["state"] == "OPEN":
            open_ports += 1

        elif result["state"] == "REFUSED":
            refused_ports += 1

        elif result["state"] == "TIMEOUT":
            timeout_ports += 1

        if result["service"] == "HTTP":
            http_count += 1

        elif result["service"] == "HTTPS":
            https_count += 1

        elif result["service"] == "SSH":
            ssh_count += 1

        elif result["service"] == "UNKNOWN":
            unknown_count += 1

    return {
        "total_ports": total_ports,
        "open_ports": open_ports,
        "refused_ports": refused_ports,
        "timeout_ports": timeout_ports,
        "http": http_count,
        "https": https_count,
        "ssh": ssh_count,
        "unknown": unknown_count
    }


def probe_http(sock, target):

    try:

        request = (
            "GET / HTTP/1.1\r\n"
            "Host: " + target + "\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.send(request.encode())

        response = sock.recv(4096)
        response_text = response.decode(errors="ignore")

        # Verify that the response is actually HTTP
        if not response_text.startswith("HTTP/"):
            return "HTTP probe failed"

        # Look for the Server header
        for line in response_text.splitlines():

            if line.startswith("Server:"):
                return line

        return "HTTP server detected"

    except socket.timeout:
        return "HTTP probe timeout"

    except OSError:
        return "HTTP probe failed"


def probe_https(target, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    secure_sock = None

    try:

        sock.connect((target, port))

        context = ssl.create_default_context()

        secure_sock = context.wrap_socket(
            sock,
            server_hostname=target
        )

        request = (
            "GET / HTTP/1.1\r\n"
            "Host: " + target + "\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        secure_sock.send(request.encode())

        response = secure_sock.recv(4096)
        response_text = response.decode(errors="ignore")

        # Verify that the response is actually HTTP over TLS
        if not response_text.startswith("HTTP/"):
            return "HTTPS probe failed"

        # Look for the Server header
        for line in response_text.splitlines():

            if line.startswith("Server:"):
                return line

        return "HTTPS server detected"

    except socket.timeout:
        return "HTTPS probe timeout"

    except (ssl.SSLError, OSError):
        return "HTTPS probe failed"

    finally:

        if secure_sock:
            secure_sock.close()
        else:
            sock.close()


def probe_ssh(target, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:

        sock.connect((target, port))

        response = sock.recv(1024)

        banner = response.decode(errors="ignore").strip()

        if banner.startswith("SSH-"):
            return banner

        return "SSH probe failed"

    except socket.timeout:
        return "SSH probe timeout"

    except OSError:
        return "SSH probe failed"

    finally:

        sock.close()

def extract_version(service_info):

    if service_info.startswith("Server:"):
        return service_info.replace("Server:", "").strip()

    if service_info.startswith("SSH-"):
        return service_info

    return service_info


def grab_banner(target, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:

        sock.connect((target, port))

        response = sock.recv(1024)

        banner = response.decode(errors="ignore").strip()

        if banner:
            return banner

        return "NO BANNER"

    except socket.timeout:
        return "NO BANNER"

    except OSError:
        return "NO BANNER"

    finally:

        sock.close()


def identify_service(target, port):

    # Known ports

    if port == 22:
        return probe_ssh(target, port)

    if port in (80, 8000, 8080):
        return probe_http(
            socket.create_connection((target, port), timeout=2),
            target
        )

    if port == 443:
        return probe_https(target, port)

    # Unknown port
    # Try HTTP first

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((target, port))
        result = probe_http(sock, target)

        if result != "HTTP probe failed":
            return result

    except OSError:
        pass

    finally:
        sock.close()

    # Try HTTPS

    result = probe_https(target, port)

    if result != "HTTPS probe failed":
        return result

    # Try SSH

    result = probe_ssh(target, port)

    if result != "SSH probe failed":
        return result

    # Nothing identified

    return grab_banner(target, port)


def get_service_name(port, service_info):

    # Known ports

    if port == 22:
        return "SSH"

    if port in (80, 8000, 8080):
        return "HTTP"

    if port == 443:
        return "HTTPS"

    # Detected from response

    if service_info.startswith("SSH-"):
        return "SSH"

    if (
        service_info.startswith("HTTP/")
        or service_info.startswith("Server:")
    ):
        return "HTTP"

    if service_info.startswith("HTTPS"):
        return "HTTPS"

    return "UNKNOWN"


# -------------------------
# Command-line arguments
# -------------------------

target = sys.argv[1]
startport = int(sys.argv[2])
endport = int(sys.argv[3])

results = []


# -------------------------
# Scan ports
# -------------------------

for port in range(startport, endport + 1):

    result, elapsed, sock = scan_port(target, port)

    if result == "OPEN":

        # scan_port() only used this socket
        # to confirm that the port is open.
        sock.close()

        service_info = identify_service(target, port)
        service = get_service_name(port, service_info)
        version = extract_version(service_info)
        observation = get_observation(result, service)  
        finding = get_finding(service)

    else:

        service_info = "N/A"
        service = "N/A"
        version = "N/A"
        observation = "N/A"
        finding ="N/A"

    results.append({
        "port": port,
        "state": result,
        "service": service,
        "version": version,
        "observation": observation,
        "finding":finding,
        "time": elapsed
    })

summary = generate_summary(results)

# -------------------------
# Display results
# -------------------------

print()

print("=" * 90)

print(
    f"{'PORT':<8}"
    f"{'STATE':<12}"
    f"{'SERVICE':<12}"
    f"{'VERSION':<35}"
    f"{'OBSERVATION':<30}"
    f"{'FINDINGS':<30}"
    f"{'TIME':<10}"
)

print("=" * 90)


for result in results:

    print(
        f"{result['port']:<8}"
        f"{result['state']:<12}"
        f"{result['service']:<12}"
        f"{result['version']:<35}"
        f"{result['observation']:<30}"
        f"{result['finding']:<30}"
        f"{result['time']:.4f}s"
    )

print("=" * 90)


print()
print("=" * 50)
print("SCAN SUMMARY")
print("=" * 50)

print(f"Ports scanned : {summary['total_ports']}")
print(f"Open          : {summary['open_ports']}")
print(f"Refused       : {summary['refused_ports']}")
print(f"Timeout       : {summary['timeout_ports']}")

print()
print("SERVICES")
print("-" * 50)

print(f"HTTP          : {summary['http']}")
print(f"HTTPS         : {summary['https']}")
print(f"SSH           : {summary['ssh']}")
print(f"Unknown       : {summary['unknown']}")

print("=" * 50)

generate_report(
    target,
    startport,
    endport,
    results,
    summary
)

print()
print("=" * 60)
print("SCAN COMPLETED")
print("Report generated successfully.")
print("Check the report for further inspection.")
print("=" * 60)

