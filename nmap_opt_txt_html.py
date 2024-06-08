import socket
from urllib.parse import urlparse
import tldextract
import subprocess

# Function to read URLs from a text file
def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

# Function to get the root domain from a URL
def get_root_domain(url):
    try:
        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        return root_domain
    except Exception as e:
        return f"Error extracting root domain for {url}: {e}"

# Function to get the IP address of a hostname
def get_ip_address(hostname):
    try:
        # Get the IP address of the hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        return f"Error getting IP for {hostname}: {e}"

# Function to get the IP address by pinging a domain
def ping_domain(domain):
    try:
        # Pinging the domain
        result = subprocess.run(['ping', '-c', '1', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            # Extracting the IP address from the ping output
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if 'PING' in line:
                    start = line.find('(') + 1
                    end = line.find(')')
                    ip_address = line[start:end]
                    return ip_address
        return None
    except Exception as e:
        return None

# Function to run an Nmap scan on an IP address
def run_nmap_scan(ip_address):
    try:
        # Run Nmap port scan
        result = subprocess.run(['nmap', '-A', '-v', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Failed to run Nmap scan on {ip_address}: {result.stderr}"
    except Exception as e:
        return f"Error running Nmap scan on {ip_address}: {e}"

# Function to save results to a text file
def save_to_text_file(file_name, output):
    with open(file_name, 'w') as file:
        file.write(output)
        file.write("\n\nBy Venom")

# Function to save results to an HTML file
def save_to_html_file(file_name, output):
    html_content = f"""
    <html>
    <head><title>Scan Results</title></head>
    <body>
    <pre>{output}</pre>
    <footer><p>By Venom</p></footer>
    </body>
    </html>
    """
    with open(file_name, 'w') as file:
        file.write(html_content)

# Main function
def main(file_path, output_format, output_file_name):
    urls = read_urls_from_file(file_path)
    scanned_ips = set()  # Set to keep track of scanned IPs
    results = []

    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        root_domain = get_root_domain(url)

        ip_address = get_ip_address(hostname)
        root_ip_address = get_ip_address(root_domain)

        results.append(f"URL: {url}")
        results.append(f"Root Domain: {root_domain}")

        if ip_address and not isinstance(ip_address, Exception):
            if ip_address not in scanned_ips:
                results.append(f"IP address of {url}: {ip_address}")
                nmap_result = run_nmap_scan(ip_address)
                results.append(f"Nmap scan result for {ip_address}:\n{nmap_result}")
                scanned_ips.add(ip_address)
            else:
                results.append(f"IP address of {url} ({ip_address}) has already been scanned.")
        else:
            results.append(f"Failed to get IP of {url}.")

        if root_ip_address and not isinstance(root_ip_address, Exception):
            if root_ip_address not in scanned_ips:
                results.append(f"IP address of root domain ({root_domain}): {root_ip_address}")
                nmap_result = run_nmap_scan(root_ip_address)
                results.append(f"Nmap scan result for {root_ip_address}:\n{nmap_result}")
                scanned_ips.add(root_ip_address)
            else:
                results.append(f"IP address of root domain ({root_domain}) ({root_ip_address}) has already been scanned.")
        else:
            root_ip_address_ping = ping_domain(root_domain)
            if root_ip_address_ping:
                if root_ip_address_ping not in scanned_ips:
                    results.append(f"IP address of root domain ({root_domain}) by ping: {root_ip_address_ping}")
                    nmap_result = run_nmap_scan(root_ip_address_ping)
                    results.append(f"Nmap scan result for {root_ip_address_ping}:\n{nmap_result}")
                    scanned_ips.add(root_ip_address_ping)
                else:
                    results.append(f"IP address of root domain ({root_domain}) by ping ({root_ip_address_ping}) has already been scanned.")
            else:
                results.append(f"Failed to get IP of root domain ({root_domain}).")

        results.append("-" * 40)

    output = "\n".join(results)
    if output_format == '1':
        save_to_text_file(output_file_name, output)
    elif output_format == '2':
        save_to_html_file(output_file_name, output)

if __name__ == "__main__":
    file_path = input("Enter the path to the text file containing URLs: ")  # Replace with your text file path
    output_format = input("Enter output format (1 for text file, 2 for HTML file): ")
    output_file_name = input("Enter the output file name: ")
    main(file_path, output_format, output_file_name)
