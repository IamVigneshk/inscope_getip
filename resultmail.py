import socket
from urllib.parse import urlparse
import tldextract
import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os

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
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        return f"Error getting IP for {hostname}: {e}"

# Function to get the IP address by pinging a domain
def ping_domain(domain):
    try:
        result = subprocess.run(['ping', '-c', '1', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
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
        result = subprocess.run(['nmap', '-A', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Failed to run Nmap scan on {ip_address}: {result.stderr}"
    except Exception as e:
        return f"Error running Nmap scan on {ip_address}: {e}"

# Function to generate HTML content for the results
def generate_html_content(output):
    styled_output = ""
    for line in output.split("\n"):
        if line.startswith("URL:") or line.startswith("Root Domain:") or line.startswith("IP address of"):
            styled_output += f"<strong style='font-family: Times New Roman;'>{line}</strong><br>\n"
        else:
            # Remove empty lines
            if line.strip():
                styled_output += f"<p>{line}</p><br>\n"

    html_content = f"""
    <html>
    <head>
        <title>Scan Results</title>
    </head>
    <body>
    <pre>{styled_output}</pre>
    <footer><p>By Venom</p></footer>
    </body>
    </html>
    """
    return html_content

# Function to extract important lines for email body
def extract_important_lines(output):
    important_lines = ""
    for line in output.split("\n"):
        if line.startswith("URL:") or line.startswith("Root Domain:") or line.startswith("IP address of"):
            important_lines += line + "\n"
    return important_lines

# Function to send the results via email
def send_email(subject, body, html_file_path, from_email, to_email):
    #smtp_server = "smtp-relay.brevo.com"
    #smtp_port = 587
    #smtp_user = "Give "
    #smtp_password = "znKr7C85jSqLBR43"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    # Attach the HTML file
    with open(html_file_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {os.path.basename(html_file_path)}",
        )
        msg.attach(part)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())

# Function to save results to a text file
def save_to_text_file(file_name, output):
    with open(file_name, 'w') as file:
        file.write(output)
        file.write("\n\nBy Venom")

# Function to save results to an HTML file
def save_to_html_file(file_name, output):
    html_content = generate_html_content(output)
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
    html_content = generate_html_content(output)

    # Print the results to the console
    print(output)

    # Save the results to a file
    if output_format == '1':
        save_to_text_file(output_file_name, output)
    elif output_format == '2':
        save_to_html_file(output_file_name, output)

    # Send the results via email
    subject = f"Scan Results: {', '.join(urls)}"
    from_email = "venomcyberrrr@gmail.com"
    to_email = "vigneshk999999999@gmail.com"
    body = extract_important_lines(output)
    send_email(subject, body, output_file_name, from_email, to_email)

if __name__ == "__main__":
    file_path = input("Enter the path to the text file containing URLs: ")  # Replace with your text file path
    output_format = input("Enter output format (1 for text file, 2 for HTML file): ")
    output_file_name = input("Enter the output file name: ")

    main(file_path, output_format, output_file_name)
