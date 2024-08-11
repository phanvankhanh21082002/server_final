import os
import re
import urllib.parse
import socket
import requests
import json
import sys

def get_all_files(directory, extensions):
    return [os.path.join(root, file)
            for root, _, files in os.walk(directory)
            for file in files if any(file.endswith(ext) for ext in extensions)]

def grep_urls(file_path):
    url_patterns = ['http', 'https', 'ftp', 'file', 'data']
    urls = set()
    url_regex = re.compile(r'\b(?:http|https|ftp|file|data):[^\s"\'<>]+')

    with open(file_path, 'r') as file:
        for line in file:
            matches = url_regex.findall(line)
            for match in matches:
                urls.add(match)
    
    return urls

def extract_domains(urls):
    domains = set()
    for url in urls:
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            if domain:
                domains.add(domain)
        except ValueError:
            pass
    return domains

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_ip_location(ip, api_key):
    url = f"https://ipinfo.io/{ip}?token={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        location = {
            "ip": data.get("ip", "N/A"),
            "country": data.get("country", "N/A"),
            "region": data.get("region", "N/A"),
            "city": data.get("city", "N/A"),
            "asn": data.get("org", "N/A"),
            "latitude": data.get("loc", "N/A").split(',')[0] if "loc" in data else "N/A",
            "longitude": data.get("loc", "N/A").split(',')[1] if "loc" in data else "N/A",
            "google_maps_link": f"https://www.google.com/maps?q={data.get('loc', 'N/A')}" if "loc" in data else "N/A"
        }
        return location
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving location for IP '{ip}': {e}")
        return None

def print_server_locations(domain_locations):
    for domain, details in domain_locations.items():
        details_str = f"IP: {details['ip']}, Country: {details['country']}, Region: {details['region']}, City: {details['city']}, ASN: {details['asn']}, View: {details['google_maps_link']}"
        print(f"{domain}: {details_str}")

def find_manifest_file(java_folder):
    for root, _, files in os.walk(java_folder):
        for file in files:
            if file == "AndroidManifest.xml":
                return os.path.join(root, file)
    return None

def main():
    java_folder = sys.argv[1]

    # Find AndroidManifest.xml file in the folder
    manifest_path = find_manifest_file(java_folder)
    if not manifest_path:
        print("AndroidManifest.xml not found in the specified folder.")
        return

    # Get all Java files and the AndroidManifest.xml file
    extensions = ['.java', '.xml']
    all_files = get_all_files(java_folder, extensions) + [manifest_path]

    # Find URLs in all files
    all_urls = set()
    for file_path in all_files:
        urls = grep_urls(file_path)
        all_urls.update(urls)

    # Extract domains from URLs
    all_domains = extract_domains(all_urls)

    # Your IPinfo API key
    api_key = '96a01403184a37'  # Replace with your actual API key

    # Known domains to exclude
    known_domains = [
        'google.com', 'youtube.com', 'yahoo.com', 'linkedin.com', 'github.com', 'facebook.com',
        'twitter.com', 'instagram.com', 'microsoft.com', 'apple.com', 'amazon.com'
    ]

    # Get location information for each domain
    domain_locations = {}
    for domain in all_domains:
        if any(known in domain for known in known_domains):
            continue  # Skip known domains
        else:
            ip_address = resolve_domain_to_ip(domain)
            if ip_address:
                location = get_ip_location(ip_address, api_key)
                if location and location['ip'] != 'N/A':
                    domain_locations[domain] = location

    # Print JSON output
    print(json.dumps(domain_locations))

if __name__ == "__main__":
    main()
