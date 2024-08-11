import os
import re
import urllib.parse
import phonenumbers
import json
import sys

def get_all_files(directory, extensions):
    return [os.path.join(root, file)
            for root, _, files in os.walk(directory)
            for file in files if any(file.endswith(ext) for ext in extensions)]

def grep_urls(file_path):
    url_patterns = ['http', 'https', 'ftp', 'file', 'data']
    urls = set()  # Use a set to ensure URLs are unique
    url_regex = re.compile(r'\b(?:http|https|ftp|file|data):[^\s"\'<>]+')

    with open(file_path, 'r') as file:
        for line in file:
            matches = url_regex.findall(line)
            for match in matches:
                urls.add(match)
    
    return urls

def grep_emails(file_path):
    email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    emails = set()

    with open(file_path, 'r') as file:
        for line in file:
            matches = email_regex.findall(line)
            for match in matches:
                emails.add(match)

    return emails

def grep_phones(file_path):
    phone_regex = re.compile(r'\b(\+?\d{1,4}[-.\s]?(\(?\d{1,3}?\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9})\b')
    phones = set()

    with open(file_path, 'r') as file:
        for line in file:
            matches = phone_regex.findall(line)
            for match in matches:
                phone_number = match[0]
                try:
                    parsed_number = phonenumbers.parse(phone_number, None)
                    if phonenumbers.is_valid_number(parsed_number):
                        phones.add(phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164))
                except phonenumbers.NumberParseException:
                    continue

    return phones

def extract_domains(urls):
    domains = set()
    common_extensions = ('.com', '.vn', '.net', '.org', '.edu', '.gov', '.info', '.biz', '.io')
    for url in urls:
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            if domain and domain.endswith(common_extensions):
                domains.add(domain)
        except ValueError as e:
            continue
    return domains

def filter_urls(urls):
    filtered_urls = set()
    common_extensions = ('.com', '.vn', '.net', '.org', '.edu', '.gov', '.info', '.biz', '.io')
    for url in urls:
        if not url.startswith(('mailto:', 'tel:', 'javascript:')):
            try:
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.netloc.endswith(common_extensions):
                    filtered_urls.add(url)
            except ValueError as e:
                continue
    return filtered_urls

def grep_firebase_urls(urls):
    firebase_urls = set()
    firebase_regex = re.compile(r'\bhttps:\/\/[a-zA-Z0-9-]+\.firebaseio\.com\b')
    for url in urls:
        if firebase_regex.match(url):
            firebase_urls.add(url)
    return firebase_urls

def find_manifest_file(java_folder):
    for root, _, files in os.walk(java_folder):
        if 'AndroidManifest.xml' in files:
            return os.path.join(root, 'AndroidManifest.xml')
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

    # Find URLs, emails, and phone numbers in all files
    all_urls = set()  # Use a set to keep track of all unique URLs
    all_emails = set()  # Use a set to keep track of all unique emails
    all_phones = set()  # Use a set to keep track of all unique phone numbers
    for file_path in all_files:
        urls = grep_urls(file_path)
        emails = grep_emails(file_path)
        phones = grep_phones(file_path)
        all_urls.update(urls)
        all_emails.update(emails)
        all_phones.update(phones)

    # Filter URLs and only keep those with common domain extensions
    filtered_urls = filter_urls(all_urls)

    # Extract Firebase URLs
    firebase_urls = grep_firebase_urls(filtered_urls)

    # Extract domains from the URLs
    all_domains = extract_domains(filtered_urls)

    # Prepare the JSON output
    output = {
        "Type": [],
        "Details": []
    }

    if filtered_urls:
        output["Type"].append("URLs")
        output["Details"].append(list(filtered_urls))

    if all_domains:
        output["Type"].append("Domains")
        output["Details"].append(list(all_domains))

    if all_emails:
        output["Type"].append("Emails")
        output["Details"].append(list(all_emails))

    if all_phones:
        output["Type"].append("Phones")
        output["Details"].append(list(all_phones))

    print(json.dumps(output))

if __name__ == "__main__":
    main()
