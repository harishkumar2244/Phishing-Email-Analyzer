import argparse
import email
from email import policy
from email.parser import BytesParser
import re
import requests
import dns.resolver
from bs4 import BeautifulSoup
from publicsuffixlist import PublicSuffixList
import json
import sys

# Configuration
PHISHING_KEYWORDS = [
    'verify your account', 'password reset', 'confirm your identity', 'urgent action required',
    'suspicious activity', 'security alert', 'account suspended', 'you have won', 'prize',
    'confidential', 'login attempt', 'update your details'
]
URL_BLACKLIST_API = "https://phish.sinkingpoint.com/api/v2/check" # Example public API

def analyze_headers(msg):
    """Analyzes email headers for signs of spoofing."""
    report = []
    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')

    if from_header and return_path and from_header not in return_path:
        report.append({
            'indicator': 'Header Mismatch',
            'description': f"The 'From' header ({from_header}) does not match the 'Return-Path' ({return_path}).",
            'risk_score': 15
        })
    return report

def extract_urls(html_content):
    """Extracts all URLs from the HTML body of the email."""
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = set()
    for a_tag in soup.find_all('a', href=True):
        urls.add(a_tag['href'])
    return list(urls)

def analyze_url(url):
    """Analyzes a single URL for phishing indicators."""
    report = []
    
    # Check against blacklist
    try:
        response = requests.post(URL_BLACKLIST_API, json={"url": url}, timeout=5)
        if response.status_code == 200 and response.json().get("phish"):
            report.append({
                'indicator': 'URL Blacklisted',
                'description': f"The URL '{url}' is on a known phishing blacklist.",
                'risk_score': 30
            })
    except requests.RequestException:
        print(f"[!] Warning: Could not connect to URL blacklist API for {url}", file=sys.stderr)

    # Check for IP address in URL
    if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        report.append({
            'indicator': 'IP Address in URL',
            'description': f"The URL '{url}' uses an IP address instead of a domain name.",
            'risk_score': 20
        })
        
    return report

def analyze_content(text_content):
    """Scans email body for phishing keywords."""
    report = []
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_content.lower():
            found_keywords.append(keyword)
    
    if found_keywords:
        report.append({
            'indicator': 'Suspicious Keywords',
            'description': f"Found keywords often used in phishing: {', '.join(found_keywords)}",
            'risk_score': 5 * len(found_keywords)
        })
    return report

def analyze_email(file_path):
    """Main function to analyze an email file."""
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        print(f"[!] Error: File not found at '{file_path}'", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Error parsing email file: {e}", file=sys.stderr)
        return None

    full_report = {
        'file_path': file_path,
        'subject': msg.get('Subject', 'N/A'),
        'from': msg.get('From', 'N/A'),
        'to': msg.get('To', 'N/A'),
        'date': msg.get('Date', 'N/A'),
        'analysis_results': [],
        'total_risk_score': 0
    }

    # 1. Analyze Headers
    full_report['analysis_results'].extend(analyze_headers(msg))

    # 2. Extract and Analyze Body Content
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if "attachment" not in content_disposition:
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    full_report['analysis_results'].extend(analyze_content(body))
                elif content_type == "text/html":
                    html_body = part.get_payload(decode=True).decode(errors='ignore')
                    urls = extract_urls(html_body)
                    for url in urls:
                        full_report['analysis_results'].extend(analyze_url(url))
    else:
        # Not a multipart email, just get the payload
        body = msg.get_payload(decode=True).decode(errors='ignore')
        full_report['analysis_results'].extend(analyze_content(body))
        if msg.get_content_type() == "text/html":
             urls = extract_urls(body)
             for url in urls:
                full_report['analysis_results'].extend(analyze_url(url))

    # Calculate total risk score
    total_score = sum(item.get('risk_score', 0) for item in full_report['analysis_results'])
    full_report['total_risk_score'] = total_score

    return full_report

def print_report(report):
    """Prints a formatted report to the console."""
    if not report:
        return
        
    print("\n" + "="*50)
    print(" PhishGuard Email Analysis Report")
    print("="*50)
    print(f"Subject: {report['subject']}")
    print(f"From: {report['from']}")
    print(f"Total Risk Score: {report['total_risk_score']}")
    
    risk_level = "Low"
    if 30 > report['total_risk_score'] >= 15:
        risk_level = "Medium"
    elif report['total_risk_score'] >= 30:
        risk_level = "High"
    print(f"Calculated Risk Level: {risk_level}")
    print("-"*50)
    
    if report['analysis_results']:
        print("Findings:")
        for finding in report['analysis_results']:
            print(f"  - [{finding['indicator']}] (Score: +{finding['risk_score']})")
            print(f"    Description: {finding['description']}")
    else:
        print("No specific phishing indicators found.")
    print("="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard: Automated Phishing Email Analyzer.",
        epilog="Example: python analyzer.py --file email.eml --output report.json"
    )
    parser.add_argument('--file', required=True, help='Path to the email file (.eml) to analyze.')
    parser.add_argument('--output', help='Optional. Path to save the detailed JSON report.')
    
    args = parser.parse_args()
    
    report = analyze_email(args.file)
    
    if report:
        print_report(report)
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=4)
                print(f"[+] Full report saved to {args.output}")
            except IOError as e:
                print(f"[!] Error saving report to file: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
