# Phishing-Email-Analyzer

![GitHub last commit](https://img.shields.io/github/last-commit/google/skia)
![GitHub stars](https://img.shields.io/github/stars/google/skia)
![GitHub forks](https://img.shields.io/github/forks/google/skia)
![GitHub issues](https://img.shields.io/github/issues/google/skia)

**PhishGuard** is a Python-based tool designed to automatically analyze email files (`.eml`) to identify and flag potential phishing attacks. It examines email headers, links, and content to generate a risk score and a detailed security report.

## How It Works

The analyzer performs a multi-layered analysis to detect suspicious characteristics common in phishing emails:

1.  **Header Analysis**: The tool inspects email headers for signs of spoofing. It checks for discrepancies between the `From` address and the `Return-Path`, and analyzes the `Received` chain for potential red flags.

2.  **URL & Link Extraction**: It extracts all hyperlinks from the email body, including those that may be obfuscated or hidden behind seemingly legitimate text.

3.  **URL Analysis**: Each extracted URL is scrutinized. The tool checks it against known phishing blacklists, looks for suspicious patterns like IP addresses used as domains, and analyzes the domain's reputation.

4.  **Content Analysis**: The email's text content is scanned for common phishing keywords and phrases that create a sense of urgency or ask for sensitive information (e.g., "verify your account," "urgent action required").

5.  **Risk Scoring & Reporting**: Based on the findings from all analysis phases, the tool calculates a risk score. A final report is generated, detailing all identified threats and providing a clear summary of the findings.

## Key Features

-   **Automated Email Analysis**: Simply provide an `.eml` file to get a full security report.
-   **Comprehensive Threat Detection**: Analyzes headers, URLs, and content to detect a wide range of phishing techniques.
-   **Risk Scoring**: Quantifies the threat level of each email with a simple risk score.
-   **Detailed Reporting**: Generates a clear, easy-to-understand report in the console or as a JSON file.
-   **Extensible**: Easy to add new keywords, URL blacklists, and analysis modules.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/phishguard-analyzer.git](https://github.com/your-username/phishguard-analyzer.git)
    cd phishguard-analyzer
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## How to Use

You can analyze an email file directly from the command line.

-   **Analyze a single email file and print the report to the console:**
    ```bash
    python analyzer.py --file "path/to/suspicious_email.eml"
    ```

-   **Analyze an email and save the detailed report as a JSON file:**
    ```bash
    python analyzer.py --file "path/to/suspicious_email.eml" --output report.json
    ```

## Interpreting the Results

The tool will output a risk score and a breakdown of its findings. A higher score indicates a higher likelihood of the email being a phishing attempt. Pay close attention to:

-   **High-Risk URLs**: Links pointing to known malicious domains.
-   **Header Mismatches**: A strong indicator of email spoofing.
-   **Urgent Language**: Keywords designed to manipulate users into acting without thinking.

## Disclaimer

This tool is provided for educational and security analysis purposes. It should be used to analyze emails you are authorized to access. The analysis provides a strong indication of risk but is not a substitute for a comprehensive security solution.

## License

This project is licensed under the MIT License.

