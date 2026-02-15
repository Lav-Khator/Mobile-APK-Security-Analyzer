# APK Armor - Attack on Anomalies (Python-Native)

A robust and efficient APK security scanner built entirely in Python. It is a static analysis security tool that evaluates Android APK files and reports structured security findings.

Note: Testing large apk files on deployed website may not be possible due to Render's limitation, in that case, using localhost is preferable.

## Key Features

- **No Java Required**: Uses `androguard` for pure Python APK analysis.
- **OWASP Mobile Top 10**: Scans for vulnerabilities mapped to 2024 standards.
- **Detects**:
    - **M1**: Hardcoded Secrets (AWS, Google, OAuth, etc.)
    - **M1**: Sensitive Logging (`Log.d`, `System.out`)
    - **M5**: Insecure Communication (HTTP, FTP)
    - **M8**: Insecure Manifest configurations (Exported components, Debuggable)
    - **M10**: Weak Cryptography (DES, MD5, RC4, ECB mode)
- **Reporting**: Generates JSON, Text, and PDF reports.
- **Web Interface**: Simple Flask-based GUI for drag-and-drop scanning.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Lav-Khator/Mobile-APK-Security-Analyzer
   cd Mobile-APK-Security-Analyzer
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   .\venv\Scripts\Activate.ps1  # Windows
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface (CLI)

Run the scanner on an APK file:

```bash
# Add the path for the APK file wherever necessary
# Basic scan (JSON report by default)
python APKScanner/apk_scanner.py -apk path/to/app.apk

# Generate Text Report
python APKScanner/apk_scanner.py -apk path/to/app.apk -report txt

# Generate PDF Report
python APKScanner/apk_scanner.py -apk path/to/app.apk -report pdf

# Specify Output Directory
python APKScanner/apk_scanner.py -apk app.apk -o results/
```

### Web Interface

Start the web GUI:

```bash
python web/app.py
```

Then open your browser at [http://localhost:5000](http://localhost:5000).

## Project Structure

- `APKScanner/apk_scanner.py`: Main CLI tool.
- `APKScanner/core/`: Scanning modules (Manifest, Network, Secrets, Crypto, Logging).
- `web/`: Flask web application.

