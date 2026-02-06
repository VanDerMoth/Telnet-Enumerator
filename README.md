# Telnet-Enumerator

A GUI-based Telnet port enumeration tool for penetration testing and security assessments.

## Features

- 🖥️ **User-Friendly GUI**: Built with tkinter for easy cross-platform use
- 🔍 **IP Range Scanning**: Scan multiple IPs using CIDR notation (e.g., 192.168.1.0/24)
- 🔒 **Encryption Detection**: Automatically assess Telnet encryption support (RFC 2946)
- 🔐 **NTLM Authentication Extraction**: Extract NTLM authentication details from telnet servers (RFC 2941, MS-TNAP)
- 🔑 **Credential Testing**: Test commonly used default credentials against telnet services
- 📋 **Banner Grabbing**: Capture and display telnet service banners
- ⏱️ **Response Time Measurement**: Track connection response times in milliseconds
- 📊 **Detailed Results**: Comprehensive scan results with timestamps and statistics
- 💾 **Export Functionality**: Save results in CSV, JSON, or TXT format
- 📈 **Progress Tracking**: Real-time progress bar for multi-target scans
- ⚙️ **Configurable Timeout**: Customize connection timeout settings
- 🚀 **Automated Builds**: GitHub Actions workflow builds Linux executables

## Installation

### Requirements

- Python 3.7+
- tkinter (usually included with Python)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/VanDerMoth/Telnet-Enumerator.git
cd Telnet-Enumerator
```

2. Install dependencies (optional, for building executables):
```bash
pip install -r requirements.txt
```

## Usage

### Running from Source

```bash
python3 telnet_enumerator.py
```

### Using the GUI

1. **Enter IP Address**: Type the target IP address or CIDR range
   - Single IP: `192.168.1.1`
   - IP Range: `192.168.1.0/24` (scans all hosts in the subnet)
   
2. **Set Timeout**: Connection timeout in seconds (default: 3)

3. **Enable Scan Options** (Optional):
   - **Extract NTLM Authentication Details**: Attempts to extract NTLM challenge information from the telnet server
   - **Test Common Credentials**: Tests commonly used default credentials (admin/admin, root/root, etc.)
   
   ⚠️ **Warning**: Credential testing may trigger security alerts and IDS/IPS systems

4. **Click Start Scan**: Begin the enumeration

5. **View Results**: Detailed results appear below with:
   - Connection status (Open/Closed/Timeout/Error)
   - Encryption support status (Supported/Not Supported/Unknown)
   - NTLM authentication details (if extracted)
   - Successful credential attempts (if tested)
   - Response time in milliseconds
   - Banner information
   - Timestamp
   - Scan statistics summary

6. **Export Results**: Save your scan results in CSV, JSON, or TXT format

### Example Scans

**Single IP Scan:**
- IP: `192.168.1.100`
- Result: Detailed information about the single host including encryption support

**Multiple IP Scan with NTLM Extraction:**
- IP: `192.168.1.0/24`
- Options: Enable "Extract NTLM Authentication Details"
- Result: Scan all 254 hosts in the subnet with progress tracking, encryption detection, and NTLM info

**Single IP with Credential Testing:**
- IP: `192.168.1.100`
- Options: Enable "Test Common Credentials"
- Result: Test 12 commonly used credentials and report successful logins

### Building Executable

To build a standalone Linux executable:

```bash
pyinstaller --onefile --windowed --name telnet-enumerator telnet_enumerator.py
```

The executable will be created in the `dist/` directory.

## Advanced Features

### NTLM Authentication Extraction

The tool implements NTLM authentication extraction based on:
- RFC 2941 (Telnet Authentication Option)
- Microsoft's MS-TNAP specification

When enabled, the tool attempts to:
- Negotiate NTLM authentication with the server
- Extract NTLM Type 2 Challenge messages
- Parse and display:
  - Target name (domain)
  - Challenge value
  - NTLM flags
  - Version information

### Credential Testing

Tests the following common default credentials:
- admin/admin
- admin/password
- root/root
- root/admin
- admin/1234
- user/user
- guest/guest
- support/support
- admin/(blank)
- root/(blank)
- ubnt/ubnt (Ubiquiti devices)
- pi/raspberry (Raspberry Pi)

The tool attempts to authenticate and reports successful logins with response snippets.

### Export Formats

**CSV Export:**
- Structured data with headers
- Easy to import into spreadsheets or databases
- Includes all scan details including NTLM info and credentials

**JSON Export:**
- Machine-readable format
- Perfect for automation and integration
- Full data structure preservation

**TXT Export:**
- Human-readable format
- Preserves the exact output from the GUI
- Ideal for reports and documentation

### Performance Features

- **Multi-threading**: Scans run in background threads to keep GUI responsive
- **Progress Tracking**: Real-time progress bar shows scan completion
- **Stop Scan**: Ability to cancel long-running scans
- **Response Time Tracking**: Measure and display connection times

## GitHub Actions Workflow

The repository includes an automated build workflow that:
- Triggers on pull requests to main/master branches
- Builds a Linux executable using PyInstaller
- Uploads the executable as a build artifact
- Retains artifacts for 30 days

## Security Notice

This tool is intended for:
- ✅ Authorized security assessments
- ✅ Penetration testing with permission
- ✅ Educational purposes
- ✅ Network administration

**⚠️ Warning**: Only use this tool on systems you own or have explicit permission to test. Unauthorized port scanning and credential testing may be illegal in your jurisdiction and may trigger security alerts.

### Responsible Use

- Always obtain proper authorization before testing
- Be aware that credential testing is noisy and will likely be detected
- NTLM extraction attempts may be logged by security systems
- Use appropriate rate limiting to avoid service disruption
- Follow your organization's security testing policies

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Author

Built with GitHub Copilot
