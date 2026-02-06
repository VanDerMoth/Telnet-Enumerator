# Telnet-Enumerator

A GUI-based Telnet port enumeration tool for penetration testing and security assessments.

## Features

- 🖥️ **User-Friendly GUI**: Built with tkinter for easy cross-platform use
- 🔍 **IP Range Scanning**: Scan multiple IPs using CIDR notation (e.g., 192.168.1.0/24)
- 📋 **Banner Grabbing**: Capture and display telnet service banners
- ⏱️ **Response Time Measurement**: Track connection response times in milliseconds
- 📊 **Detailed Results**: Comprehensive scan results with timestamps and statistics
- 💾 **Export Functionality**: Save results in CSV, JSON, or TXT format
- 📈 **Progress Tracking**: Real-time progress bar for multi-target scans
- ⚙️ **Configurable**: Customize port and timeout settings
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
   
2. **Set Port**: Default is 23 (standard telnet port), but can be changed to scan other services

3. **Set Timeout**: Connection timeout in seconds (default: 3)

4. **Click Start Scan**: Begin the enumeration

5. **View Results**: Detailed results appear below with:
   - Connection status (Open/Closed/Timeout/Error)
   - Response time in milliseconds
   - Banner information
   - Timestamp
   - Scan statistics summary

6. **Export Results**: Save your scan results in CSV, JSON, or TXT format

### Example Scans

**Single IP Scan:**
- IP: `192.168.1.100`
- Port: `23`
- Result: Detailed information about the single host

**Multiple IP Scan:**
- IP: `192.168.1.0/24`
- Port: `23`
- Result: Scan all 254 hosts in the subnet with progress tracking

### Building Executable

To build a standalone Linux executable:

```bash
pyinstaller --onefile --windowed --name telnet-enumerator telnet_enumerator.py
```

The executable will be created in the `dist/` directory.

## Advanced Features

### Export Formats

**CSV Export:**
- Structured data with headers
- Easy to import into spreadsheets or databases
- Includes all scan details

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

**⚠️ Warning**: Only use this tool on systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Author

Built with GitHub Copilot
