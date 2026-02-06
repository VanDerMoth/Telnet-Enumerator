# Telnet-Enumerator

A GUI-based Telnet port enumeration tool for penetration testing and security assessments.

## Features

- 🖥️ **User-Friendly GUI**: Built with tkinter for easy cross-platform use
- 🔍 **IP Range Scanning**: Scan multiple IPs using CIDR notation (e.g., 192.168.1.0/24)
- ⚡ **Concurrent Scanning**: Multi-threaded scanning with configurable thread pool (1-50 threads)
- 🥷 **Stealth Mode**: Randomize scan order, source ports, and add jitter to avoid detection
- 🔒 **Encryption Detection**: Automatically assess Telnet encryption support (RFC 2946)
- 🔐 **NTLM Authentication Extraction**: Extract NTLM authentication details from telnet servers (RFC 2941, MS-TNAP)
- 🔑 **Credential Testing**: Test commonly used default credentials against telnet services
- 📄 **File Viewing**: View files on the telnet server when valid credentials are found (useful for lateral movement)
- 🔎 **Auto File Scrubbing**: Automatically discover and enumerate ALL text/image files PLUS common system files when credentials are found
- 📑 **Tabbed Interface**: Separate tabs for scan results and file contents to prevent clutter
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

3. **Set Thread Count**: Number of concurrent connections (default: 10, range: 1-50)
   - Higher values = faster scans but more network noise
   - Lower values = slower scans but more stealthy

4. **Enable Scan Options** (Optional):
   - **Extract NTLM Authentication Details**: Attempts to extract NTLM challenge information from the telnet server
   - **Test Common Credentials**: Tests commonly used default credentials (admin/admin, root/root, etc.)
   - **View Files**: When enabled with credential testing, attempts to view files on the target system when valid credentials are found
     - **Auto-scrub common files**: Automatically discovers ALL text/image files PLUS common system files (up to 100 total files)
     - **Custom files**: Specify your own comma-separated list of files to view
   
   ⚠️ **Warning**: Credential testing may trigger security alerts and IDS/IPS systems

5. **Enable Stealth Options** (Optional - Less Detectable):
   - **Randomize Scan Order & Source Ports**: Randomizes the order of IP scanning and uses random source ports to avoid pattern detection
   - **Add Random Delays (Jitter)**: Adds random delays (0.5-2.0 seconds) between connection attempts to avoid rate-based detection
   
   ℹ️ **Note**: Stealth options significantly reduce detection by IDS/IPS but will slow down scans

6. **Click Start Scan**: Begin the enumeration

7. **View Results**: Results are displayed in two tabs:
   - **Main Results Tab**: Shows scan results with connection status, encryption support, NTLM details, successful credentials, and file view summaries
   - **Files Viewed Tab**: Shows complete contents of all files retrieved from targets (when credentials are found)
   
   Main results include:
   - Connection status (Open/Closed/Timeout/Error)
   - Encryption support status (Supported/Not Supported/Unknown)
   - NTLM authentication details (if extracted)
   - Successful credential attempts (if tested)
   - File view summary with count (full content in Files Viewed tab)
   - Response time in milliseconds
   - Banner information
   - Timestamp
   - Scan statistics summary

8. **Export Results**: Save your scan results in CSV, JSON, or TXT format

### Example Scans

**Fast Concurrent Scan:**
- IP: `192.168.1.0/24`
- Threads: `20`
- Result: Rapidly scan all 254 hosts in the subnet using 20 concurrent connections

**Stealth Scan (Low Detection):**
- IP: `192.168.1.0/24`
- Threads: `5`
- Options: Enable "Randomize Scan Order & Source Ports" and "Add Random Delays (Jitter)"
- Result: Slower but much less detectable scan with randomized order and timing

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

**Credential Testing with File Viewing:**
- IP: `192.168.1.100`
- Options: Enable "Test Common Credentials" and "View Files"
- Files: `/etc/passwd,/etc/hosts`
- Result: Test credentials and automatically view specified files when valid credentials are found
- Use Case: Quickly gather system information for lateral movement analysis

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

### File Viewing and Auto-Scrubbing for Lateral Movement

When valid credentials are discovered during credential testing, the tool can automatically attempt to view files on the target system. This feature is valuable for:
- **Lateral Movement**: Quickly assess accessible information after gaining credentials
- **Reconnaissance**: Identify system configuration and sensitive data
- **Privilege Assessment**: Determine what files the compromised credentials can access

**Configuration Options:**
1. **Manual File Selection** (Default):
   - Enable "View Files" checkbox (requires "Test Common Credentials" to be enabled)
   - Specify file paths to view in the input field (comma-separated)
   - Default paths include: `/etc/passwd`, `/etc/hosts`
   - Common useful paths:
     - Linux: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys`
     - Windows: `C:\Windows\System32\drivers\etc\hosts`, `C:\Users\Administrator\Desktop\*`

2. **Auto-Scrub Mode** (NEW):
   - Enable "View Files" and "Auto-scrub common files" checkboxes
   - Automatically attempts to read ALL discovered text/image files PLUS common system files (up to 100 total files)
   - **System files included** (62 files):
     - Linux: `/etc/passwd`, `/etc/hosts`, `/etc/hostname`, `/etc/issue`, `/etc/os-release`, `/proc/version`, `/proc/cpuinfo`, `/etc/ssh/sshd_config`, `/etc/network/interfaces`, `/root/.ssh/authorized_keys`, `/root/.bash_history`, plus CTF files
     - Windows: `C:\Windows\System32\drivers\etc\hosts`, `C:\Windows\win.ini`, `C:\boot.ini`, plus CTF files
   - **Dynamic file discovery**:
     - Text files: `.txt`, `.log`, `.conf`, `.config`, `.md`, `.csv`, `.json`, `.xml`, `.yaml`, `.yml`, `.ini`, `.sh`, `.bat`, `.ps1`
     - Image files: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tif`, `.tiff`, `.svg`
   - **Discovery process**:
     - Linux: Uses `find` commands to search common directories (`/root`, `/home`, `/tmp`, `/var`, `/opt`, `/etc`)
     - Windows: Uses `dir` commands to search user directories and Desktop folders
     - Searches for files under 10MB in size
     - Combines discovered files with known system files for comprehensive coverage
     - Limits total results to 100 files to prevent overwhelming output
   - Ideal for CTF scenarios and thorough reconnaissance where you want maximum file coverage

**How it works:**
1. When credentials successfully authenticate, the tool maintains the telnet session
2. Attempts to read specified or common files using standard commands (`cat`, `type`, `more`)
3. Captures file contents (up to 2000 characters per file)
4. Main Results tab shows file count summary
5. Files Viewed tab displays complete file contents with metadata (IP, credentials, timestamp, file path)
6. Reports errors if files cannot be read (permissions, non-existent, etc.)

**Display:**
- **Main Results Tab**: Shows credential success and file view summary (e.g., "3/5 files successfully read")
- **Files Viewed Tab**: Dedicated tab showing all file contents in detail, preventing clutter in main results

⚠️ **Warning**: File viewing is intrusive and will generate logs on the target system. Use only in authorized penetration testing scenarios.

### Export Formats

**CSV Export:**
- Structured data with headers
- Easy to import into spreadsheets or databases
- Includes all scan details including NTLM info, credentials, and viewed files

**JSON Export:**
- Machine-readable format
- Perfect for automation and integration
- Full data structure preservation including file contents

**TXT Export:**
- Human-readable format
- Preserves the exact output from the GUI
- Ideal for reports and documentation

### Performance & Stealth Features

#### Speed Improvements
- **Concurrent Scanning**: Uses ThreadPoolExecutor for parallel IP scanning (configurable 1-50 threads)
- **Optimized Timeouts**: Reduced internal delays for faster credential testing and NTLM extraction
- **Efficient Socket Handling**: Improved connection management and resource usage
- **Multi-threading**: Scans run in background threads to keep GUI responsive
- **Progress Tracking**: Real-time progress bar shows scan completion
- **Stop Scan**: Ability to cancel long-running scans
- **Response Time Tracking**: Measure and display connection times

#### Stealth Features (Reduced Detectability)
- **Randomized Scan Order**: Shuffle IP addresses to avoid sequential scanning patterns
- **Source Port Randomization**: Use random high ports (10000-65000) to avoid fingerprinting
- **Jitter/Random Delays**: Add random delays (0.5-2.0 sec) between connections to avoid rate-based detection
- **Rate Limiting**: Control scan speed with thread count to avoid triggering IDS/IPS alerts
- **Configurable Timing**: Adjust timeouts and delays to match normal traffic patterns

#### Stealth Recommendations
- Use 5 or fewer threads for maximum stealth
- Enable both randomization and jitter options
- Increase timeout values to 5+ seconds for more natural timing
- Avoid credential testing on production systems (very noisy)
- Consider scanning during peak hours when legitimate traffic is higher

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

**⚠️ Warning**: Only use this tool on systems you own or have explicit permission to test. Unauthorized port scanning, credential testing, and file access may be illegal in your jurisdiction and may trigger security alerts.

### Responsible Use

- Always obtain proper authorization before testing
- Be aware that credential testing is noisy and will likely be detected
- File viewing operations are logged and highly intrusive - use only in authorized scenarios
- NTLM extraction attempts may be logged by security systems
- Use appropriate rate limiting to avoid service disruption
- Follow your organization's security testing policies

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Author

Built with GitHub Copilot
