# Telnet-Enumerator

A GUI-based Telnet port enumeration tool for penetration testing and security assessments.

## Features

- 🖥️ **User-Friendly GUI**: Built with tkinter for easy cross-platform use
- 🔍 **Port Scanning**: Enumerate telnet services on any IP address
- 📋 **Banner Grabbing**: Capture and display service banners
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

1. **Enter IP Address**: Type the target IP address (e.g., 192.168.1.1)
2. **Set Port**: Default is 23 (standard telnet port)
3. **Set Timeout**: Connection timeout in seconds (default: 3)
4. **Click Scan**: Start the enumeration
5. **View Results**: Results appear in the text area below

### Building Executable

To build a standalone Linux executable:

```bash
pyinstaller --onefile --windowed --name telnet-enumerator telnet_enumerator.py
```

The executable will be created in the `dist/` directory.

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
