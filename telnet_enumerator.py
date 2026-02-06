#!/usr/bin/env python3
"""
Telnet Enumerator - A GUI tool for enumerating telnet ports
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from typing import Optional, List, Dict, Tuple
import queue
import time
import json
import csv
from datetime import datetime
import ipaddress
import base64
import struct
import random
from concurrent.futures import ThreadPoolExecutor, as_completed


class TelnetEnumerator:
    """Main class for telnet port enumeration"""
    
    # Common default credentials for telnet services
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('root', 'admin'),
        ('admin', '1234'),
        ('user', 'user'),
        ('guest', 'guest'),
        ('support', 'support'),
        ('admin', ''),
        ('root', ''),
        ('ubnt', 'ubnt'),
        ('pi', 'raspberry'),
    ]
    
    def __init__(self):
        self.default_port = 23
        self.timeout = 3
        self.encryption_check_delay = 0.5  # Delay in seconds for encryption response
        self.max_workers = 10  # Default thread pool size for concurrent scanning
        self.jitter_min = 0.0  # Minimum delay between scans (seconds)
        self.jitter_max = 0.0  # Maximum delay between scans (seconds)
        self.randomize_order = False  # Whether to randomize scan order
        self.randomize_source_port = False  # Whether to randomize source port for stealth
    
    def _check_encryption_support(self, sock: socket.socket) -> str:
        """
        Check if the Telnet server supports encryption
        
        Telnet encryption is negotiated using Telnet options as defined in:
        - RFC 2946: Telnet Data Encryption Option
        - RFC 854: Telnet Protocol Specification
        
        Args:
            sock: Active socket connection to the telnet server
            
        Returns:
            str: 'supported', 'not_supported', or 'unknown'
        """
        try:
            # Telnet protocol constants
            IAC = b'\xff'   # Interpret As Command
            DO = b'\xfd'    # Request the other party to perform an option
            DONT = b'\xfe'  # Request the other party not to perform an option
            WILL = b'\xfb'  # Indicates willingness to perform an option
            WONT = b'\xfc'  # Indicates refusal to perform an option
            SB = b'\xfa'    # Subnegotiation begin
            SE = b'\xf0'    # Subnegotiation end
            
            # Telnet option codes
            ENCRYPT = b'\x26'  # Encryption option (38 decimal)
            
            # Set a short timeout for this operation
            sock.settimeout(2)
            
            # First, receive any initial data/options from server
            try:
                initial_data = sock.recv(1024)
            except socket.timeout:
                initial_data = b''
            
            # Send IAC DO ENCRYPT to ask if server supports encryption
            encryption_query = IAC + DO + ENCRYPT
            sock.send(encryption_query)
            
            # Wait for response
            time.sleep(self.encryption_check_delay)
            response = sock.recv(1024)
            
            # Parse the response for encryption support
            if IAC + WILL + ENCRYPT in response:
                return 'supported'
            elif IAC + WONT + ENCRYPT in response:
                return 'not_supported'
            else:
                # Check if the server sent any encryption-related subnegotiation
                if ENCRYPT in response and SB in response:
                    return 'supported'
                # If no clear response, return unknown
                return 'unknown'
                
        except socket.timeout:
            return 'unknown'
        except Exception:
            return 'unknown'
    
    def _extract_ntlm_info(self, sock: socket.socket) -> Optional[Dict]:
        """
        Attempt to extract NTLM authentication information from telnet server
        
        Based on RFC 2941 (Telnet Authentication Option) and MS-TNAP specification.
        
        Args:
            sock: Active socket connection to the telnet server
            
        Returns:
            dict with NTLM information or None if not available
        """
        try:
            # Telnet protocol constants
            IAC = b'\xff'
            WILL = b'\xfb'
            DO = b'\xfd'
            DONT = b'\xfe'
            WONT = b'\xfc'
            SB = b'\xfa'
            SE = b'\xf0'
            
            # Authentication option (37 decimal, 0x25 hex)
            AUTH = b'\x25'
            
            sock.settimeout(5)
            
            # Receive initial banner/negotiation
            try:
                initial_data = sock.recv(4096)
            except socket.timeout:
                initial_data = b''
            
            # Send WILL AUTHENTICATION to indicate we want to authenticate
            auth_will = IAC + WILL + AUTH
            sock.send(auth_will)
            
            time.sleep(0.3)  # Reduced from 0.5 for speed
            
            # Receive server's response
            try:
                response = sock.recv(4096)
            except socket.timeout:
                return None
            
            # Look for authentication subnegotiation
            if IAC + SB + AUTH in response:
                # Extract NTLM challenge if present
                return self._parse_ntlm_challenge(response)
            
            return None
            
        except Exception:
            return None
    
    def _parse_ntlm_challenge(self, data: bytes) -> Optional[Dict]:
        """
        Parse NTLM challenge from telnet authentication data
        
        Args:
            data: Raw bytes from telnet authentication negotiation
            
        Returns:
            dict with parsed NTLM information or None
        """
        try:
            ntlm_info = {}
            
            # Look for NTLM signature "NTLMSSP"
            ntlm_sig = b'NTLMSSP\x00'
            if ntlm_sig in data:
                ntlm_offset = data.index(ntlm_sig)
                ntlm_data = data[ntlm_offset:]
                
                # Parse message type (should be 0x02000000 for Type 2 Challenge)
                if len(ntlm_data) >= 12:
                    msg_type = struct.unpack('<I', ntlm_data[8:12])[0]
                    
                    if msg_type == 2:  # Type 2 Challenge Message
                        ntlm_info['message_type'] = 'NTLM_CHALLENGE'
                        
                        # Extract target name (domain) if available
                        if len(ntlm_data) >= 20:
                            target_name_len = struct.unpack('<H', ntlm_data[12:14])[0]
                            target_name_offset = struct.unpack('<I', ntlm_data[16:20])[0]
                            
                            if len(ntlm_data) >= target_name_offset + target_name_len:
                                try:
                                    target_name = ntlm_data[target_name_offset:target_name_offset + target_name_len].decode('utf-16-le', errors='ignore')
                                    if target_name:
                                        ntlm_info['target_name'] = target_name
                                except (UnicodeDecodeError, AttributeError):
                                    pass
                        
                        # Extract challenge (8 bytes at offset 24)
                        if len(ntlm_data) >= 32:
                            challenge = ntlm_data[24:32]
                            ntlm_info['challenge'] = base64.b64encode(challenge).decode('ascii')
                        
                        # Extract flags if available
                        if len(ntlm_data) >= 24:
                            flags = struct.unpack('<I', ntlm_data[20:24])[0]
                            ntlm_info['flags'] = hex(flags)
                        
                        # Try to extract version information if available (offset 48)
                        if len(ntlm_data) >= 56:
                            try:
                                version_data = ntlm_data[48:56]
                                major = version_data[0]
                                minor = version_data[1]
                                build = struct.unpack('<H', version_data[2:4])[0]
                                ntlm_info['version'] = f"{major}.{minor}.{build}"
                            except (struct.error, IndexError):
                                pass
                        
                        return ntlm_info
            
            return None
            
        except (struct.error, IndexError, ValueError):
            return None
    
    def _test_credentials(self, ip_address: str, port: int, credentials: List[Tuple[str, str]]) -> List[Dict]:
        """
        Test a list of credentials against the telnet server
        
        Args:
            ip_address: Target IP address
            port: Target port
            credentials: List of (username, password) tuples to test
            
        Returns:
            List of successful login attempts with details
        """
        successful_logins = []
        
        for username, password in credentials:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                connection_result = sock.connect_ex((ip_address, port))
                
                if connection_result == 0:
                    # Wait for initial banner/prompt
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError):
                        banner = ""
                    
                    # Send username
                    sock.send((username + '\r\n').encode('utf-8'))
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    
                    try:
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError):
                        response = ""
                    
                    # Send password
                    sock.send((password + '\r\n').encode('utf-8'))
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    
                    try:
                        final_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError):
                        final_response = ""
                    
                    # Check for successful login indicators
                    # Common success indicators in responses
                    success_indicators = [
                        'welcome', 'logged in', 'login successful', 
                        '$', '#', '>', 'shell', 'prompt', 'success'
                    ]
                    
                    # Common failure indicators
                    failure_indicators = [
                        'incorrect', 'failed', 'denied', 'invalid',
                        'login failed', 'authentication failed', 'bad password'
                    ]
                    
                    response_lower = (response + final_response).lower()
                    
                    has_success = any(indicator in response_lower for indicator in success_indicators)
                    has_failure = any(indicator in response_lower for indicator in failure_indicators)
                    
                    # If we see success indicators and no failure indicators, consider it successful
                    if has_success and not has_failure:
                        successful_logins.append({
                            'username': username,
                            'password': password,
                            'response': (response + final_response).strip()[:200]  # Limit response length
                        })
                
                sock.close()
                
            except (socket.error, OSError):
                # Network errors are expected during credential testing
                pass
            
            # Small delay between attempts to avoid overwhelming the server
            # Only add delay if jitter is not configured (avoid double delays)
            if self.jitter_max == 0:
                time.sleep(0.1)  # Reduced from 0.2 for speed
        
        return successful_logins
    
    def check_telnet(self, ip_address: str, port: int = 23, extract_ntlm: bool = False, test_credentials: bool = False) -> dict:
        """
        Check if telnet port is open on the specified IP address
        
        Args:
            ip_address: Target IP address
            port: Port to check (default 23 for telnet)
            extract_ntlm: Whether to attempt NTLM authentication extraction
            test_credentials: Whether to test common credentials
            
        Returns:
            dict with status, banner, error, timing information, encryption support, NTLM info, and credential test results
        """
        # Apply jitter/delay if configured
        if self.jitter_max > 0:
            delay = random.uniform(self.jitter_min, self.jitter_max)
            time.sleep(delay)
        
        result = {
            'ip': ip_address,
            'port': port,
            'status': 'closed',
            'banner': None,
            'error': None,
            'response_time': None,
            'encryption_support': None,
            'ntlm_info': None,
            'credential_results': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Create socket connection with source port randomization for stealth
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Randomize source port for stealth (bind to random high port)
            if self.randomize_source_port:
                try:
                    random_port = random.randint(10000, 65000)
                    # Bind to loopback or any interface depending on target IP
                    # For client sockets, binding to '' (any interface) is standard practice
                    # as we're making outbound connections, not listening for inbound
                    sock.bind(('0.0.0.0', random_port))
                except (OSError, socket.error):
                    # If binding fails, proceed without source port randomization
                    pass
            
            sock.settimeout(self.timeout)
            
            # Measure connection time
            start_time = time.time()
            connection_result = sock.connect_ex((ip_address, port))
            connect_time = time.time() - start_time
            
            if connection_result == 0:
                result['status'] = 'open'
                result['response_time'] = round(connect_time * 1000, 2)  # Convert to milliseconds
                
                # Check for encryption support
                try:
                    result['encryption_support'] = self._check_encryption_support(sock)
                except Exception as e:
                    # Don't fail the entire check if encryption detection fails
                    result['error'] = f"Encryption check failed: {str(e)}"
                
                # Try to grab banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner
                except Exception as e:
                    if result['error']:
                        result['error'] += f"; Banner grab failed: {str(e)}"
                    else:
                        result['error'] = f"Banner grab failed: {str(e)}"
            else:
                result['response_time'] = round(connect_time * 1000, 2)
            
            sock.close()
            
            # Attempt NTLM extraction if requested and port is open
            if extract_ntlm and result['status'] == 'open':
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip_address, port))
                    ntlm_info = self._extract_ntlm_info(sock)
                    if ntlm_info:
                        result['ntlm_info'] = ntlm_info
                    sock.close()
                except Exception as e:
                    if result['error']:
                        result['error'] += f"; NTLM extraction failed: {str(e)}"
                    else:
                        result['error'] = f"NTLM extraction failed: {str(e)}"
            
            # Test credentials if requested and port is open
            if test_credentials and result['status'] == 'open':
                try:
                    credential_results = self._test_credentials(ip_address, port, self.DEFAULT_CREDENTIALS)
                    if credential_results:
                        result['credential_results'] = credential_results
                except Exception as e:
                    if result['error']:
                        result['error'] += f"; Credential testing failed: {str(e)}"
                    else:
                        result['error'] = f"Credential testing failed: {str(e)}"
            
        except socket.timeout:
            result['status'] = 'timeout'
            result['error'] = 'Connection timeout'
        except socket.gaierror:
            result['status'] = 'error'
            result['error'] = 'Invalid IP address or hostname'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result


class TelnetEnumeratorGUI:
    """GUI interface for Telnet Enumerator"""
    
    # Constants
    MAX_BANNER_LINES = 10
    WINDOW_HEIGHT = 750
    
    def __init__(self, root):
        self.root = root
        self.root.title("Telnet Enumerator - Advanced Edition")
        self.root.geometry(f"900x{self.WINDOW_HEIGHT}")
        self.root.resizable(True, True)
        
        self.enumerator = TelnetEnumerator()
        self.scan_thread = None
        self.result_queue = queue.Queue()
        self.scan_results = []  # Store all scan results
        self.is_scanning = False
        
        # Options for scanning
        self.extract_ntlm_var = tk.BooleanVar(value=False)
        self.test_credentials_var = tk.BooleanVar(value=False)
        self.randomize_order_var = tk.BooleanVar(value=False)
        self.use_jitter_var = tk.BooleanVar(value=False)
        
        self.setup_ui()
        self.check_queue()
    
    def setup_ui(self):
        """Setup the GUI components"""
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Telnet Port Enumerator - Advanced Edition", 
                               font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # IP Address input
        ttk.Label(main_frame, text="IP Address/CIDR:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(main_frame, width=30)
        self.ip_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")
        ttk.Label(main_frame, text="(e.g., 192.168.1.0/24 or single IP)", font=('Helvetica', 8)).grid(row=1, column=2, sticky=tk.W)
        
        # Timeout input
        ttk.Label(main_frame, text="Timeout (sec):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.timeout_entry = ttk.Entry(main_frame, width=30)
        self.timeout_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.timeout_entry.insert(0, "3")
        
        # Thread count input
        ttk.Label(main_frame, text="Threads:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.threads_entry = ttk.Entry(main_frame, width=30)
        self.threads_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.threads_entry.insert(0, "10")
        ttk.Label(main_frame, text="(concurrent connections, 1-50)", font=('Helvetica', 8)).grid(row=3, column=2, sticky=tk.W)
        
        # Options frame for checkboxes
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10, padx=5)
        
        self.extract_ntlm_checkbox = ttk.Checkbutton(
            options_frame, 
            text="Extract NTLM Authentication Details",
            variable=self.extract_ntlm_var
        )
        self.extract_ntlm_checkbox.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.test_credentials_checkbox = ttk.Checkbutton(
            options_frame,
            text="Test Common Credentials",
            variable=self.test_credentials_var
        )
        self.test_credentials_checkbox.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        ttk.Label(options_frame, text="⚠️ Credential testing may trigger security alerts", 
                 font=('Helvetica', 8), foreground='orange').grid(row=2, column=0, sticky=tk.W, pady=2)
        
        # Stealth options
        stealth_frame = ttk.LabelFrame(main_frame, text="Stealth Options (Less Detectable)", padding="10")
        stealth_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10, padx=5)
        
        self.randomize_checkbox = ttk.Checkbutton(
            stealth_frame,
            text="Randomize Scan Order & Source Ports",
            variable=self.randomize_order_var
        )
        self.randomize_checkbox.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.jitter_checkbox = ttk.Checkbutton(
            stealth_frame,
            text="Add Random Delays (Jitter: 0.5-2.0 sec)",
            variable=self.use_jitter_var
        )
        self.jitter_checkbox.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        ttk.Label(stealth_frame, text="ℹ️ Stealth options reduce detection but slow down scans", 
                 font=('Helvetica', 8), foreground='blue').grid(row=2, column=0, sticky=tk.W, pady=2)
        
        # Progress bar
        ttk.Label(main_frame, text="Progress:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.progress_bar = ttk.Progressbar(main_frame, mode='determinate')
        self.progress_bar.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.progress_label = ttk.Label(main_frame, text="0/0")
        self.progress_label.grid(row=6, column=2, sticky=tk.W, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=2, padx=5)
        
        self.export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        self.export_button.grid(row=0, column=3, padx=5)
        
        # Results text area
        ttk.Label(main_frame, text="Results:").grid(row=8, column=0, sticky=(tk.W, tk.N), pady=5)
        
        self.results_text = scrolledtext.ScrolledText(main_frame, width=90, height=25, 
                                                      wrap=tk.WORD, font=('Courier', 9))
        self.results_text.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), 
                              pady=5, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
    
    def validate_inputs(self) -> tuple:
        """Validate user inputs"""
        ip_address = self.ip_entry.get().strip()
        
        if not ip_address:
            return False, "IP address is required"
        
        try:
            timeout = float(self.timeout_entry.get().strip())
            if timeout <= 0:
                return False, "Timeout must be greater than 0"
            if timeout > 60:
                return False, "Timeout must be 60 seconds or less"
        except ValueError:
            return False, "Timeout must be a valid number"
        
        try:
            threads = int(self.threads_entry.get().strip())
            if threads < 1:
                return False, "Thread count must be at least 1"
            if threads > 50:
                return False, "Thread count must be 50 or less"
        except ValueError:
            return False, "Thread count must be a valid integer"
        
        return True, None
    
    def start_scan(self):
        """Start the telnet enumeration scan"""
        valid, error = self.validate_inputs()
        
        if not valid:
            self.append_result(f"Error: {error}\n")
            return
        
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running")
            return
        
        # Disable scan button during scan
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.is_scanning = True
        self.status_var.set("Scanning...")
        self.scan_results = []  # Clear previous results
        
        # Get values
        ip_address = self.ip_entry.get().strip()
        port = 23  # Hardcoded for telnet
        timeout = float(self.timeout_entry.get().strip())
        threads = int(self.threads_entry.get().strip())
        
        # Update enumerator timeout
        self.enumerator.timeout = timeout
        self.enumerator.max_workers = threads
        
        # Get scan options
        extract_ntlm = self.extract_ntlm_var.get()
        test_credentials = self.test_credentials_var.get()
        
        # Get stealth options
        randomize_order = self.randomize_order_var.get()
        use_jitter = self.use_jitter_var.get()
        
        # Configure stealth settings
        self.enumerator.randomize_order = randomize_order
        self.enumerator.randomize_source_port = randomize_order  # Use same control for both
        if use_jitter:
            self.enumerator.jitter_min = 0.5
            self.enumerator.jitter_max = 2.0
        else:
            self.enumerator.jitter_min = 0.0
            self.enumerator.jitter_max = 0.0
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(ip_address, port, extract_ntlm, test_credentials),
            daemon=True
        )
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.status_var.set("Scan stopped by user")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def run_scan(self, ip_address: str, port: int, extract_ntlm: bool, test_credentials: bool):
        """Run the scan in a separate thread with concurrent execution"""
        try:
            results = []
            total_scans = 0
            completed_scans = 0
            
            # Check if it's a CIDR range or single IP
            is_cidr = '/' in ip_address
            
            # Prepare list of IPs to scan
            ips_to_scan = []
            
            if is_cidr:
                # IP range scanning with CIDR
                try:
                    network = ipaddress.ip_network(ip_address, strict=False)
                    # Handle different network sizes including /31 and /32
                    ips_to_scan = [str(ip) for ip in network.hosts()]
                    if not ips_to_scan:  # Handle /31 and /32
                        ips_to_scan = [str(ip) for ip in network]
                except ValueError as e:
                    # Invalid CIDR notation, treat as single IP
                    ips_to_scan = [ip_address]
            else:
                # Single IP scan
                ips_to_scan = [ip_address]
            
            # Randomize order if stealth mode is enabled
            if self.enumerator.randomize_order:
                random.shuffle(ips_to_scan)
            
            total_scans = len(ips_to_scan)
            self.result_queue.put(('progress', 0, total_scans))
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.enumerator.max_workers) as executor:
                # Submit all scan tasks
                future_to_ip = {
                    executor.submit(
                        self.enumerator.check_telnet, 
                        ip, port, extract_ntlm, test_credentials
                    ): ip 
                    for ip in ips_to_scan
                }
                
                # Process completed scans as they finish
                for future in as_completed(future_to_ip):
                    if not self.is_scanning:
                        # Cancel remaining tasks if scan is stopped
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    try:
                        result = future.result()
                        results.append(result)
                        completed_scans += 1
                        self.result_queue.put(('progress', completed_scans, total_scans))
                    except Exception as e:
                        # Log error but continue with other scans
                        ip = future_to_ip[future]
                        error_result = {
                            'ip': ip,
                            'port': port,
                            'status': 'error',
                            'banner': None,
                            'error': str(e),
                            'response_time': None,
                            'encryption_support': None,
                            'ntlm_info': None,
                            'credential_results': None,
                            'timestamp': datetime.now().isoformat()
                        }
                        results.append(error_result)
                        completed_scans += 1
                        self.result_queue.put(('progress', completed_scans, total_scans))
            
            # Send results
            self.result_queue.put(('results', results))
            
        except Exception as e:
            self.result_queue.put(('error', str(e)))
    
    def check_queue(self):
        """Check the result queue for updates"""
        try:
            while True:
                msg_type, *data = self.result_queue.get_nowait()
                
                if msg_type == 'progress':
                    completed, total = data
                    self.progress_bar['maximum'] = total
                    self.progress_bar['value'] = completed
                    self.progress_label.config(text=f"{completed}/{total}")
                    
                elif msg_type == 'results':
                    results = data[0]
                    self.scan_results.extend(results)
                    self.display_results(results)
                    self.scan_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.is_scanning = False
                    self.status_var.set(f"Scan complete - {len(results)} target(s) scanned")
                    
                elif msg_type == 'error':
                    self.append_result(f"Error: {data[0]}\n")
                    self.scan_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.is_scanning = False
                    self.status_var.set("Error occurred")
                
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_queue)
    
    def display_results(self, results: List[dict]):
        """Display scan results with detailed information"""
        # Summary header
        total = len(results)
        open_count = sum(1 for r in results if r['status'] == 'open')
        closed_count = sum(1 for r in results if r['status'] == 'closed')
        timeout_count = sum(1 for r in results if r['status'] == 'timeout')
        error_count = sum(1 for r in results if r['status'] == 'error')
        
        output = []
        output.append("\n" + "=" * 80)
        output.append("TELNET ENUMERATION SCAN RESULTS")
        output.append("=" * 80)
        output.append(f"Scan Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Total Targets:  {total}")
        output.append(f"Open Ports:     {open_count}")
        output.append(f"Closed Ports:   {closed_count}")
        output.append(f"Timeouts:       {timeout_count}")
        output.append(f"Errors:         {error_count}")
        output.append("=" * 80)
        output.append("")
        
        # Detailed results
        for idx, result in enumerate(results, 1):
            output.append(f"\n[Target {idx}/{total}]")
            output.append("-" * 80)
            output.append(f"IP Address:      {result['ip']}")
            output.append(f"Port:            {result['port']}")
            output.append(f"Status:          {result['status'].upper()}")
            output.append(f"Timestamp:       {result['timestamp']}")
            
            if result['response_time'] is not None:
                output.append(f"Response Time:   {result['response_time']} ms")
            
            # Display encryption support information
            if result.get('encryption_support'):
                enc_status = result['encryption_support']
                if enc_status == 'supported':
                    output.append(f"Encryption:      🔒 SUPPORTED")
                elif enc_status == 'not_supported':
                    output.append(f"Encryption:      ⚠️ NOT SUPPORTED")
                else:
                    output.append(f"Encryption:      ❓ UNKNOWN")
            
            # Display NTLM information if available
            if result.get('ntlm_info'):
                output.append("\n🔐 NTLM Authentication Details:")
                output.append("." * 80)
                ntlm_info = result['ntlm_info']
                
                if ntlm_info.get('message_type'):
                    output.append(f"  Message Type:    {ntlm_info['message_type']}")
                if ntlm_info.get('target_name'):
                    output.append(f"  Target Name:     {ntlm_info['target_name']}")
                if ntlm_info.get('challenge'):
                    output.append(f"  Challenge:       {ntlm_info['challenge']}")
                if ntlm_info.get('flags'):
                    output.append(f"  Flags:           {ntlm_info['flags']}")
                if ntlm_info.get('version'):
                    output.append(f"  Version:         {ntlm_info['version']}")
                
                output.append("." * 80)
            
            # Display credential test results if available
            if result.get('credential_results'):
                output.append("\n✅ SUCCESSFUL CREDENTIAL TESTS:")
                output.append("." * 80)
                for cred in result['credential_results']:
                    output.append(f"  Username:        {cred['username']}")
                    output.append(f"  Password:        {cred['password']}")
                    if cred.get('response'):
                        output.append(f"  Response:        {cred['response'][:100]}...")
                    output.append("  " + "-" * 76)
                output.append("." * 80)
            
            if result['status'] == 'open':
                output.append("")
                output.append("✓ PORT IS OPEN")
                
                if result['banner']:
                    output.append("\nBanner Information:")
                    output.append("." * 80)
                    # Split banner into lines for better display
                    banner_lines = result['banner'].split('\n')
                    for line in banner_lines[:self.MAX_BANNER_LINES]:
                        output.append(f"  {line}")
                    if len(banner_lines) > self.MAX_BANNER_LINES:
                        output.append(f"  ... ({len(banner_lines) - self.MAX_BANNER_LINES} more lines)")
                    output.append("." * 80)
                else:
                    output.append("\nNo banner received (service may not send initial banner)")
                    
            elif result['status'] == 'closed':
                output.append("\n✗ PORT IS CLOSED")
            elif result['status'] == 'timeout':
                output.append("\n⚠ CONNECTION TIMED OUT")
            elif result['status'] == 'error':
                output.append(f"\n✗ ERROR OCCURRED")
            
            if result['error']:
                output.append(f"\nError Details: {result['error']}")
            
            output.append("-" * 80)
        
        output.append("\n" + "=" * 80)
        output.append(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("=" * 80)
        output.append("")
        
        self.append_result("\n".join(output))
    
    def append_result(self, text: str):
        """Append text to results area"""
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.scan_results = []
        self.progress_bar['value'] = 0
        self.progress_label.config(text="0/0")
        self.status_var.set("Ready")
    
    def export_results(self):
        """Export scan results to file"""
        if not self.scan_results:
            messagebox.showinfo("No Results", "No scan results to export")
            return
        
        # Ask user for export format
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Results")
        export_window.geometry("300x150")
        export_window.transient(self.root)
        export_window.grab_set()
        
        ttk.Label(export_window, text="Select export format:", 
                 font=('Helvetica', 12, 'bold')).pack(pady=20)
        
        button_frame = ttk.Frame(export_window)
        button_frame.pack(pady=10)
        
        def export_csv():
            export_window.destroy()
            self._export_to_csv()
        
        def export_json():
            export_window.destroy()
            self._export_to_json()
        
        def export_txt():
            export_window.destroy()
            self._export_to_txt()
        
        ttk.Button(button_frame, text="CSV", command=export_csv, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="JSON", command=export_json, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="TXT", command=export_txt, width=10).pack(side=tk.LEFT, padx=5)
    
    def _export_to_csv(self):
        """Export results to CSV file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"telnet_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IP Address', 'Port', 'Status', 'Response Time (ms)', 
                                   'Encryption Support', 'Banner', 'NTLM Info', 'Successful Credentials', 'Error', 'Timestamp'])
                    for result in self.scan_results:
                        # Format NTLM info
                        ntlm_str = 'N/A'
                        if result.get('ntlm_info'):
                            ntlm_parts = []
                            for key, value in result['ntlm_info'].items():
                                ntlm_parts.append(f"{key}={value}")
                            ntlm_str = "; ".join(ntlm_parts)
                        
                        # Format credential results
                        cred_str = 'N/A'
                        if result.get('credential_results'):
                            cred_parts = []
                            for cred in result['credential_results']:
                                cred_parts.append(f"{cred['username']}:{cred['password']}")
                            cred_str = "; ".join(cred_parts)
                        
                        writer.writerow([
                            result['ip'],
                            result['port'],
                            result['status'],
                            result.get('response_time', 'N/A'),
                            result.get('encryption_support', 'N/A'),
                            result.get('banner', 'N/A'),
                            ntlm_str,
                            cred_str,
                            result.get('error', 'N/A'),
                            result.get('timestamp', 'N/A')
                        ])
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def _export_to_json(self):
        """Export results to JSON file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"telnet_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def _export_to_txt(self):
        """Export results to text file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"telnet_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                content = self.results_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = TelnetEnumeratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
