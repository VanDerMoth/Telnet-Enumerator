#!/usr/bin/env python3
"""
Telnet Enumerator - A GUI tool for enumerating telnet ports
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from typing import Optional, List
import queue
import time
import json
import csv
from datetime import datetime
import ipaddress


class TelnetEnumerator:
    """Main class for telnet port enumeration"""
    
    def __init__(self):
        self.default_port = 23
        self.timeout = 3
    
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
            time.sleep(0.5)
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
    
    def check_telnet(self, ip_address: str, port: int = 23) -> dict:
        """
        Check if telnet port is open on the specified IP address
        
        Args:
            ip_address: Target IP address
            port: Port to check (default 23 for telnet)
            
        Returns:
            dict with status, banner, error, timing information, and encryption support
        """
        result = {
            'ip': ip_address,
            'port': port,
            'status': 'closed',
            'banner': None,
            'error': None,
            'response_time': None,
            'encryption_support': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    
    def __init__(self, root):
        self.root = root
        self.root.title("Telnet Enumerator - Advanced Edition")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.enumerator = TelnetEnumerator()
        self.scan_thread = None
        self.result_queue = queue.Queue()
        self.scan_results = []  # Store all scan results
        self.is_scanning = False
        
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
        
        # Progress bar
        ttk.Label(main_frame, text="Progress:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.progress_bar = ttk.Progressbar(main_frame, mode='determinate')
        self.progress_bar.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.progress_label = ttk.Label(main_frame, text="0/0")
        self.progress_label.grid(row=3, column=2, sticky=tk.W, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=2, padx=5)
        
        self.export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        self.export_button.grid(row=0, column=3, padx=5)
        
        # Results text area
        ttk.Label(main_frame, text="Results:").grid(row=5, column=0, sticky=(tk.W, tk.N), pady=5)
        
        self.results_text = scrolledtext.ScrolledText(main_frame, width=90, height=25, 
                                                      wrap=tk.WORD, font=('Courier', 9))
        self.results_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), 
                              pady=5, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
    
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
        
        # Update enumerator timeout
        self.enumerator.timeout = timeout
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(ip_address, port),
            daemon=True
        )
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.status_var.set("Scan stopped by user")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def run_scan(self, ip_address: str, port: int):
        """Run the scan in a separate thread"""
        try:
            results = []
            total_scans = 0
            completed_scans = 0
            
            # Check if it's a CIDR range or single IP
            is_cidr = '/' in ip_address
            
            if is_cidr:
                # IP range scanning with CIDR
                try:
                    network = ipaddress.ip_network(ip_address, strict=False)
                    # Handle different network sizes including /31 and /32
                    total_scans = max(1, network.num_addresses - 2)
                    self.result_queue.put(('progress', 0, total_scans))
                    
                    for ip in network.hosts():
                        if not self.is_scanning:
                            break
                        result = self.enumerator.check_telnet(str(ip), port)
                        results.append(result)
                        completed_scans += 1
                        self.result_queue.put(('progress', completed_scans, total_scans))
                        
                except ValueError as e:
                    # Invalid CIDR notation, treat as single IP
                    total_scans = 1
                    self.result_queue.put(('progress', 0, total_scans))
                    result = self.enumerator.check_telnet(ip_address, port)
                    results.append(result)
                    completed_scans += 1
                    self.result_queue.put(('progress', completed_scans, total_scans))
            else:
                # Single IP scan
                total_scans = 1
                self.result_queue.put(('progress', 0, total_scans))
                
                if self.is_scanning:
                    result = self.enumerator.check_telnet(ip_address, port)
                    results.append(result)
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
                                   'Encryption Support', 'Banner', 'Error', 'Timestamp'])
                    for result in self.scan_results:
                        writer.writerow([
                            result['ip'],
                            result['port'],
                            result['status'],
                            result.get('response_time', 'N/A'),
                            result.get('encryption_support', 'N/A'),
                            result.get('banner', 'N/A'),
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
