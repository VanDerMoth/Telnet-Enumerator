#!/usr/bin/env python3
"""
Telnet Enumerator - A GUI tool for enumerating telnet ports
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Optional
import queue


class TelnetEnumerator:
    """Main class for telnet port enumeration"""
    
    def __init__(self):
        self.default_port = 23
        self.timeout = 3
    
    def check_telnet(self, ip_address: str, port: int = 23) -> dict:
        """
        Check if telnet port is open on the specified IP address
        
        Args:
            ip_address: Target IP address
            port: Port to check (default 23 for telnet)
            
        Returns:
            dict with status, banner, and error information
        """
        result = {
            'ip': ip_address,
            'port': port,
            'status': 'closed',
            'banner': None,
            'error': None
        }
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            connection_result = sock.connect_ex((ip_address, port))
            
            if connection_result == 0:
                result['status'] = 'open'
                
                # Try to grab banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner
                except Exception as e:
                    result['error'] = f"Banner grab failed: {str(e)}"
            
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
    
    def __init__(self, root):
        self.root = root
        self.root.title("Telnet Enumerator")
        self.root.geometry("700x550")
        self.root.resizable(True, True)
        
        self.enumerator = TelnetEnumerator()
        self.scan_thread = None
        self.result_queue = queue.Queue()
        
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
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Telnet Port Enumerator", 
                               font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # IP Address input
        ttk.Label(main_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(main_frame, width=30)
        self.ip_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Port input
        ttk.Label(main_frame, text="Port:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(main_frame, width=30)
        self.port_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.port_entry.insert(0, "23")
        
        # Timeout input
        ttk.Label(main_frame, text="Timeout (sec):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.timeout_entry = ttk.Entry(main_frame, width=30)
        self.timeout_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.timeout_entry.insert(0, "3")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=2, rowspan=3, padx=5)
        
        self.scan_button = ttk.Button(button_frame, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, pady=5, sticky=(tk.W, tk.E))
        
        self.clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_results)
        self.clear_button.grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E))
        
        # Results text area
        ttk.Label(main_frame, text="Results:").grid(row=4, column=0, sticky=(tk.W, tk.N), pady=5)
        
        self.results_text = scrolledtext.ScrolledText(main_frame, width=70, height=20, 
                                                      wrap=tk.WORD, font=('Courier', 10))
        self.results_text.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), 
                              pady=5, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
    
    def validate_inputs(self) -> tuple:
        """Validate user inputs"""
        ip_address = self.ip_entry.get().strip()
        
        if not ip_address:
            return False, "IP address is required"
        
        try:
            port = int(self.port_entry.get().strip())
            if port < 1 or port > 65535:
                return False, "Port must be between 1 and 65535"
        except ValueError:
            return False, "Port must be a valid number"
        
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
        
        # Disable scan button during scan
        self.scan_button.config(state=tk.DISABLED)
        self.status_var.set("Scanning...")
        
        # Get values
        ip_address = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
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
    
    def run_scan(self, ip_address: str, port: int):
        """Run the scan in a separate thread"""
        try:
            result = self.enumerator.check_telnet(ip_address, port)
            self.result_queue.put(('result', result))
        except Exception as e:
            self.result_queue.put(('error', str(e)))
    
    def check_queue(self):
        """Check the result queue for updates"""
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == 'result':
                    self.display_result(data)
                elif msg_type == 'error':
                    self.append_result(f"Error: {data}\n")
                
                self.scan_button.config(state=tk.NORMAL)
                self.status_var.set("Ready")
                
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_queue)
    
    def display_result(self, result: dict):
        """Display scan results"""
        output = []
        output.append("=" * 60)
        output.append(f"Telnet Enumeration Results")
        output.append("=" * 60)
        output.append(f"Target IP: {result['ip']}")
        output.append(f"Port: {result['port']}")
        output.append(f"Status: {result['status'].upper()}")
        
        if result['status'] == 'open':
            output.append("\n✓ Port is OPEN")
            if result['banner']:
                output.append(f"\nBanner Information:")
                output.append("-" * 60)
                output.append(result['banner'])
                output.append("-" * 60)
            else:
                output.append("\nNo banner received")
        elif result['status'] == 'closed':
            output.append("\n✗ Port is CLOSED")
        elif result['status'] == 'timeout':
            output.append("\n⚠ Connection timed out")
        elif result['status'] == 'error':
            output.append(f"\n✗ Error occurred")
        
        if result['error']:
            output.append(f"\nError Details: {result['error']}")
        
        output.append("=" * 60)
        output.append("")
        
        self.append_result("\n".join(output))
    
    def append_result(self, text: str):
        """Append text to results area"""
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = TelnetEnumeratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
