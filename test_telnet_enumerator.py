#!/usr/bin/env python3
"""
Simple unit tests for Telnet Enumerator
"""

import unittest
import sys
import socket
from telnet_enumerator import TelnetEnumerator


class TestTelnetEnumerator(unittest.TestCase):
    """Test cases for TelnetEnumerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.enumerator = TelnetEnumerator()
    
    def test_init(self):
        """Test that the enumerator initializes correctly"""
        self.assertEqual(self.enumerator.default_port, 23)
        self.assertEqual(self.enumerator.timeout, 3)
        self.assertIsInstance(self.enumerator.DEFAULT_CREDENTIALS, list)
        self.assertGreater(len(self.enumerator.DEFAULT_CREDENTIALS), 0)
    
    def test_default_credentials_format(self):
        """Test that default credentials are properly formatted"""
        for cred in self.enumerator.DEFAULT_CREDENTIALS:
            self.assertIsInstance(cred, tuple)
            self.assertEqual(len(cred), 2)
            self.assertIsInstance(cred[0], str)  # username
            self.assertIsInstance(cred[1], str)  # password
    
    def test_check_telnet_invalid_ip(self):
        """Test telnet check with invalid IP address"""
        result = self.enumerator.check_telnet("invalid.ip.address", 23)
        self.assertEqual(result['status'], 'error')
        self.assertIsNotNone(result['error'])
        self.assertIn('ip', result)
        self.assertIn('port', result)
        self.assertIn('timestamp', result)
    
    def test_check_telnet_closed_port(self):
        """Test telnet check with closed port on localhost"""
        # Use a high port number that's unlikely to be open
        result = self.enumerator.check_telnet("127.0.0.1", 65534, False, False)
        # Should be either 'closed' or 'timeout'
        self.assertIn(result['status'], ['closed', 'timeout'])
        self.assertIn('ip', result)
        self.assertIn('port', result)
        self.assertEqual(result['ip'], '127.0.0.1')
        self.assertEqual(result['port'], 65534)
    
    def test_check_telnet_result_structure(self):
        """Test that check_telnet returns the expected structure"""
        result = self.enumerator.check_telnet("127.0.0.1", 65534, False, False)
        
        # Check all required fields are present
        required_fields = ['ip', 'port', 'status', 'banner', 'error', 
                          'response_time', 'encryption_support', 'ntlm_info',
                          'credential_results', 'timestamp']
        
        for field in required_fields:
            self.assertIn(field, result)
    
    def test_ntlm_parse_with_no_data(self):
        """Test NTLM parsing with empty data"""
        result = self.enumerator._parse_ntlm_challenge(b'')
        self.assertIsNone(result)
    
    def test_ntlm_parse_with_invalid_data(self):
        """Test NTLM parsing with invalid data"""
        result = self.enumerator._parse_ntlm_challenge(b'invalid data')
        self.assertIsNone(result)
    
    def test_check_telnet_with_ntlm_disabled(self):
        """Test telnet check with NTLM extraction disabled"""
        result = self.enumerator.check_telnet("127.0.0.1", 65534, extract_ntlm=False)
        # NTLM info should be None when disabled
        self.assertIsNone(result.get('ntlm_info'))
    
    def test_check_telnet_with_credentials_disabled(self):
        """Test telnet check with credential testing disabled"""
        result = self.enumerator.check_telnet("127.0.0.1", 65534, test_credentials=False)
        # Credential results should be None when disabled
        self.assertIsNone(result.get('credential_results'))


class TestTelnetEnumeratorIntegration(unittest.TestCase):
    """Integration tests that may require network access"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.enumerator = TelnetEnumerator()
    
    def test_localhost_scan(self):
        """Test basic scan of localhost"""
        # This should work even without telnet running
        result = self.enumerator.check_telnet("127.0.0.1", 23, False, False)
        self.assertIsNotNone(result)
        self.assertIn(result['status'], ['open', 'closed', 'timeout'])


if __name__ == '__main__':
    print("Running Telnet Enumerator Tests...")
    print("=" * 80)
    
    # Run the tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestTelnetEnumerator))
    suite.addTests(loader.loadTestsFromTestCase(TestTelnetEnumeratorIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
