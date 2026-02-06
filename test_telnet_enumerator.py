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
        # Test new concurrent and stealth attributes
        self.assertEqual(self.enumerator.max_workers, 10)
        self.assertEqual(self.enumerator.jitter_min, 0.0)
        self.assertEqual(self.enumerator.jitter_max, 0.0)
        self.assertEqual(self.enumerator.randomize_order, False)
        self.assertEqual(self.enumerator.randomize_source_port, False)
    
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
    
    def test_stealth_options_configuration(self):
        """Test that stealth options can be configured"""
        self.enumerator.randomize_order = True
        self.enumerator.randomize_source_port = True
        self.enumerator.jitter_min = 0.5
        self.enumerator.jitter_max = 2.0
        
        self.assertTrue(self.enumerator.randomize_order)
        self.assertTrue(self.enumerator.randomize_source_port)
        self.assertEqual(self.enumerator.jitter_min, 0.5)
        self.assertEqual(self.enumerator.jitter_max, 2.0)
    
    def test_concurrent_workers_configuration(self):
        """Test that concurrent workers can be configured"""
        self.enumerator.max_workers = 20
        self.assertEqual(self.enumerator.max_workers, 20)
    
    def test_files_to_view_initialization(self):
        """Test that files_to_view is initialized correctly"""
        self.assertIsInstance(self.enumerator.files_to_view, list)
        self.assertEqual(len(self.enumerator.files_to_view), 0)
    
    def test_files_to_view_configuration(self):
        """Test that files_to_view can be configured"""
        test_files = ['/etc/passwd', '/etc/hosts']
        self.enumerator.files_to_view = test_files
        self.assertEqual(self.enumerator.files_to_view, test_files)
    
    def test_view_files_via_telnet_empty_list(self):
        """Test file viewing with empty file list"""
        # Create a mock socket (won't actually be used)
        sock = None
        result = self.enumerator._view_files_via_telnet(sock, [])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)
    
    def test_file_extensions_defined(self):
        """Test that file extensions for discovery are defined"""
        self.assertIsInstance(self.enumerator.TEXT_EXTENSIONS, list)
        self.assertIsInstance(self.enumerator.IMAGE_EXTENSIONS, list)
        self.assertGreater(len(self.enumerator.TEXT_EXTENSIONS), 0)
        self.assertGreater(len(self.enumerator.IMAGE_EXTENSIONS), 0)
        # Check some expected extensions
        self.assertIn('txt', self.enumerator.TEXT_EXTENSIONS)
        self.assertIn('jpg', self.enumerator.IMAGE_EXTENSIONS)
        self.assertIn('png', self.enumerator.IMAGE_EXTENSIONS)
    
    def test_max_discovered_files_limit(self):
        """Test that MAX_DISCOVERED_FILES is defined and reasonable"""
        self.assertIsInstance(self.enumerator.MAX_DISCOVERED_FILES, int)
        self.assertGreater(self.enumerator.MAX_DISCOVERED_FILES, 0)
        self.assertLessEqual(self.enumerator.MAX_DISCOVERED_FILES, 1000)
    
    def test_discover_files_via_telnet_with_none_socket(self):
        """Test file discovery with None socket returns empty list"""
        # Should handle gracefully without crashing
        result = self.enumerator._discover_files_via_telnet(None)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0, "Should return empty list for None socket")
    
    def test_auto_scrub_configuration(self):
        """Test that auto_scrub_files can be configured"""
        self.enumerator.auto_scrub_files = True
        self.assertTrue(self.enumerator.auto_scrub_files)
        self.enumerator.auto_scrub_files = False
        self.assertFalse(self.enumerator.auto_scrub_files)


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
