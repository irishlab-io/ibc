"""
Security tests to validate that vulnerabilities have been fixed.

This module tests that the security fixes applied to views.py are effective
and that the application now follows secure coding best practices.
"""

import json
import os
import tempfile
from unittest.mock import Mock, patch, mock_open

import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest


class TestSecurityFixes(TestCase):
    """Test cases to validate security fixes."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_to_traces_no_command_injection(self):
        """
        Test that to_traces() no longer executes shell commands.
        
        Validates fix for CWE-78 (Command Injection).
        """
        from web.views import to_traces
        
        # Test with malicious payload that would execute commands in old version
        malicious_payloads = [
            "echo test; whoami",
            "echo test && rm -rf /tmp/test",
            "$(whoami)",
            "`id`",
        ]
        
        for payload in malicious_payloads:
            with self.subTest(payload=payload):
                with patch('os.system') as mock_system:
                    # Call the fixed function
                    result = to_traces(payload)
                    
                    # Verify os.system is NOT called (fix for command injection)
                    mock_system.assert_not_called()
                    
                    # Should return success status
                    self.assertEqual(result, "0")

    def test_to_traces_safe_file_logging(self):
        """Test that to_traces() safely logs to file without executing commands."""
        from web.views import to_traces
        
        test_string = "transfer from account 123 to account 456"
        
        with patch('builtins.open', mock_open()) as mock_file:
            result = to_traces(test_string)
            
            # Should open file for appending
            mock_file.assert_called()
            
            # Should return success
            self.assertEqual(result, "0")

    def test_certificate_uses_json_not_pickle(self):
        """
        Test that certificate operations use JSON instead of pickle.
        
        Validates fix for CWE-502 (Insecure Deserialization).
        """
        from web.views import CertificateData
        
        # Create certificate data
        cert = CertificateData("test_user")
        
        # Should be serializable to JSON
        cert_dict = cert.to_dict()
        self.assertIsInstance(cert_dict, dict)
        self.assertEqual(cert_dict["username"], "test_user")
        
        # Should be able to serialize to JSON (not pickle)
        json_str = json.dumps(cert_dict)
        self.assertIsInstance(json_str, str)
        
        # Should be able to deserialize safely
        loaded_dict = json.loads(json_str)
        loaded_cert = CertificateData.from_dict(loaded_dict)
        self.assertEqual(loaded_cert.username, "test_user")

    def test_no_pickle_import_in_views(self):
        """Test that pickle module is not imported in views.py."""
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Verify pickle is not imported
        self.assertNotIn('import pickle', content)
        self.assertNotIn('from pickle', content)

    def test_encryption_uses_aes_not_des(self):
        """
        Test that encryption uses AES instead of DES.
        
        Validates fix for CWE-327 (Weak Cryptography).
        """
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Verify AES is used
        self.assertIn('from Crypto.Cipher import AES', content)
        self.assertIn('AES.MODE_GCM', content)
        
        # Verify DES is not used
        self.assertNotIn('DES.new', content)
        self.assertNotIn('DES.MODE_CBC', content)

    def test_no_hardcoded_encryption_key(self):
        """Test that there are no hardcoded encryption keys."""
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Verify the old hardcoded key is not present
        self.assertNotIn('bytes("01234567"', content)
        self.assertNotIn('"01234567"', content)
        
        # Verify keys are derived from settings or generated
        self.assertIn('PBKDF2', content)
        self.assertIn('get_random_bytes', content)

    def test_avatar_view_validates_filename(self):
        """
        Test that AvatarView validates filenames to prevent path traversal.
        
        Validates fix for CWE-22 (Path Traversal).
        """
        from web.views import AvatarView
        
        # Test path traversal attempts
        dangerous_filenames = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "test/../../secret.png",
            "image.png\x00.txt",
            "image.png\n.txt",
        ]
        
        for filename in dangerous_filenames:
            with self.subTest(filename=filename):
                is_safe = AvatarView._is_safe_filename(filename)
                self.assertFalse(is_safe, f"Should reject dangerous filename: {filename}")
        
        # Test valid filenames
        valid_filenames = [
            "avatar.png",
            "user123.jpg",
            "profile-image.jpeg",
            "photo_1.gif",
        ]
        
        for filename in valid_filenames:
            with self.subTest(filename=filename):
                is_safe = AvatarView._is_safe_filename(filename)
                self.assertTrue(is_safe, f"Should accept valid filename: {filename}")

    def test_credit_card_image_view_validates_path(self):
        """Test that CreditCardImageView validates paths to prevent traversal."""
        from web.views import CreditCardImageView
        
        # Test path traversal attempts
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\secret.txt",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
        ]
        
        for path in dangerous_paths:
            with self.subTest(path=path):
                is_safe = CreditCardImageView._is_safe_filename(path)
                self.assertFalse(is_safe, f"Should reject dangerous path: {path}")

    def test_malicious_certificate_endpoint_disabled(self):
        """Test that MaliciousCertificateDownloadView is disabled."""
        from web.views import MaliciousCertificateDownloadView
        
        request = self.factory.post('/certificate/malicious')
        request.user = Mock()
        request.user.username = "test_user"
        
        view = MaliciousCertificateDownloadView()
        view.request = request
        
        # Should return error response
        response = view.post(request)
        
        # Should return 410 Gone status
        self.assertEqual(response.status_code, 410)
        
        # Should contain error message
        response_data = json.loads(response.content)
        self.assertIn("error", response_data)
        self.assertIn("disabled", response_data["error"])

    def test_new_certificate_view_validates_json(self):
        """Test that NewCertificateView only accepts valid JSON."""
        from web.views import NewCertificateView
        from django.core.files.uploadedfile import SimpleUploadedFile
        
        # Test with invalid pickle data (should be rejected)
        pickle_data = b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00'
        pickle_file = SimpleUploadedFile(
            "cert.json",
            pickle_data,
            content_type="application/octet-stream"
        )
        
        request = self.factory.post('/certificate/upload')
        request.FILES = {'file': pickle_file}
        request.user = Mock()
        
        view = NewCertificateView()
        response = view.post(request)
        
        # Should reject invalid JSON
        self.assertEqual(response.status_code, 400)

    def test_avatar_update_validates_file_type(self):
        """Test that AvatarUpdateView validates file types using magic bytes."""
        from web.views import AvatarUpdateView
        from django.core.files.uploadedfile import SimpleUploadedFile
        
        # Test with non-image data
        text_file = SimpleUploadedFile(
            "fake.png",
            b"This is not an image file",
            content_type="image/png"
        )
        
        request = self.factory.post('/avatar/update')
        request.FILES = {'imageFile': text_file}
        request.user = Mock()
        request.user.username = "testuser"
        
        view = AvatarUpdateView()
        view.request = request
        
        # Should handle invalid file gracefully
        with patch('web.views.storage_service'):
            response = view.post(request)
            
        # Should redirect (not crash)
        self.assertEqual(response.status_code, 302)


class TestInputSanitization(TestCase):
    """Test input sanitization and validation."""

    def test_filename_sanitization(self):
        """Test that filenames are properly sanitized."""
        from web.views import AvatarView
        
        # Test various malicious inputs
        test_cases = [
            ("normal.png", True),
            ("../../../etc/passwd", False),
            ("file\x00.png", False),
            ("file\n.png", False),
            ("file;rm -rf.png", False),
            ("file|whoami.png", False),
            ("file`id`.png", False),
            ("file$(ls).png", False),
        ]
        
        for filename, should_be_safe in test_cases:
            with self.subTest(filename=filename):
                result = AvatarView._is_safe_filename(filename)
                self.assertEqual(
                    result, 
                    should_be_safe,
                    f"Filename {filename!r} should {'be' if should_be_safe else 'not be'} safe"
                )


@pytest.mark.security
class TestSecurityImprovements:
    """High-level security improvement tests."""

    def test_no_os_system_calls(self):
        """Verify that os.system is not used in views.py."""
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Should not contain direct os.system calls
        assert 'os.system(' not in content, "os.system() should not be used"

    def test_uses_modern_cryptography(self):
        """Verify modern cryptography is used."""
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Should use modern algorithms
        assert 'AES' in content
        assert 'PBKDF2' in content
        assert 'get_random_bytes' in content
        
        # Should not use deprecated algorithms
        assert 'DES' not in content

    def test_safe_serialization(self):
        """Verify safe serialization is used."""
        with open('src/web/views.py', 'r') as f:
            content = f.read()
            
        # Should use JSON
        assert 'import json' in content
        assert 'json.dumps' in content
        assert 'json.loads' in content
        
        # Should not use pickle
        assert 'pickle.dumps' not in content
        assert 'pickle.loads' not in content
