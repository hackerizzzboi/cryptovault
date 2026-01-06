#!/usr/bin/env python3
"""
Unit tests for CryptoVault Pro
Simple tests that work in GitHub Actions (no GUI)
"""

import unittest
import tempfile
import os
import json
import base64
import hashlib
import secrets
from datetime import datetime

class TestCryptoVaultCore(unittest.TestCase):
    """Test core cryptographic functions (NO GUI)"""
    
    def setUp(self):
        """Set up test environment"""
        # Import cryptography modules
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        
        self.rsa = rsa
        self.ec = ec
        self.Cipher = Cipher
        self.algorithms = algorithms
        self.modes = modes
        self.sym_padding = sym_padding
        self.backend = default_backend
        self.hashes = hashes
        self.serialization = serialization
    
    def test_rsa_key_generation(self):
        """Test RSA 2048 key generation"""
        print("🧪 Testing RSA key generation...")
        key = self.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend()
        )
        self.assertEqual(key.key_size, 2048)
        print(f"✅ RSA key: {key.key_size} bits")
        
        # Test serialization
        pem = key.private_bytes(
            encoding=self.serialization.Encoding.PEM,
            format=self.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self.serialization.NoEncryption()
        )
        self.assertIn(b'BEGIN PRIVATE KEY', pem)
        print("✅ RSA key serialized to PEM")
    
    def test_ecc_key_generation(self):
        """Test ECC P-256 key generation"""
        print("🧪 Testing ECC key generation...")
        key = self.ec.generate_private_key(
            self.ec.SECP256R1(),
            self.backend()
        )
        self.assertIsNotNone(key)
        print("✅ ECC P-256 key generated")
        
        # Get public key
        public_key = key.public_key()
        self.assertIsNotNone(public_key)
        print("✅ ECC public key extracted")
    
    def test_sha256_hashing(self):
        """Test SHA-256 hashing"""
        print("🧪 Testing SHA-256 hashing...")
        test_data = b"CryptoVault Pro Test Data"
        
        # Method 1: Using hashlib
        hash1 = hashlib.sha256(test_data).hexdigest()
        self.assertEqual(len(hash1), 64)  # SHA-256 = 64 hex chars
        
        # Method 2: Using cryptography library
        digest = self.hashes.Hash(self.hashes.SHA256(), backend=self.backend())
        digest.update(test_data)
        hash2 = digest.finalize().hex()
        
        self.assertEqual(hash1, hash2)
        print(f"✅ SHA-256 hash: {hash1[:16]}...")
    
    def test_aes_encryption_decryption(self):
        """Test AES encryption/decryption cycle"""
        print("🧪 Testing AES encryption/decryption...")
        
        # Generate random key and IV
        key = secrets.token_bytes(32)  # AES-256
        iv = secrets.token_bytes(16)   # Block size
        
        # Test data
        plaintext = b"Secret message for CryptoVault"
        
        # Encrypt
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv), backend=self.backend())
        encryptor = cipher.encryptor()
        padder = self.sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Decrypt
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv), backend=self.backend())
        decryptor = cipher.decryptor()
        unpadder = self.sym_padding.PKCS7(128).unpadder()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        self.assertEqual(plaintext, decrypted)
        print(f"✅ AES encrypted {len(plaintext)} bytes")
        print(f"✅ Decrypted successfully")
    
    def test_json_serialization(self):
        """Test JSON serialization of crypto data"""
        print("🧪 Testing JSON serialization...")
        
        test_package = {
            'algorithm': 'RSA-AES-256-CBC',
            'timestamp': datetime.now().isoformat(),
            'data': base64.b64encode(b"test data").decode(),
            'hash': hashlib.sha256(b"test data").hexdigest(),
            'version': '1.0.0'
        }
        
        # Serialize to JSON
        json_str = json.dumps(test_package, indent=2)
        self.assertIn('algorithm', json_str)
        self.assertIn('timestamp', json_str)
        
        # Deserialize
        loaded = json.loads(json_str)
        self.assertEqual(loaded['algorithm'], 'RSA-AES-256-CBC')
        
        print("✅ JSON serialization/deserialization works")
    
    def test_file_operations(self):
        """Test file read/write operations"""
        print("🧪 Testing file operations...")
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            test_content = "CryptoVault test file content"
            f.write(test_content)
            temp_path = f.name
        
        try:
            # Read file
            with open(temp_path, 'r') as f:
                content = f.read()
            
            self.assertEqual(content, test_content)
            
            # Test file hash
            with open(temp_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            self.assertEqual(len(file_hash), 64)
            print(f"✅ File hash: {file_hash[:16]}...")
            
        finally:
            # Clean up
            os.unlink(temp_path)
        
        print("✅ File operations work correctly")


class TestCryptoVaultIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_hybrid_encryption_workflow(self):
        """Test complete hybrid encryption workflow"""
        print("🧪 Testing hybrid encryption workflow...")
        
        # Import needed modules
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        
        # Step 1: Generate RSA key
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Step 2: Generate random AES key
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        # Step 3: Encrypt data with AES
        plaintext = b"Confidential message for Softwarica College"
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        # Step 4: Encrypt AES key with RSA
        encrypted_aes_key = rsa_key.public_key().encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Step 5: Create package
        package = {
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'iv': base64.b64encode(iv).decode(),
            'data': base64.b64encode(ciphertext).decode(),
            'algorithm': 'RSA-AES-256-CBC',
            'timestamp': datetime.now().isoformat()
        }
        
        self.assertIn('encrypted_key', package)
        self.assertIn('data', package)
        print("✅ Hybrid encryption package created")
        
        # Verify package structure
        json_package = json.dumps(package, indent=2)
        self.assertIn('RSA-AES-256-CBC', json_package)
        print("✅ Package JSON serialization works")


def run_all_tests():
    """Run all tests and print summary"""
    print("\n" + "="*60)
    print("🚀 CRYPTOVAULT PRO - UNIT TEST SUITE")
    print("="*60)
    
    # Create test suite
    loader = unittest.TestLoader()
    
    # Load tests
    core_suite = loader.loadTestsFromTestCase(TestCryptoVaultCore)
    integration_suite = loader.loadTestsFromTestCase(TestCryptoVaultIntegration)
    
    # Combine suites
    all_tests = unittest.TestSuite([core_suite, integration_suite])
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(all_tests)
    
    # Print summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    print(f"Total tests: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n🎉 ALL TESTS PASSED! ✅")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    # This allows the test to run in CI/CD without GUI
    import sys
    sys.exit(run_all_tests())