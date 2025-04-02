import unittest
from phe import paillier, EncryptedNumber

# Generate a key pair for all tests
public_key, private_key = paillier.generate_paillier_keypair()

class TestEncryptionHomomorphism(unittest.TestCase):
    def test_homomorphic_subtraction_zero(self):
        """
        Test homomorphic subtraction:
        Subtracting two encryptions of the same value should decrypt to 0.
        """
        password_value = 123456789
        encrypted1 = public_key.encrypt(password_value)
        encrypted2 = public_key.encrypt(password_value)
        
        diff = encrypted1 - encrypted2
        decrypted_diff = private_key.decrypt(diff)
        self.assertEqual(decrypted_diff, 0, "Homomorphic subtraction of identical values should yield 0")
        print("test_homomorphic_subtraction_zero passed, decrypted_diff:", decrypted_diff)
        
    def test_homomorphic_subtraction_different(self):
        """
        Test homomorphic subtraction with different values:
        Subtracting two different encrypted numbers should yield the difference of their plaintext values.
        """
        a = 5000
        b = 3000
        encrypted_a = public_key.encrypt(a)
        encrypted_b = public_key.encrypt(b)
        diff = encrypted_a - encrypted_b
        decrypted_diff = private_key.decrypt(diff)
        self.assertEqual(decrypted_diff, a - b, "Homomorphic subtraction should compute the correct difference")
        print("test_homomorphic_subtraction_different passed, decrypted_diff:", decrypted_diff)
        

    def test_homomorphic_addition(self):
        """
        Test homomorphic addition:
        Adding two encrypted numbers should yield the sum of their plaintext values.
        """
        a = 1000
        b = 2000
        encrypted_a = public_key.encrypt(a)
        encrypted_b = public_key.encrypt(b)
        encrypted_sum = encrypted_a + encrypted_b
        decrypted_sum = private_key.decrypt(encrypted_sum)
        self.assertEqual(decrypted_sum, a + b, "Homomorphic addition should compute the sum of plaintext values")
        print("test_homomorphic_addition passed, decrypted_sum:", decrypted_sum)

    def test_homomorphic_multiplication_constant(self):
        """
        Test homomorphic multiplication by a constant:
        Multiplying an encrypted number by a constant should yield the product of the plaintext and the constant.
        """
        a = 12345
        k = 5
        encrypted_a = public_key.encrypt(a)
        encrypted_product = encrypted_a * k
        decrypted_product = private_key.decrypt(encrypted_product)
        self.assertEqual(decrypted_product, a * k, "Multiplying an encrypted number by a constant should yield the correct product")
        print("test_homomorphic_multiplication_constant passed, decrypted_product:", decrypted_product)

    def test_encryption_decryption_identity(self):
        """
        Test basic encryption and decryption:
        Encrypting a number and then decrypting it should return the original value.
        """
        original_value = 987654321
        encrypted_value = public_key.encrypt(original_value)
        decrypted_value = private_key.decrypt(encrypted_value)
        self.assertEqual(decrypted_value, original_value, "Encryption followed by decryption should preserve the original value")
        print("test_encryption_decryption_identity passed, decrypted_value:", decrypted_value)

    

    
if __name__ == '__main__':
    unittest.main()


