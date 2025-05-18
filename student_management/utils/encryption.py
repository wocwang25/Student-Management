import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from decimal import Decimal

def hashing_password(password):
    """
    Hash a password using SHA-1
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return hashlib.sha1(password).digest()

def generate_key_pair():
    """
    Generate an RSA key pair with a size of 2048 bits
    Returns (private_key, public_key, public_key_pem)
    """
    # Generate private key
    private_key = RSA.generate(2048)
    
    # Get public key
    public_key = private_key.publickey()
    
    # Get PEM string for storage
    public_key_pem = public_key.export_key().decode('utf-8')
    
    return private_key, public_key, public_key_pem

def encrypt_salary(salary, public_key_pem):
    """
    Encrypt salary using RSA-2048 encryption (with OAEP padding)
    
    Args:
        salary: The salary to encrypt
        public_key_pem: The RSA-2048 public key in PEM format
        
    Returns:
        Binary encrypted data
    """
    # Convert salary to string and encode to binary
    salary_bytes = str(salary).encode('utf-8')
    
    # Load RSA-2048 public key from PEM
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
        
    public_key = RSA.import_key(public_key_pem)
    
    # Create cipher with OAEP padding using SHA-256
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    
    # Encrypt the data
    encrypted = cipher.encrypt(salary_bytes)
    
    return encrypted

def decrypt_salary(encrypted_salary, private_key_pem, password):
    """
    Decrypt salary that was encrypted using RSA with OAEP padding
    
    Args:
        encrypted_salary: The encrypted salary binary data
        private_key_pem: The private key in PEM format
        password: The password protecting the private key
        
    Returns:
        The decrypted salary as a string
    """
    try:
        # Deserialize the private key using the password
        private_key = deserialize_private_key(private_key_pem, password)
        
        # Create cipher with OAEP padding using SHA-256
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Decrypt the salary
        decrypted_data = cipher.decrypt(encrypted_salary)
        
        # Return as string
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error decrypting salary: {str(e)}")

def serialize_private_key(private_key, password):
    """
    Serialize private key protected by a password
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
        
    return private_key.export_key(passphrase=password, pkcs=8).decode('utf-8')

def deserialize_private_key(private_key_pem, password):
    """
    Deserialize private key protected by a password
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
        
    return RSA.import_key(
        private_key_pem if isinstance(private_key_pem, bytes) else private_key_pem.encode('utf-8'),
        passphrase=password
    )

def encrypt_score(score, public_key_pem):
    """
    Encrypt score in the same way as SQL Server's encryptbyasymkey
    
    Args:
        score: The score to encrypt (decimal or float)
        public_key_pem: The public key in PEM format
        
    Returns:
        Binary encrypted data
    """
    # Convert score to integer after multiplying by 100 (same as SQL)
    score_int = int(float(score) * 100)
    
    # Convert integer to binary representation (big endian - similar to SQL Server)
    # Using 4 bytes for int (32 bits)
    binary_data = score_int.to_bytes(4, byteorder='big')
    
    # Load public key from PEM
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
        
    public_key = RSA.import_key(public_key_pem)
    
    # Create cipher with OAEP padding using SHA-256
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    
    # Encrypt the data
    encrypted = cipher.encrypt(binary_data)
    
    # Return raw binary data
    return encrypted

def decrypt_score(encrypted_score, private_key_pem, password):
    """
    Decrypt a score that was encrypted using RSA with OAEP padding
    
    Args:
        encrypted_score: The encrypted score binary data
        private_key_pem: The private key in PEM format
        password: The password protecting the private key
        
    Returns:
        The decrypted score as a Decimal
    """        
    try:
        private_key = deserialize_private_key(private_key_pem, password)
        
        # Create cipher with OAEP padding using SHA-256
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_score)
        
        # Convert the 4-byte binary back to an integer
        score_int = int.from_bytes(decrypted_data, byteorder='big')
        
        # Convert back to decimal (divide by 100 since we multiplied by 100 when encrypting)
        return Decimal(score_int) / 100
        
    except Exception as e:
        raise ValueError(f"Error decrypting score: {str(e)}")