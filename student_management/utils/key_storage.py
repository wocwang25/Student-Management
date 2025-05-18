import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Define the directory where keys will be stored
KEY_STORAGE_DIR = Path('./student_management/private_keys')

# Create the directory if it doesn't exist
if not KEY_STORAGE_DIR.exists():
    KEY_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

def save_private_key(manv, private_key_data):
    """
    Save an employee's private key to a local file
    
    Args:
        manv: Employee ID
        private_key_data: Private key data (string or bytes)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        key_path = KEY_STORAGE_DIR / f"{manv}.pem"
        
        # Nếu là bytes, lưu ở chế độ binary
        if isinstance(private_key_data, bytes):
            with open(key_path, 'wb') as f:
                f.write(private_key_data)
        else:
            # Nếu là string, lưu ở chế độ text
            with open(key_path, 'w', encoding='utf-8') as f:
                f.write(private_key_data)
        
        # Set file permissions to be readable only by current user
        os.chmod(key_path, 0o600)  # Only user can read/write
        
        return True
    except Exception as e:
        print(f"Lỗi khi lưu private key cho {manv}: {str(e)}")
        return False

def get_private_key(manv):
    """
    Retrieve an employee's private key from local storage
    
    Args:
        manv: Employee ID
    
    Returns:
        str: Private key in PEM format or None if not found
    """
    try:
        key_path = KEY_STORAGE_DIR / f"{manv}.pem"
        
        if not key_path.exists():
            logger.warning(f"Private key for employee {manv} not found")
            return None
        
        with open(key_path, 'r', encoding='utf-8') as f:
            private_key_pem = f.read()
        
        return private_key_pem
    except Exception as e:
        logger.error(f"Failed to retrieve private key for {manv}: {str(e)}")
        return None