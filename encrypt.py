from base64 import urlsafe_b64encode, b64decode, b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from secrets import token_hex


def generate_fernet(key: str, salt: str | None = None):
    """Creates fernet object from key and optionally salt"""

    # Use given salt or generate one
    if salt is None:
        s = token_hex(16).encode("utf-8")
    else:
        s = salt.encode("utf-8")

    assert s is not None

    # Generate key derivator
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=10000)
    # Derive key from password bytes
    token = urlsafe_b64encode(kdf.derive(key.encode()))
    return Fernet(token), s


def encrypt_string(key: str, data: bytes):
    """Encrypt user uploaded file"""
    fernet, salt = generate_fernet(key)

    #  encrypt data
    return fernet.encrypt(b64encode(data)), salt


def decrypt_string(key: str, salt: str, data: bytes):
    """Decrypt user uploaded data"""
    fernet, _ = generate_fernet(key, salt)

    # decrypt data
    return b64decode(fernet.decrypt(data))
