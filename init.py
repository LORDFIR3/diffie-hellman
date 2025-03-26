import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
from flask import request, session, jsonify
import jwt
import random
import base64
from sympy import randprime

load_dotenv()

# Secret key for JWT validation (must match your authorization app's secret)
SECRET_KEY = os.getenv('SECRET_KEY')

P = randprime(2**10, 2**64)
G = random.randint(2, P - 1)


def generate_private_key():
    return random.randint(2, P - 2)


def generate_public_key(private_key):
    return pow(G, private_key, P)


def generate_shared_key(public_key, private_key):
    return pow(public_key, private_key, P)


# Message encryption and decryption functions
def encrypt_message(message, shared_key):
    """ Uses shared key, created during Diffie-Hellman protocol execution to encrypt message """
    key_size = 16  # AES key size, you can adjust for 128, 192, or 256-bit
    shared_key_bytes = shared_key.to_bytes(key_size, byteorder='big')  # Adjust byteorder as necessary

    cipher = AES.new(shared_key_bytes, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted).decode()


def decrypt_message(encrypted_message, shared_key):
    """ Uses shared key, created during Diffie-Hellman protocol execution to decrypt message """
    key_size = 16  # AES key size, you can adjust for 128, 192, or 256-bit
    shared_key_bytes = shared_key.to_bytes(key_size, byteorder='big')  # Adjust byteorder as necessary

    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]  # Extract IV
    encrypted = encrypted_data[16:]
    cipher = AES.new(shared_key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode()

# Token verification function
def is_authenticated():
    """ Function to check if user is logged in """
    if session.get('Authenticated'):
        return True

    token = request.args.get('verify') # "Token"
    if not token:
        return False
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not decoded or "login" not in decoded or "password" not in decoded:
            return False
        session['user'] = decoded['login']
        session['Authenticated'] = True
        print(session)
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

