import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Construct a TCP socket
HOST, CA_PORT, GD_PORT = "140.113.194.88", 20000, 20500

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2CA:
    # Connect to CA
    sock2CA.connect((HOST, CA_PORT))

    # Send ID to CA
    msg_size = len("0216023")
    byte_msg_size = struct.pack("i", msg_size)
    sock2CA.sendall(byte_msg_size)
    sock2CA.sendall(bytes("0216023", 'utf-8'))
    print('I send 0216023 to CA')

    # Receive hello from CA
    msg_size = struct.unpack('i', sock2CA.recv(4))
    received = str(sock2CA.recv(int(msg_size[0])), "utf-8")
    print('CA send ', received)

    # Certificate signing request PEM file
    with open('private.pem', 'rb') as f:
        myPriKey = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
        f.close()
    CSR = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"0216023"),
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # Sign the CSR with our private key.
    ).sign(myPriKey, hashes.SHA256(), default_backend())
    CSRpem = CSR.public_bytes(serialization.Encoding.PEM)
    msg_size = len(str(CSRpem))
    byte_msg_size = struct.pack('i', msg_size)
    sock2CA.sendall(byte_msg_size)
    sock2CA.sendall(CSRpem)
    print('I send CSR PEM to CA :\n', str(CSRpem, 'utf-8'))

    # Certificate in PEM format
    msg_size = struct.unpack('i', sock2CA.recv(4))
    received = str(sock2CA.recv(int(msg_size[0])), "utf-8")
    print('CA send\n', received)
    CERT = received

    # Receive bye from CA
    msg_size = struct.unpack('i', sock2CA.recv(4))
    received = str(sock2CA.recv(int(msg_size[0])), "utf-8")
    print('CA send ', received)
