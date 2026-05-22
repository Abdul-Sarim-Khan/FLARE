"""
FLARE v0.4 - TLS Certificate Generator

Generates a self-signed RSA-2048 certificate for the FLARE server.
Called by server/setup/1_setup.ps1 during server setup.

Usage:
    python generate_cert.py [--cert certs/flare_server.crt] [--key certs/flare_server.key]

Output:
    - Writes the cert and key PEM files
    - Prints the SHA-256 fingerprint to stdout (copy this to the agent config)
"""

import argparse
import datetime
import hashlib
import ipaddress
import pathlib
import socket
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("ERROR: 'cryptography' package not installed.")
    print("       Run: pip install cryptography>=42.0.0")
    sys.exit(1)


def generate(cert_path: pathlib.Path, key_path: pathlib.Path) -> str:
    """
    Generate a self-signed cert + key.
    Returns the SHA-256 fingerprint hex string (no colons).
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # --- Private key ---
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # --- Subject / Issuer ---
    hostname = socket.gethostname()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         "FLARE Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "FLARE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Monitoring"),
    ])

    # --- SAN: include hostname + all local IPs so cert validates on the LAN ---
    san_names = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        local_ip = socket.gethostbyname(hostname)
        san_names.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
    except Exception:
        pass

    # --- Build cert (valid 10 years) ---
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    # --- Write key (PEM, no passphrase) ---
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # --- Write cert (PEM) ---
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)

    # --- Fingerprint (SHA-256 of DER-encoded cert) ---
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(cert_der).hexdigest().upper()

    return fingerprint


def main():
    parser = argparse.ArgumentParser(description="FLARE TLS certificate generator")
    parser.add_argument("--cert", default="certs/flare_server.crt",
                        help="Output path for the certificate PEM")
    parser.add_argument("--key",  default="certs/flare_server.key",
                        help="Output path for the private key PEM")
    args = parser.parse_args()

    root     = pathlib.Path(__file__).parent
    cert_out = root / args.cert
    key_out  = root / args.key

    if cert_out.exists() and key_out.exists():
        # Re-compute fingerprint from existing cert instead of regenerating
        cert_der = x509.load_pem_x509_certificate(cert_out.read_bytes()) \
                       .public_bytes(serialization.Encoding.DER)
        fp = hashlib.sha256(cert_der).hexdigest().upper()
        print(f"CERT_EXISTS  {cert_out}")
        print(f"KEY_EXISTS   {key_out}")
        print(f"FINGERPRINT  {fp}")
        return

    fp = generate(cert_out, key_out)
    print(f"CERT_WRITTEN {cert_out}")
    print(f"KEY_WRITTEN  {key_out}")
    print(f"FINGERPRINT  {fp}")


if __name__ == "__main__":
    main()
