"""
FLARE v0.6 - PKI Generator (mTLS)
──────────────────────────────────
Generates a minimal 3-tier PKI for mutual TLS:

  CA layer (server-held, never distributed):
    certs/ca.crt   — CA certificate   (copy to every agent machine)
    certs/ca.key   — CA private key   (keep on server only)

  Server layer:
    certs/server.crt  — server certificate signed by CA
    certs/server.key  — server private key

  Client bundles (one per agent/admin machine):
    certs/clients/<name>/client.crt  — PEM cert  -> FLARE_CLIENT_CERT
    certs/clients/<name>/client.key  — PEM key   -> FLARE_CLIENT_KEY
    certs/clients/<name>/client.p12  — PKCS12 bundle for browser import

Usage
-----
  # 1. First-time server setup (generates CA + server cert):
  python generate_pki.py

  # 2. Provision a new agent called "DESKTOP-ABC":
  python generate_pki.py --client DESKTOP-ABC

  # 3. Same, but protect the .p12 with a passphrase:
  python generate_pki.py --client DESKTOP-ABC --p12-pass s3cr3t

Called by server/setup/1_setup.ps1 during server setup.
"""

import argparse
import datetime
import ipaddress
import pathlib
import socket
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError:
    print("ERROR: 'cryptography' package not installed.")
    print("       Run: pip install cryptography>=42.0.0")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _write_key(key, path: pathlib.Path):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))


def _has_aki(cert_path: pathlib.Path) -> bool:
    """Return True if the cert file contains an AuthorityKeyIdentifier extension.

    Python 3.12+ / OpenSSL 3.x enforce that signed certificates carry AKI.
    Certs generated without it will fail chain validation with
    'Missing Authority Key Identifier'.  We use this to detect and auto-
    regenerate stale certs produced by older versions of this script.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        return True
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CA
# ---------------------------------------------------------------------------

def generate_ca(
    cert_path: pathlib.Path,
    key_path:  pathlib.Path,
):
    """
    Generate the FLARE CA cert + key.
    If both already exist, loads and returns them without overwriting.

    Returns: (ca_key, ca_cert)
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if cert_path.exists() and key_path.exists():
        ca_key  = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        print(f"CA_EXISTS    {cert_path}")
        return ca_key, ca_cert

    key = _gen_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,              "FLARE CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "FLARE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
    ])
    now  = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,  content_commitment=False,
            key_encipherment=False,  data_encipherment=False,
            key_agreement=False,     key_cert_sign=True,
            crl_sign=True,           encipher_only=False,  decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    _write_key(key, key_path)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"CA_WRITTEN   {cert_path}")
    print(f"CA_KEY       {key_path}")
    return key, cert


# ---------------------------------------------------------------------------
# Server certificate
# ---------------------------------------------------------------------------

def generate_server_cert(
    cert_path: pathlib.Path,
    key_path:  pathlib.Path,
    ca_key,
    ca_cert,
):
    """
    Generate a server cert signed by CA.
    SANs include localhost, the machine hostname, and all local IPv4 addresses.
    Skipped silently if both files already exist.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if cert_path.exists() and key_path.exists():
        if _has_aki(cert_path):
            print(f"SERVER_EXISTS {cert_path}")
            return
        # Cert exists but is missing AKI — regenerate silently so chain validation
        # works with Python 3.12+ / OpenSSL 3.x strict mode.
        print(f"SERVER_REGEN  {cert_path}  (missing AKI — regenerating)")

    key      = _gen_key()
    hostname = socket.gethostname()
    subject  = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,              "FLARE Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "FLARE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Server"),
    ])

    # Build SAN: localhost + hostname + every local IPv4 we can find.
    # This makes the cert portable — works on whichever interface the
    # operator picks at startup, and across DHCP renewals on multi-NIC hosts.
    san_names = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    found_ips: set[str] = {"127.0.0.1"}

    # All addresses bound to local interfaces (covers multi-NIC, VPN, WSL, etc.)
    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
        for ip in addrs:
            if ip not in found_ips:
                try:
                    san_names.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
                    found_ips.add(ip)
                except (ipaddress.AddressValueError, ValueError):
                    pass
    except Exception:
        pass

    # Default-route IP (the one used to reach the internet — most likely what
    # other LAN hosts will see)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and primary not in found_ips:
            try:
                san_names.append(x509.IPAddress(ipaddress.IPv4Address(primary)))
                found_ips.add(primary)
            except (ipaddress.AddressValueError, ValueError):
                pass
    except Exception:
        pass

    print(f"SERVER_SAN_IPS  {sorted(found_ips)}")

    now  = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_names),              critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),   critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,  content_commitment=False,
            key_encipherment=True,   data_encipherment=False,
            key_agreement=False,     key_cert_sign=False,
            crl_sign=False,          encipher_only=False,  decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_key(key, key_path)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"SERVER_CERT  {cert_path}")
    print(f"SERVER_KEY   {key_path}")


# ---------------------------------------------------------------------------
# Client bundle
# ---------------------------------------------------------------------------

def generate_client_bundle(
    name:         str,
    ca_key,
    ca_cert,
    out_dir:      pathlib.Path,
    p12_password: str = "",
):
    """
    Generate a per-client cert bundle signed by the CA.

    Writes three files:
      client.crt  — PEM cert  (FLARE_CLIENT_CERT on the agent machine)
      client.key  — PEM key   (FLARE_CLIENT_KEY  on the agent machine)
      client.p12  — PKCS12    (import into browser for dashboard access)

    The cert CN is set to `name` (e.g. hostname or user@host).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "client.crt"
    key_path  = out_dir / "client.key"
    p12_path  = out_dir / "client.p12"

    key     = _gen_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,              name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "FLARE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Agent"),
    ])

    now  = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,  content_commitment=False,
            key_encipherment=False,  data_encipherment=False,
            key_agreement=False,     key_cert_sign=False,
            crl_sign=False,          encipher_only=False,  decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # PEM cert + key
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key, key_path)

    # PKCS12 bundle (cert + key + CA chain) for browser import
    p12_enc = (
        serialization.BestAvailableEncryption(p12_password.encode())
        if p12_password
        else serialization.NoEncryption()
    )
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=name.encode(),
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=p12_enc,
    )
    p12_path.write_bytes(p12_bytes)

    print(f"CLIENT_CERT  {cert_path}")
    print(f"CLIENT_KEY   {key_path}")
    print(f"CLIENT_P12   {p12_path}")
    if p12_password:
        print(f"P12_PASS     (as supplied via --p12-pass)")
    else:
        print(f"P12_PASS     (none — no import password required)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FLARE mTLS PKI generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_pki.py                          # first-time: CA + server cert
  python generate_pki.py --client DESKTOP-ABC     # new agent bundle
  python generate_pki.py --client admin --p12-pass hunter2  # browser admin bundle
""",
    )
    parser.add_argument("--ca-cert",     default="certs/ca.crt",     help="CA cert path")
    parser.add_argument("--ca-key",      default="certs/ca.key",      help="CA key path")
    parser.add_argument("--server-cert", default="certs/server.crt",  help="Server cert path")
    parser.add_argument("--server-key",  default="certs/server.key",  help="Server key path")
    parser.add_argument("--client",      default=None,
                        help="Generate a client bundle with this CN (hostname or name)")
    parser.add_argument("--client-dir",  default=None,
                        help="Output directory for client bundle "
                             "(default: certs/clients/<name>)")
    parser.add_argument("--p12-pass",    default="",
                        help="Optional passphrase for the PKCS12 browser bundle")
    args = parser.parse_args()

    root             = pathlib.Path(__file__).parent
    ca_cert_path     = root / args.ca_cert
    ca_key_path      = root / args.ca_key
    server_cert_path = root / args.server_cert
    server_key_path  = root / args.server_key

    # Always ensure CA + server cert exist
    ca_key_obj, ca_cert_obj = generate_ca(ca_cert_path, ca_key_path)
    generate_server_cert(server_cert_path, server_key_path, ca_key_obj, ca_cert_obj)

    # Optionally generate a client bundle
    if args.client:
        name       = args.client
        client_dir = (
            pathlib.Path(args.client_dir)
            if args.client_dir
            else root / "certs" / "clients" / name
        )
        print()
        generate_client_bundle(name, ca_key_obj, ca_cert_obj, client_dir, args.p12_pass)
        print()
        print("  --- Deployment instructions -----------------------------------")
        print("  Copy to the agent machine:")
        print(f"    ca.crt      ->  FLARE_CA_CERT     = {ca_cert_path}")
        print(f"    client.crt  ->  FLARE_CLIENT_CERT = {client_dir / 'client.crt'}")
        print(f"    client.key  ->  FLARE_CLIENT_KEY  = {client_dir / 'client.key'}")
        print()
        print("  For dashboard browser access on the agent machine:")
        print(f"    1. Install {ca_cert_path} as a Trusted Root CA")
        print(f"    2. Import  {client_dir / 'client.p12'} into your browser cert store")
        print("  ---------------------------------------------------------------")


if __name__ == "__main__":
    main()
