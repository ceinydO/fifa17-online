"""Generate a throwaway local CA and a server certificate for the redirector hostname."""
from __future__ import annotations

import datetime
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import Config

CA_CN = "FIFA17 Friendlies Local Dev CA"


def _hash(name: str):
    return {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[name.lower()]


# --- SHA-1 signing done by hand -------------------------------------------------------------
# Newer versions of the `cryptography` package refuse to sign certificates with SHA-1. Some very
# old TLS stacks only understand SHA-1 signatures, so for that (local, throwaway) case we build
# the signature ourselves: same certificate, signature algorithm swapped, RSA PKCS#1 v1.5 by hand.
_ALG_SHA256_RSA = bytes.fromhex("300d06092a864886f70d01010b0500")
_ALG_SHA1_RSA = bytes.fromhex("300d06092a864886f70d0101050500")
_SHA1_DIGESTINFO = bytes.fromhex("3021300906052b0e03021a05000414")


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _rsa_sign_sha1(key, message: bytes) -> bytes:
    numbers = key.private_numbers()
    n, d = numbers.public_numbers.n, numbers.d
    k = (n.bit_length() + 7) // 8
    t = _SHA1_DIGESTINFO + hashlib.sha1(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def _sign(builder: x509.CertificateBuilder, key, hash_name: str) -> x509.Certificate:
    if hash_name.lower() != "sha1":
        return builder.sign(key, _hash(hash_name))
    draft = builder.sign(key, hashes.SHA256())
    tbs = draft.tbs_certificate_bytes
    if tbs.count(_ALG_SHA256_RSA) != 1:
        raise RuntimeError("unexpected certificate layout, cannot re-sign with SHA-1")
    tbs = tbs.replace(_ALG_SHA256_RSA, _ALG_SHA1_RSA)
    signature = _rsa_sign_sha1(key, tbs)
    der = _der(0x30, tbs + _ALG_SHA1_RSA + _der(0x03, b"\x00" + signature))
    return x509.load_der_x509_certificate(der)


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def ensure_certs(cfg: Config, force: bool = False) -> dict:
    d = cfg.cert_dir_path
    d.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca": d / "ca.pem",
        "ca_key": d / "ca.key",
        "server": d / "server.pem",
        "server_key": d / "server.key",
    }
    if not force and all(p.exists() for p in paths.values()):
        return paths

    sig_hash = cfg.cert_sig_hash
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=1)
    end = now + datetime.timedelta(days=3650)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)])
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    ca_cert = _sign(ca_builder, ca_key, sig_hash)

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cfg.redirector_host)]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(cfg.redirector_host),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    srv_cert = _sign(srv_builder, ca_key, sig_hash)

    pem = serialization.Encoding.PEM
    paths["ca"].write_bytes(ca_cert.public_bytes(pem))
    paths["ca_key"].write_bytes(_pem_key(ca_key))
    # server.pem = leaf + CA, so clients that want the chain get it
    paths["server"].write_bytes(srv_cert.public_bytes(pem) + ca_cert.public_bytes(pem))
    paths["server_key"].write_bytes(_pem_key(srv_key))
    return paths
