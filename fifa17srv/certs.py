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

# --- ProtoSSL cert-verify bypass, by hand ---------------------------------------------------
# Documented in Aim4kill/Bug_OldProtoSSL: old EA ProtoSSL stacks parse the signature algorithm
# OID with a switch statement; an OID it doesn't recognise falls into the default case, which
# sets the expected hash length to 0. The verification is a memcmp() of that length, so with
# length 0 it "matches" without comparing anything and any signature bytes are accepted.
# rsaEncryption (1.2.840.113549.1.1.1) is the same byte length as the sha1/sha256 OIDs above but
# isn't a signature-with-hash algorithm, so it trips the bug instead of validating normally.
_ALG_PROTOSSL_BYPASS = bytes.fromhex("300d06092a864886f70d0101010500")


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
    name = hash_name.lower()
    if name == "sha256":
        return builder.sign(key, _hash(name))
    if name not in ("sha1", "protossl-bypass"):
        raise ValueError(f"unknown cert_sig_hash: {hash_name!r}")

    draft = builder.sign(key, hashes.SHA256())
    tbs = draft.tbs_certificate_bytes
    if tbs.count(_ALG_SHA256_RSA) != 1:
        raise RuntimeError("unexpected certificate layout, cannot re-sign")
    alg = _ALG_SHA1_RSA if name == "sha1" else _ALG_PROTOSSL_BYPASS
    tbs = tbs.replace(_ALG_SHA256_RSA, alg)
    # The signature bytes themselves don't matter for protossl-bypass (the bug skips checking
    # them), but a real SHA-1 signature keeps the certificate well-formed either way.
    signature = _rsa_sign_sha1(key, tbs)
    der = _der(0x30, tbs + alg + _der(0x03, b"\x00" + signature))
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
        "server_leaf": d / "server_leaf.pem",
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
    # server.pem = leaf + CA (full chain); server_leaf.pem = leaf only. Some old ProtoSSL clients
    # apparently only expect the leaf and choke on an extra (self-signed, so pointless to them
    # anyway) CA certificate in the handshake -- try both against the real client.
    paths["server"].write_bytes(srv_cert.public_bytes(pem) + ca_cert.public_bytes(pem))
    paths["server_leaf"].write_bytes(srv_cert.public_bytes(pem))
    paths["server_key"].write_bytes(_pem_key(srv_key))
    return paths
