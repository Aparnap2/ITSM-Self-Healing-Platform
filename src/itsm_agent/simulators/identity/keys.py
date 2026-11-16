"""Signing keys, JWT minting and TLS material for the LOCAL identity simulator.

Development/staging only — see ``simulators/identity/__init__.py``.

The simulator is a **signing authority** and nothing more: it signs RS256
JWTs and publishes the matching public keys. It never asserts roles or
tenants; those are resolved by the application from its own directory.
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

#: The only algorithm this simulator signs with. The application's relying
#: party keeps its own allowlist; the simulator does not widen it.
SIGNING_ALGORITHM = "RS256"

#: Key size for the generated RSA key. 2048 bits keeps the simulator fast
#: enough for a test suite while staying a realistic size.
KEY_SIZE = 2048


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SigningKey:
    """One RSA signing key, with its public half publishable as a JWK."""

    kid: str
    private_key: rsa.RSAPrivateKey

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    def jwk(self) -> dict[str, Any]:
        """The public key as a JWK (RFC 7517), ready for a JWKS document."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": SIGNING_ALGORITHM,
            "kid": self.kid,
            "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }

    def sign(self, signing_input: bytes) -> bytes:
        """RSASSA-PKCS1-v1_5 over SHA-256, as RS256 requires."""
        return self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def generate_signing_key(kid: str | None = None) -> SigningKey:
    """Generate a fresh signing key."""
    return SigningKey(
        kid=kid or uuid.uuid4().hex,
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE),
    )


def encode_jwt(
    claims: dict[str, Any],
    key: SigningKey,
    *,
    algorithm: str = SIGNING_ALGORITHM,
) -> str:
    """Encode a signed JWT (compact serialization)."""
    if algorithm != SIGNING_ALGORITHM:
        raise ValueError(f"the simulator signs only {SIGNING_ALGORITHM}")
    header = {"alg": algorithm, "typ": "JWT", "kid": key.kid}
    segments = [
        _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode()),
        _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = key.sign(signing_input)
    return f"{segments[0]}.{segments[1]}.{_b64url(signature)}"


def mint_claims(
    *,
    issuer: str,
    audience: str,
    subject: str,
    ttl_seconds: int = 900,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Standard claims for a simulator-minted token.

    Deliberately minimal: issuer, audience, subject and the time claims. No
    role, tenant or permission claim is ever minted — authorization is the
    application's business.
    """
    issued_at = now or datetime.now(UTC)
    return {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": int(issued_at.timestamp()),
        "nbf": int((issued_at - timedelta(seconds=5)).timestamp()),
        "exp": int((issued_at + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": uuid.uuid4().hex,
    }


@dataclass(frozen=True)
class TlsMaterial:
    """A throwaway CA and a server certificate it signed.

    The JWKS endpoint must be reachable over https (the relying party
    refuses anything else), so the simulator signs its own certificate and
    publishes the CA: the client pins it explicitly instead of disabling
    verification.
    """

    ca_cert_pem: bytes
    server_cert_pem: bytes
    server_key_pem: bytes


def generate_tls_material(
    hostnames: tuple[str, ...] = ("localhost", "127.0.0.1"),
) -> TlsMaterial:
    """Generate a CA and a server certificate for the simulator's JWKS host."""
    import datetime as _dt

    now = _dt.datetime.now(_dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "ITS-M Local Simulator CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-M Local Simulator"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    import ipaddress

    san_entries: list[x509.GeneralName] = []
    for host in hostnames:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_entries.append(x509.DNSName(host))
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    return TlsMaterial(
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM),
        server_cert_pem=server_cert.public_bytes(serialization.Encoding.PEM),
        server_key_pem=server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def write_tls_material(material: TlsMaterial, directory: str) -> dict[str, str]:
    """Write the CA, certificate and key to a directory; return the paths."""
    from pathlib import Path

    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca": base / "simulator-ca.pem",
        "cert": base / "simulator-cert.pem",
        "key": base / "simulator-key.pem",
    }
    paths["ca"].write_bytes(material.ca_cert_pem)
    paths["cert"].write_bytes(material.server_cert_pem)
    paths["key"].write_bytes(material.server_key_pem)
    return {name: str(path) for name, path in paths.items()}


__all__ = [
    "KEY_SIZE",
    "SIGNING_ALGORITHM",
    "SigningKey",
    "TlsMaterial",
    "encode_jwt",
    "generate_signing_key",
    "generate_tls_material",
    "mint_claims",
    "write_tls_material",
]
