"""TLS material reuse for the local identity simulator.

A restart must not silently invalidate a CA that a running relying party has
already pinned: HTTPX builds its TLS context once and does not re-read the
file, so a regenerated CA turns every later JWKS fetch into a failure with no
obvious cause.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from itsm_agent.simulators.identity.keys import (
    generate_tls_material,
    load_tls_material,
    write_tls_material,
)


def test_written_material_is_reusable_byte_for_byte(tmp_path: Path) -> None:
    material = generate_tls_material(("identity", "localhost", "127.0.0.1"))
    write_tls_material(material, str(tmp_path))

    loaded = load_tls_material(str(tmp_path), ("identity", "localhost", "127.0.0.1"))

    assert loaded is not None
    assert loaded.ca_cert_pem == material.ca_cert_pem
    assert loaded.server_cert_pem == material.server_cert_pem
    assert loaded.server_key_pem == material.server_key_pem


def test_absent_material_is_not_reused(tmp_path: Path) -> None:
    assert load_tls_material(str(tmp_path), ("localhost",)) is None


def test_material_that_does_not_cover_a_hostname_is_not_reused(tmp_path: Path) -> None:
    write_tls_material(generate_tls_material(("localhost",)), str(tmp_path))

    assert load_tls_material(str(tmp_path), ("identity",)) is None


def test_material_that_is_about_to_expire_is_not_reused(tmp_path: Path) -> None:
    write_tls_material(generate_tls_material(("localhost",)), str(tmp_path))

    later = datetime.now(UTC) + timedelta(hours=23, minutes=30)

    assert load_tls_material(str(tmp_path), ("localhost",), now=later) is None


def test_a_corrupt_key_file_is_not_reused(tmp_path: Path) -> None:
    material = generate_tls_material(("localhost",))
    paths = write_tls_material(material, str(tmp_path))
    Path(paths["key"]).write_bytes(b"not a key")

    assert load_tls_material(str(tmp_path), ("localhost",)) is None
