"""CLI for the LOCAL identity simulator — development and staging only.

    python -m itsm_agent.simulators.identity \\
        --issuer https://issuer.simulator.test --audience itsm-audience \\
        --subject reviewer-a --subject reviewer-b

serves until interrupted (serving is the default mode) and prints the JWKS
URL, the token URL and the CA path. ``--token --mint-subject ...`` mints a
token for a subject instead.

Every output is labelled as simulator output: this is not an identity
provider and it holds no application authorization.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from itsm_agent.simulators.identity import __simulator_notice__
from itsm_agent.simulators.identity.client import fetch_token
from itsm_agent.simulators.identity.keys import (
    generate_signing_key,
    generate_tls_material,
    load_tls_material,
    write_tls_material,
)
from itsm_agent.simulators.identity.server import assert_loopback, run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="identity-simulator",
        description=__simulator_notice__,
    )
    parser.add_argument("--issuer", default="https://issuer.simulator.test")
    parser.add_argument("--audience", default="itsm-audience")
    parser.add_argument(
        "--subject",
        action="append",
        default=[],
        help="subject the simulator may mint tokens for; repeat for several",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--public-url",
        default="",
        help="base URL advertised in discovery (default: https://<host>:<port>)",
    )
    parser.add_argument(
        "--tls-hostname",
        action="append",
        default=[],
        help="hostname/IP the served certificate must cover; repeat for several "
        "(default: localhost and 127.0.0.1)",
    )
    parser.add_argument(
        "--allow-container-bind",
        action="store_true",
        help="permit a wildcard bind inside an isolated container network; "
        "loopback remains the default and the only option without this flag",
    )
    parser.add_argument(
        "--state-dir",
        default="/tmp/itsm-identity-simulator",
        help="where the CA and certificate are written",
    )
    parser.add_argument(
        "--token",
        action="store_true",
        help="mint a token for --mint-subject and exit instead of serving",
    )
    parser.add_argument("--mint-subject", default="")
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--base-url", default="")
    return parser


async def _mint(args: argparse.Namespace) -> int:
    if not args.mint_subject:
        print("refused: --mint-subject is required with --token", file=sys.stderr)
        return 2
    if not args.ca_file or not args.base_url:
        print(
            "refused: --ca-file and --base-url are required to mint a token",
            file=sys.stderr,
        )
        return 2
    token = await fetch_token(
        base_url=args.base_url,
        subject=args.mint_subject,
        ca_path=args.ca_file,
    )
    print(json.dumps({"access_token": token, "mode": "simulator"}, indent=2))
    return 0


async def _serve(args: argparse.Namespace) -> int:
    subjects = tuple(dict.fromkeys(args.subject)) or ("reviewer-a",)
    key = generate_signing_key()
    # One material for both the served certificate and the published CA
    # path: the client pins exactly the CA that signed the certificate.
    hostnames = tuple(dict.fromkeys(args.tls_hostname)) or ("localhost", "127.0.0.1")
    # A restart must not replace a CA that a running API already trusts: HTTPX
    # builds its TLS context once and will not re-read the file. Reuse valid
    # material and regenerate only when it can no longer serve these hostnames.
    material = load_tls_material(args.state_dir, hostnames)
    reused = material is not None
    if material is None:
        material = generate_tls_material(hostnames)
    material_paths = write_tls_material(material, args.state_dir)
    base_url = args.public_url or f"https://{args.host}:{args.port}"
    print(
        json.dumps(
            {
                "mode": "simulator",
                "notice": __simulator_notice__,
                "issuer": args.issuer,
                "audience": args.audience,
                "jwks_url": f"{base_url}/jwks",
                "token_url": f"{base_url}/token",
                "discovery_url": f"{base_url}/.well-known/openid-configuration",
                "ca_file": material_paths["ca"],
                "subjects": list(subjects),
                "kid": key.kid,
                "tls_hostnames": list(hostnames),
                "tls_material_reused": reused,
            },
            indent=2,
        ),
        flush=True,
    )
    await run(
        issuer=args.issuer,
        audience=args.audience,
        subjects=subjects,
        host=args.host,
        port=args.port,
        state_dir=args.state_dir,
        key=key,
        material=material,
        allow_container_bind=args.allow_container_bind,
        base_url=base_url,
    )
    return 0


#: The only environments this simulator may run in. There is no production
#: value: the platform's own environment vocabulary stops at "staging".
ALLOWED_ENVIRONMENTS = ("local", "test", "staging")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        assert_loopback(args.host, allow_container_bind=args.allow_container_bind)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    environment = os.environ.get("ITSM_ENV", "local").strip().lower()
    if environment not in ALLOWED_ENVIRONMENTS:
        print(
            "refused: the identity simulator may only run in "
            f"{ALLOWED_ENVIRONMENTS}, not {environment!r}",
            file=sys.stderr,
        )
        return 2
    if args.token:
        return asyncio.run(_mint(args))
    return asyncio.run(_serve(args))


if __name__ == "__main__":  # pragma: no cover - process boundary
    raise SystemExit(main())
