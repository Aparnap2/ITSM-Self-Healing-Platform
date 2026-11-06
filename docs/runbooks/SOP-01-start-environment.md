# SOP-01 — Start and verify the local environment

Scope: local Docker Compose stack for the ITSM self-healing platform.
Audience: developers and agents running deterministic tests locally.

## Prerequisites

- Docker Engine with Compose v2 (`docker compose version`).
- `uv` for Python tooling (`uv --version`).
- A `.env` file at the repo root (see below).

## Required `.env` keys

> NOTE: `.env.example` could not be committed because the workspace permission
> rules deny writing `*.env*` files. Copy the keys below into a local `.env`
> (gitignored) manually. Never commit `.env`.

```sh
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=itsm
POSTGRES_USER=itsm
POSTGRES_PASSWORD=<alphanumeric-password>   # required; compose fails closed without it
POSTGRES_HOST_PORT=5432
DATABASE_URL=postgresql://itsm:<alphanumeric-password>@127.0.0.1:5432/itsm
NATS_URL=nats://127.0.0.1:4222
NATS_HOST_PORT=4222
NATS_MONITOR_HOST_PORT=8222
MOCKOON_HOST_PORT=3001
ITSM_API_BASE_URL=http://127.0.0.1:3001
IDENTITY_API_BASE_URL=http://127.0.0.1:3001
INFRA_API_BASE_URL=http://127.0.0.1:3001
API_HOST_PORT=8000
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
PROMETHEUS_HOST_PORT=9090
LOG_LEVEL=INFO
GROQ_API_KEY=                                # optional; deterministic tests must not need it
```

Use an alphanumeric password: the value is embedded into `DATABASE_URL`.

## Start

```sh
make compose-up          # docker compose up -d --wait (waits for healthchecks)
docker compose ps        # all services healthy/running
```

## Port map (all bound to 127.0.0.1)

| Service | Port | Notes |
| --- | --- | --- |
| postgres | 5432 | durable business state (source of truth) |
| nats | 4222 | JetStream; monitor port 8222 |
| mockoon | 3001 | ITSM + identity + infra simulators |
| api | 8000 | application API (app slice) |
| prometheus | 9090 | metrics UI |
| otel-collector | 4317 / 4318 | OTLP gRPC / HTTP |
| localstack | 4566 | opt-in: `docker compose --profile localstack up -d` |

## Verify

```sh
curl -s http://127.0.0.1:3001/health                                   # mockoon
curl -s http://127.0.0.1:9090/-/healthy                                # prometheus
docker compose exec nats nats-server --help >/dev/null && echo nats-ok
docker compose exec postgres pg_isready -U itsm                        # postgres
```

## Stop / reset

```sh
make compose-down       # stop, keep volumes
make compose-reset      # stop and DELETE volumes (guarded: refuses non-local DATABASE_URL)
```

## Troubleshooting

- **Mockoon container unhealthy / config not loaded**: check
  `docker compose logs mockoon`. The data-file schema uses `stripUnknown`, so
  schema drift fails as missing routes rather than a load error. The
  `lastMigration` value (33) must not exceed the CLI's current migration
  version.
- **NATS JetStream write errors**: if the `nats-data` named volume is
  root-owned the JetStream store may be unwritable; check
  `docker compose logs nats`. Fallback: change the JetStream `store_dir` to an
  ephemeral path and document the trade-off.
- **Port conflicts**: all host ports are overridable via `.env`
  (`*_HOST_PORT`). Observed example: `Bind for 0.0.0.0:5432 failed: port is
  already allocated` when another project's postgres owns host port 5432 —
  set `POSTGRES_HOST_PORT=55432` (and update `DATABASE_URL` to match) and
  re-run `docker compose up -d postgres`. Verified working on 2026-10-28.

## Licensing notes

- Moto (Apache-2.0) is the default AWS API simulator, used in-process via
  pytest — no container, no SaaS.
- LocalStack is quarantined behind the opt-in `localstack` compose profile
  (see ADR-0003 for license/plan terms).
- Mockoon is MIT-licensed; no account or SaaS plan required.
- Ollama is optional; deterministic tests never require it.
