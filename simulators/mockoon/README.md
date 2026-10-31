# Mockoon simulators — deterministic acceptance environment

One Mockoon CLI instance (port 3001) serves all three simulated external APIs:
the ITSM API, the identity API, and the infrastructure API. This is the
deterministic acceptance environment required by the PRD — real SaaS adapters
(Jira, ServiceNow) are optional and never required for tests.

## File

- `mockoon.json` — the Mockoon data file mounted read-only into the
  `mockoon/cli:9.5.0` container by `compose.yaml`
  (`./simulators/mockoon/mockoon.json:/home/mockoon/data/mockoon.json:ro`).

## Routes and fault injection

| Route | Behavior |
| --- | --- |
| `GET /health` | Always `200` — used by the compose healthcheck. |
| `POST /api/v1/incidents` | `201`, echoes `title`/`severity`/`affected_service` from the request body. |
| `GET /api/v1/incidents` | `200`, empty list. |
| `GET /api/v1/incidents/:incidentId` | `200`, echoes the incident id. |
| `PATCH /api/v1/incidents/:incidentId` | `200`, echoes requested `status`. |
| `GET /api/v1/identity/principals/principal-sim-001` | `200`, known principal. **Declared before** the `:principalId` route so the literal path wins. |
| `GET /api/v1/identity/principals/:principalId` | `404` — unknown principals fail closed. |
| `GET /api/v1/services/:serviceId/health` | `200` by default; `503` when request header `x-sim-health-state: unhealthy`; `200` + degraded body when `x-sim-health-state: degraded`. |
| `POST /api/v1/actions/restart-service` | `200` by default; `503` when header `x-sim-fault-mode: transient_fail`; `200` after 5 s latency when `x-sim-fault-mode: timeout_then_success` (caller timeout → uncertain outcome → reconciliation path); `500` when `x-sim-fault-mode: always_fail`. |

Fault injection is header-driven so tests stay deterministic and parallel-safe:
each request chooses its own scenario via `x-sim-health-state` /
`x-sim-fault-mode` instead of mutating shared simulator state.

## Schema notes (verified against Mockoon 9.5.0)

- The image `ENTRYPOINT` is `mockoon-cli start`; `compose.yaml` therefore
  passes only flags (`--data ... --port 3001 --disable-admin-api`).
- `lastMigration: 33` is set conservatively. Mockoon runs in-memory migrations
  for lower values and errors for higher ones — if the file fails to load,
  check the container logs first.
- The data-file schema uses `stripUnknown: true`: unknown fields are dropped
  silently, so schema drift fails as missing behavior, not as a load error.
- Conditional responses are declared before the `default: true` response;
  Mockoon evaluates rules top-down.
- The admin API (`/mockoon-admin/`) is disabled via `--disable-admin-api`.

## Verification

```sh
# Schema/semantic validation (no server started):
docker run --rm --entrypoint mockoon-cli -v "$PWD/simulators/mockoon:/data:ro" \
  mockoon/cli:9.5.0 validate --data /data/mockoon.json

# Live smoke test:
docker compose up -d mockoon
curl -s http://127.0.0.1:3001/health
curl -s -H 'x-sim-health-state: unhealthy' http://127.0.0.1:3001/api/v1/services/payments-api/health -i
```

## Licensing

Mockoon is MIT-licensed; the CLI image is free for this use. No SaaS plan or
account is required.
