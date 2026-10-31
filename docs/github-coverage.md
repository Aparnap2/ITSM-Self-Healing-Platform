# GitHub Organization Audit Coverage (Task 10)

## Supported events

- Organization membership changes (add/remove member).
- Team membership changes.
- Repository permission changes.
- Repository security-setting changes (where available).

## Pagination and rate limits

- Cursor pagination via Link header.
- Authenticated rate limit ~5000 req/hr; 429 stops ingestion for retry.
- Checkpointed by timestamp.

## Limitations

- Audit log retention varies by GitHub plan (Enterprise vs Team).
- Some event types unavailable on lower plans.
- No real GitHub credentials in baseline; respx fixtures used.
