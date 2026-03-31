# @squip/hyperpipe-core

`@squip/hyperpipe-core` is the first-party Hyperpipe runtime engine.

Package contract:

- the package root is side-effect free
- the supported process entrypoint is the `hyperpipe-core` binary
- stable public surface is limited to protocol/config helpers and versioned runtime
  launch integration through `@squip/hyperpipe-core-host`

Internal runtime modules remain implementation details unless they are explicitly
documented and exported as part of a future public API.

Logging defaults:

- production-safe redaction is enabled for auth tokens, secrets, cookies, invite material,
  and `nsec`-like values that appear in log payloads
- noisy infrastructure traces are suppressed by default
- use `HYPERPIPE_CORE_LOG_LEVEL=debug` to enable verbose diagnostics
- use `HYPERPIPE_CORE_SUPPRESS_NOISE=false` to re-enable suppressed trace families

Join runtime defaults:

- direct discovery v2 is enabled by default
- total join deadline is disabled by default
- relay protocol request timeout is disabled by default
- direct join verify timeout is disabled by default

The older env vars still work as explicit overrides:

- `JOIN_DIRECT_DISCOVERY_V2`
- `JOIN_TOTAL_DEADLINE_MS`
- `RELAY_PROTOCOL_REQUEST_TIMEOUT_MS`
- `DIRECT_JOIN_VERIFY_TIMEOUT_MS`
