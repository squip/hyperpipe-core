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
