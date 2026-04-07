# SAST Security Report — gpBlockchain/app_view

Date: 2026-04-07
Analyzer: llm-sast-scanner v1.3 (GitHub Copilot Custom Agent)

## Executive Summary

The **app_view** repository is a Rust-based DAO governance application built on Axum (web framework), SQLx with Sea-Query (PostgreSQL query builder), and the CKB blockchain SDK. A full audit of all 49 source files identified **5 findings**: 1 Medium, 3 Low, and 1 Informational. The most critical issue is a denial-of-service vulnerability caused by a memory leak in the error handling path that permanently allocates heap memory for every error response. No SQL injection, RCE, or authentication bypass vulnerabilities were found; database queries consistently use parameterized bindings through Sea-Query/SQLx, and write endpoints enforce DID-based ECDSA signature verification.

## Critical Findings

_None identified._

## High Findings

_None identified._

## Medium Findings

```
[MEDIUM] VULN-001 — Denial of Service (Memory Leak)  [CONFIRMED]
File: src/error.rs:65-66
Description: The `string_to_static_str` function uses `Box::leak` to permanently
  allocate heap memory for every error response string, creating memory that can
  never be reclaimed by the allocator.
Impact: An attacker can trigger thousands of validation errors per second (e.g.,
  by sending requests with invalid parameters to any public endpoint), each of
  which permanently leaks a heap-allocated string. Over time, server memory usage
  grows monotonically until the process is killed by the OOM killer, causing a
  denial of service.
Evidence:
  // src/error.rs:65-66
  fn string_to_static_str(s: String) -> &'static str {
      Box::leak(s.into_boxed_str())
  }

  // Called on every error response path (lines 24, 29, 34, 39, 44):
  AppError::ValidateFailed(msg) => (
      StatusCode::BAD_REQUEST,
      "ValidateFailed",
      string_to_static_str(msg),  // leaks user-influenced string
  ),
  AppError::Unknown(msg) => (
      StatusCode::INTERNAL_SERVER_ERROR,
      "ServerError",
      string_to_static_str(msg),  // leaks internal error string
  ),
Judge: CONFIRMED — The `Box::leak` call is unconditional on every error path.
  No public endpoint requires authentication for triggering validation errors
  (any POST with an invalid body, any GET with missing required parameters).
  The 10-second TimeoutLayer does not mitigate this since error responses are
  generated immediately. There is no memory cap or eviction mechanism.
Remediation: Remove `Box::leak` and return an owned `String` instead. Axum's
  `IntoResponse` supports owned strings natively. Replace the error response
  construction with:
    let body = Json(json!({
        "code": status.as_u16(),
        "error": error,
        "message": error_message,
    }));
  where `error_message` is a `String` rather than `&'static str`. Alternatively,
  use `Cow<'static, str>` for fixed messages and owned strings for dynamic ones.
Reference: references/denial_of_service.md
```

## Low Findings

```
[LOW] VULN-002 — Information Disclosure in Error Responses  [CONFIRMED]
File: src/error.rs:36-44
Description: Internal error details from the PDS server and from arbitrary library
  errors are returned verbatim to API clients in JSON error responses.
Impact: An attacker can learn internal service topology, library error messages,
  and PDS server behavior by triggering error conditions, aiding further attack
  reconnaissance.
Evidence:
  // src/error.rs:36-39 — PDS error details exposed
  AppError::CallPdsFailed(msg) => (
      StatusCode::INTERNAL_SERVER_ERROR,
      "CallPdsFailed",
      string_to_static_str(json!({"pds": msg}).to_string()),
  ),

  // src/error.rs:41-44 — Generic catch-all exposes any error
  AppError::Unknown(msg) => (
      StatusCode::INTERNAL_SERVER_ERROR,
      "ServerError",
      string_to_static_str(msg),  // raw error from any From<E> conversion
  ),

  // src/error.rs:57-62 — blanket From impl converts all errors
  impl<E> From<E> for AppError where E: Into<Error> {
      fn from(err: E) -> Self {
          Self::Unknown(err.into().to_string())
      }
  }
Judge: CONFIRMED — The `From<E>` blanket impl converts all errors (including
  database errors, serialization errors, blockchain RPC errors) into
  `AppError::Unknown` which returns the raw error message to the client. While
  `ExecSqlFailed` correctly hides the detail, `Unknown` does not.
Remediation: Replace dynamic error messages in client responses with generic
  messages (e.g., "Internal server error") and log the detailed error server-side
  using `error!()` or `tracing::error!()`. Return only a correlation/request ID
  to the client for debugging.
Reference: references/information_disclosure.md
```

```
[LOW] VULN-003 — Unbounded Pagination Limit  [CONFIRMED]
File: src/api/reply.rs:31, src/api/like.rs:31, src/api/proposal.rs:39
Description: Multiple query structs accept a `limit: u64` field from user input
  without any maximum bound validation, allowing clients to request arbitrarily
  large result sets from the database.
Impact: An attacker can set `limit` to `u64::MAX` to force the database to attempt
  returning all rows, consuming excessive database CPU, memory, and network bandwidth.
  Combined with the 5-connection database pool limit, this can degrade service for
  all users.
Evidence:
  // src/api/reply.rs:25-37
  pub struct ReplyQuery {
      pub limit: u64,  // no #[validate(range(max = ...))]
  }

  // src/api/like.rs:25-37
  pub struct LikeQuery {
      pub limit: u64,  // no #[validate(range(max = ...))]
  }

  // src/api/proposal.rs:33-47
  pub struct ProposalQuery {
      pub limit: u64,  // no #[validate(range(max = ...))]
  }

  // Compare with properly bounded pagination in vote.rs:
  pub struct ListSelfQuery {
      #[validate(range(min = 1))]
      pub per_page: u64,  // has min but no max
  }
Judge: CONFIRMED — The `limit` field is passed directly to `.limit(query.limit)`
  in the Sea-Query builder. The TimeoutLayer (10s) partially mitigates impact but
  a single slow query can block one of only 5 database pool connections.
Remediation: Add `#[validate(range(min = 1, max = 100))]` to all `limit` and
  `per_page` fields. Apply a server-side cap (e.g., `query.limit.min(100)`) before
  passing to the query builder as a defense-in-depth measure.
Reference: references/denial_of_service.md
```

```
[LOW] VULN-004 — Race Condition in Vote Meta Creation  [LIKELY]
File: src/api/mod.rs:216-258
Description: The `create_vote_tx` function performs a non-atomic check-then-insert
  for VoteMeta records. Two concurrent requests for the same proposal can both pass
  the existence check and create duplicate VoteMeta entries.
Impact: Duplicate VoteMeta entries for the same proposal and state can cause
  inconsistency in the voting process. The on-chain settlement layer mitigates
  financial risk, but the application layer may display incorrect vote status
  or allow multiple vote transactions to be initiated for the same proposal vote.
Evidence:
  // src/api/mod.rs:229-250
  let vote_meta_row = if let Ok(vote_meta_row) =
      sqlx::query_as_with::<_, VoteMetaRow, _>(&sql, value)
          .fetch_one(&state.db)
          .await
  {
      vote_meta_row          // Path A: existing row found
  } else {
      // ...
      vote_meta_row.id = VoteMeta::insert(&state.db, &vote_meta_row).await?;
      vote_meta_row          // Path B: new row created
  };

  // No UNIQUE constraint on (proposal_uri, proposal_state) in VoteMeta table.
  // No SELECT ... FOR UPDATE or advisory lock to prevent concurrent creation.
Judge: LIKELY — The race window exists between the SELECT and INSERT. While the
  on-chain blockchain settlement layer prevents actual double-voting, duplicate
  VoteMeta records could cause confusing UX and incorrect vote tallying in the
  application layer. Exploitation requires concurrent requests which is feasible
  but impact is bounded by the blockchain settlement.
Remediation: Add a UNIQUE constraint on `(proposal_uri, proposal_state)` in the
  VoteMeta table, or use `INSERT ... ON CONFLICT` (upsert) to atomically handle
  the create-or-fetch pattern. Alternatively, use `SELECT ... FOR UPDATE` within
  a database transaction.
Reference: references/race_conditions.md
```

## Informational

```
[INFO] VULN-005 — Permissive CORS Configuration
File: src/main.rs:203
Description: The application uses `CorsLayer::permissive()` which allows requests
  from any origin with any headers and methods.
Impact: Any website can make cross-origin requests to and read responses from
  this API. Since the API uses signature-based authentication (not cookie-based),
  this does not enable CSRF attacks. All read endpoints are public by design.
  However, the permissive policy means any third-party website can programmatically
  query the API on behalf of its visitors.
Evidence:
  // src/main.rs:203
  .layer(CorsLayer::permissive())
Judge: This is appropriate for a public DAO governance API designed to be consumed
  by any frontend. The signature-based authentication model (DID ECDSA signatures
  in request bodies) is not vulnerable to CSRF regardless of CORS policy. Noted
  as informational for documentation purposes.
Remediation: If the API is intended to be consumed only from known frontends,
  replace `CorsLayer::permissive()` with an explicit allowlist of origins.
  Otherwise, document the permissive CORS policy as an intentional design decision.
Reference: references/csrf.md
```

## Unverifiable Findings

_None._

## Remediation Priority

1. **VULN-001 (Memory Leak DoS)** — Remove `Box::leak` from error handling. This is the highest priority as it enables unauthenticated remote denial of service with trivial exploitation effort.
2. **VULN-002 (Information Disclosure)** — Replace verbose error messages in client responses with generic messages and log details server-side.
3. **VULN-003 (Unbounded Pagination)** — Add maximum bound validation to all `limit`/`per_page` query parameters across all API endpoints.
4. **VULN-004 (Race Condition)** — Add a UNIQUE constraint or use atomic upsert for VoteMeta creation.
5. **VULN-005 (Permissive CORS)** — Document as intentional or restrict to known frontends.

---

## Appendix: Analysis Summary

### Technology Stack
- **Language**: Rust (edition 2024), `unsafe_code = "forbid"`
- **Web Framework**: Axum (via `common_x::restful`)
- **Database**: PostgreSQL via SQLx + Sea-Query (parameterized query builder)
- **HTTP Client**: reqwest (for outbound API calls to indexers and PDS)
- **Authentication**: DID-based ECDSA signature verification (k256)
- **Blockchain**: CKB (Nervos Network) SDK for on-chain vote settlement
- **Protocol**: AT Protocol (atrium-api) for social data relay

### Areas Analyzed
- All 49 source files across `src/api/`, `src/lexicon/`, `src/scheduler/`, `src/relayer/`
- SQL injection: All queries use Sea-Query + SQLx parameterized bindings. `Expr::cust_with_values` is used correctly with `$N` placeholders for all user inputs. **No SQL injection found.**
- SSRF: Outbound HTTP targets (`pds`, `indexer_*_url`) are operator-configured via CLI flags. User input only controls path segments or query parameters on trusted internal services. **No SSRF found.**
- XSS: Pure REST/JSON API with no HTML rendering. Not applicable.
- RCE: `unsafe_code = "forbid"` in Cargo.toml. No shell execution, `eval`, or deserialization of untrusted formats. **No RCE found.**
- Authentication: Write endpoints consistently require DID-based ECDSA signature verification with 5-minute timestamp window. Ownership and admin checks are applied where appropriate.
- Secrets: No hardcoded credentials. Database URL passed via CLI flag and environment variable. API documentation gated behind opt-in `--apidoc` flag.
