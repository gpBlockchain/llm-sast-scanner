# SAST Security Report — nervosnetwork/fiber-dashboard
Date: 2026-04-07
Analyzer: llm-sast-scanner v1.3 (GitHub Copilot Custom Agent)

## Executive Summary

The fiber-dashboard repository is a Rust backend (Salvo web framework + sqlx/PostgreSQL) paired with a Next.js frontend. The scan identified **5 confirmed findings** across severity levels: 1 High (SQL injection via `format!`-based query construction in the `/analysis` endpoint), 2 Medium (SQL injection via sort/order interpolation across multiple endpoints, and unsafe mutable static access with data races), 1 Low (overly permissive CORS allowing any origin), and 1 Informational (missing authentication on all API endpoints). Additionally, 1 finding is marked as Unverifiable.

---

## High Findings

```
[HIGH] VULN-001 — SQL Injection (Date-based)  [CONFIRMED]
File: src/pg_read/operates.rs:681-684 (AnalysisParams::to_sql method)
Description: User-supplied date values (start_time, end_time) from the POST /analysis JSON body
  are interpolated directly into SQL via Rust's format!() macro without parameterization.
Impact: An attacker can inject arbitrary SQL through crafted date strings in the JSON body,
  potentially reading, modifying, or deleting data from the PostgreSQL database.
Evidence:
  // src/pg_read/operates.rs, inside AnalysisParams::to_sql():
  sql.push_str(&format!(
      "where day >= '{}'::date and day < '{}'::date ",
      start_time, end_time
  ));
  // start_time and end_time are derived from user-supplied NaiveDate fields
  // in the AnalysisParams struct, deserialized from the POST body.
  // While chrono::NaiveDate has a constrained Display format (%Y-%m-%d),
  // these values are NOT passed via $1/$2 bind parameters — they are
  // string-interpolated directly into the SQL text.
  //
  // The serde deserialization of NaiveDate acts as an implicit allowlist
  // (only valid YYYY-MM-DD strings are accepted), which significantly
  // limits practical exploitation. However, the fundamental pattern is
  // unsafe: any future refactor changing the field type (e.g., to String
  // or a custom type with flexible Display) would immediately create a
  // fully exploitable SQL injection.
  //
  // Additionally, the `fields` parameter in the same struct allows
  // selecting which columns to query. The AnalysisField enum converts
  // to fixed strings ("channels_count", "nodes_count", etc.), so this
  // is safe. However, the `range` field (a free-form Option<String>)
  // is only used in match arms and never interpolated into SQL directly.
Judge: CONFIRMED — The format!-based SQL construction is a textbook SQL injection pattern.
  While NaiveDate's constrained serialization currently limits exploitation, the
  code lacks parameterized queries as a defense layer. The pattern violates secure
  coding practices and is fragile against refactoring.
Remediation: Replace format!-based date interpolation with sqlx bind parameters:
  sql.push_str("where day >= $1::date and day < $2::date ");
  // Then bind start_time and end_time as parameters to sqlx::query()
Reference: references/sql_injection.md
```

---

## Medium Findings

```
[MEDIUM] VULN-002 — SQL Injection (ORDER BY clause interpolation)  [CONFIRMED]
File: src/pg_read/types.rs:269-270, src/pg_read/types.rs:317-318,
      src/pg_read/operates.rs:177-178, src/pg_read/operates.rs:929-930,
      src/pg_read/operates.rs:947-948
Description: Multiple SQL query-building functions interpolate sort_by.as_str() and
  order.as_str() values directly into SQL ORDER BY clauses using format!().
  These values derive from user-supplied query parameters (sort_by, order) via
  Salvo's query extraction. Although the values are constrained by serde
  deserialization into enums (ListNodesHourlySortBy, ChannelSortBy,
  ChannelStateSortBy, Order), the as_str() methods return literal SQL fragments
  (e.g., "n.created_timestamp", "c.last_commit_time", "ASC", "DESC") which
  are string-interpolated into the query.
Impact: Currently limited by enum deserialization — only valid enum variants are accepted.
  However, the code pattern is inherently unsafe. If any enum variant's as_str()
  value were changed to include user-controllable content, or if the enum were
  extended to accept arbitrary strings, SQL injection would be immediately possible.
  The ORDER BY position is exploitable for boolean-based blind SQL injection.
Evidence:
  // src/pg_read/types.rs, fetch_node_by_region():
  let sql = format!(
      r#"... ORDER BY {} {}
      LIMIT {} OFFSET {}"#,
      params.sort_by.as_str(),  // enum-controlled, but interpolated
      params.order.as_str(),     // enum-controlled, but interpolated
      page_size,                 // usize — safe
      offset,                    // usize — safe
  );
  // Same pattern in: fetch_node_fuzzy_by_name_or_id(), fetch_by_page_hourly(),
  // query_channels_by_node_id(), group_channel_by_state()
Judge: CONFIRMED — While exploitation is currently blocked by enum constraints, the code
  violates defense-in-depth principles. The same pattern appears in 5+ query-building
  functions. Severity is Medium because current exploitability requires a code change,
  but the blast radius of a single enum extension is wide.
Remediation: Use a match statement to select from hardcoded SQL fragments rather than
  calling .as_str() and interpolating. Or validate the string against an explicit
  allowlist before interpolation. Better yet, pass LIMIT/OFFSET as bind parameters
  where possible and use a separate approach for ORDER BY.
Reference: references/sql_injection.md
```

```
[MEDIUM] VULN-003 — Unsafe Mutable Static Access (Data Race / UB)  [CONFIRMED]
File: src/ip_location.rs:7-16 (ipinfo_cache function),
      src/ip_location.rs:18-33 (ipinfo function)
Description: The ipinfo_cache() and ipinfo() functions use unsafe blocks to access
  mutable static variables (IPINFO_CACHE, IPINFO) via OnceLock::get_mut().
  The code comments claim "only one thread can access here" but this is not
  enforced — the functions are called from async contexts (lookup_ipinfo) which
  may run concurrently across multiple tokio worker threads.
Impact: Concurrent access to the mutable HashMap and IpInfo client can cause data races,
  leading to undefined behavior in Rust. This could result in memory corruption,
  crashes, or potentially exploitable memory safety issues. In a multi-threaded
  tokio runtime (used by the application, as shown in Cargo.toml with
  "rt-multi-thread"), this is a real concern.
Evidence:
  // src/ip_location.rs
  #[allow(static_mut_refs)]
  fn ipinfo_cache() -> &'static mut HashMap<String, IpDetails> {
      static mut IPINFO_CACHE: OnceLock<HashMap<String, IpDetails>> = OnceLock::new();
      // Safety: only one thread can access here  <-- NOT TRUE
      unsafe {
          IPINFO_CACHE.get_or_init(Default::default);
          IPINFO_CACHE.get_mut().unwrap()
      }
  }
  // Called from:
  pub async fn lookup_ipinfo(ip: &str) -> Result<IpDetails, IpError> {
      let global_ipinfo_cache = ipinfo_cache();  // race condition
      ...
  }
Judge: CONFIRMED — The rt-multi-thread tokio runtime means multiple worker threads can
  call lookup_ipinfo() concurrently. The #[allow(static_mut_refs)] suppression
  explicitly silences the compiler's warning about this exact unsafe pattern.
  This is a soundness bug that violates Rust's safety guarantees.
Remediation: Replace the unsafe mutable statics with thread-safe alternatives:
  - Use std::sync::Mutex<HashMap<String, IpDetails>> or tokio::sync::Mutex
  - Or use a concurrent hashmap like dashmap
  - Or use std::sync::OnceLock<Mutex<IpInfo>> for the IpInfo client
Reference: N/A (memory safety / undefined behavior)
```

---

## Low Findings

```
[LOW] VULN-004 — Overly Permissive CORS Policy  [CONFIRMED]
File: src/bin/fiber-dashbord.rs:80-83 (http_server function)
Description: The HTTP server configures CORS with AllowOrigin::any(), permitting
  requests from any origin. While the API is read-only for most endpoints,
  the POST endpoints (/analysis, /nodes_by_udt) accept cross-origin requests
  from any website.
Impact: Any website can make authenticated cross-origin requests to the API.
  Since no authentication is implemented, this primarily means any website
  can embed and exfiltrate the dashboard's network topology data (node IPs,
  channel information, etc.). If authentication were added in the future
  without fixing CORS, it would enable CSRF-like attacks.
Evidence:
  // src/bin/fiber-dashbord.rs
  let cors = Cors::new()
      .allow_origin(AllowOrigin::any())
      .allow_headers(vec!["content-type", "accept", "authorization"])
      .allow_methods(vec![Method::GET, Method::POST, Method::OPTIONS])
      .into_handler();
Judge: CONFIRMED — The wildcard origin is intentional for a public dashboard API, but it
  weakens defense-in-depth. The authorization header is allowed in CORS but no
  authentication is implemented, creating a misleading configuration.
Remediation: Restrict AllowOrigin to the known frontend domain(s) rather than using
  any(). Remove "authorization" from allowed headers if authentication is not
  implemented.
Reference: references/csrf.md
```

---

## Informational

```
[INFO] VULN-005 — No Authentication on API Endpoints  [CONFIRMED]
File: src/bin/fiber-dashbord.rs:85-110 (router definition)
Description: All 19 HTTP API endpoints are publicly accessible without any form of
  authentication or rate limiting. This includes both GET and POST endpoints
  that expose network topology data (node IPs/locations, channel details,
  financial capacities).
Impact: All network data is publicly accessible. While this may be intentional for a
  public dashboard, the exposed data includes:
  - Node IP addresses with geolocation (country, city, region, coordinates)
  - Channel capacity and financial state information
  - Node identity public keys and addresses
  The health_check endpoint also exposes internal heartbeat timestamps of
  background tasks.
Evidence:
  // All routes are defined without any auth middleware:
  let router = Router::new()
      .push(Router::with_path("nodes_hourly").get(list_nodes_hourly))
      .push(Router::with_path("channels_hourly").get(list_channels_hourly))
      // ... 17 more endpoints, none with auth middleware
Judge: CONFIRMED — This appears to be by design for a public blockchain network dashboard.
  However, the exposure of IP geolocation data for network nodes could be sensitive.
  Marked as informational since authentication at the network layer may be intended.
Remediation: If the data is meant to be public, consider at minimum adding rate limiting
  to prevent abuse. If node geolocation data is sensitive, add authentication to
  those specific endpoints.
Reference: references/information_disclosure.md
```

---

## Unverifiable Findings

```
[UNVERIFIABLE] VULN-006 — Default PostgreSQL Password in .env.example
File: .env.example:1
Blocked by: Cannot determine if the .env.example value "password" is used in production
  deployments. The compose.yaml uses ${POSTGRES_PASSWORD} which reads from .env,
  and the fallback in src/lib.rs:21 includes a hardcoded connection string
  "postgres://postgres:password@localhost:5432/postgres" — but this is only used
  when DATABASE_URL env var is not set. Additionally, compose.yaml sets
  POSTGRES_HOST_AUTH_METHOD: trust which bypasses password authentication entirely
  for the containerized PostgreSQL instance, making the password field irrelevant
  in that deployment context. The trust auth method means any connection to the
  database is accepted without a password, but this is mitigated by Docker
  networking (the database is only accessible within the fiber-network bridge).
```

---

## Remediation Priority

1. **VULN-001** (High) — Replace `format!`-based date interpolation in `AnalysisParams::to_sql()` with sqlx bind parameters. This is the most directly exploitable finding and the simplest to fix.

2. **VULN-003** (Medium) — Replace unsafe mutable statics in `ip_location.rs` with thread-safe alternatives (`Mutex`, `dashmap`, or `tokio::sync::RwLock`). This is a soundness bug that could cause crashes or memory corruption under concurrent load.

3. **VULN-002** (Medium) — Refactor all ORDER BY clause construction to avoid string interpolation. While currently protected by enum constraints, the pattern is fragile and repeated across 5+ functions.

4. **VULN-004** (Low) — Restrict CORS `AllowOrigin` to the actual frontend domain. Remove unused `authorization` from allowed headers.

5. **VULN-005** (Info) — Consider adding rate limiting to prevent API abuse. Evaluate whether node geolocation data exposure requires access controls.
