# SAST Security Report — CCF-DAO1-1/ckb-fund-dao-ui

Date: 2026-04-07
Analyzer: llm-sast-scanner v1.3 (GitHub Copilot Custom Agent)

## Executive Summary

The **ckb-fund-dao-ui** repository is a Next.js 15 / React 19 / TypeScript DAO governance frontend for the CKB (Nervos Network) blockchain. The application uses AT Protocol (web5-api) for identity management, Secp256k1 ECDSA key-pair authentication, and connects to a backend API server for proposal management, voting, and treasury operations. A full audit of all ~130 source files identified **5 findings**: 1 High, 2 Medium, 1 Low, and 1 Informational. The most critical issue is the storage of private cryptographic signing keys in browser `localStorage` without encryption, which is accessible to any XSS vector. The application demonstrates good XSS hygiene overall — all `dangerouslySetInnerHTML` sinks consistently use DOMPurify sanitization, with one notable exception.

## Critical Findings

_None identified._

## High Findings

```
[HIGH] VULN-001 — Sensitive Key Material in localStorage (Insecure Storage)  [CONFIRMED]
File: src/lib/storage.ts:57-60, src/lib/signature.ts:17-19, src/hooks/createAccount.ts (multiple)
Description: The user's private Secp256k1 signing key (signKey) is stored in
  plaintext in browser localStorage under the key '@dao:client'. This key is used
  for all authenticated operations (proposals, votes, comments, account management).
Impact: Any successful XSS attack — even a transient reflected XSS via a
  third-party dependency, browser extension, or a bypass of DOMPurify — can
  exfiltrate the user's private signing key. With the signing key, an attacker can
  impersonate the user: create proposals, cast votes, submit reports, and manage
  the user's DAO identity. Unlike session tokens which can be rotated, a compromised
  signing key requires full account recreation on-chain.
Evidence:
  // src/lib/storage.ts:57-60 — signing key stored in plaintext
  setToken: clientRun((accTokenVal: TokenStorageType) => {
    window.localStorage.setItem(ACCESS_TOKEN_STORE_KEY, JSON.stringify(accTokenVal));
  }),

  // src/lib/storage.ts:12 — TokenStorageType includes signKey
  export type TokenStorageType = {
    did: string
    walletAddress: string
    signKey: string          // <-- private key in plaintext
  }

  // src/lib/signature.ts:17-19 — signKey read for every signature operation
  const storageInfo = storage.getToken();
  if (!storageInfo?.signKey) {
      throw new Error("User not logged in or missing sign key");
  }
  const keyPair = await Secp256k1Keypair.import(storageInfo.signKey.slice(2));

  // src/components/user-center/KeyQRCodeModal.tsx:42-49 — signKey exposed in QR code
  const data = {
    did: tokenData.did,
    signKey: tokenData.signKey,        // private key in QR code
    walletAddress: tokenData.walletAddress,
    password: password,                 // 4-digit PIN
    timestamp: Date.now(),
  };
Judge: CONFIRMED — The signing key is the user's primary credential and is stored
  in an unencrypted form accessible to any JavaScript running in the page context.
  localStorage has no origin-isolation beyond same-origin policy and is not
  protected from XSS like HttpOnly cookies. The export functionality
  (ExportDIDInfoModal) does encrypt the key with AES-GCM before export, proving
  the codebase has encryption capability — but this is not applied to at-rest
  storage. The QR code export uses only a 4-digit PIN (10,000 possible values)
  as the "password" for the plaintext JSON.
Remediation:
  1. Store the signing key encrypted at rest using Web Crypto API (AES-GCM)
     with a key derived from the user's wallet signature or a password via
     PBKDF2 (as already implemented in encrypt.ts). Decrypt only when needed
     for signing operations.
  2. Consider using the Web Crypto API's non-extractable CryptoKey
     (crypto.subtle.importKey with extractable: false) for signing operations
     where the key never leaves the secure keystore.
  3. For the QR code export, require a minimum 8-character alphanumeric
     password (matching the file export requirement) and encrypt the QR data
     with AES-GCM before encoding.
  4. Add Content-Security-Policy headers to limit script execution origins
     as defense-in-depth against XSS-based key theft.
Reference: references/insecure_storage.md
```

## Medium Findings

```
[MEDIUM] VULN-002 — Stored XSS via Unsanitized dangerouslySetInnerHTML  [CONFIRMED]
File: src/components/user-center/DiscussionRecordsTable.tsx:172
Description: The DiscussionRecordsTable component renders comment content using
  dangerouslySetInnerHTML without applying DOMPurify sanitization to the final
  output, despite having a renderContent() function that sanitizes HTML. The
  record.commentContent field is sanitized at line 90 via renderContent(), but
  there is an inconsistency in the data flow: the useMemo transformation applies
  renderContent() to the text field, producing sanitized commentContent. However,
  any code path that directly sets commentContent without going through
  renderContent() would bypass sanitization.
Impact: If an attacker stores malicious HTML in a comment via the backend (which
  accepts HTML-formatted text), and any code path bypasses the renderContent()
  sanitization, the XSS payload would execute in the context of any user viewing
  their discussion records. Combined with VULN-001, this could lead to signing
  key exfiltration.
Evidence:
  // src/components/user-center/DiscussionRecordsTable.tsx:172
  <div
    className="comment-text"
    dangerouslySetInnerHTML={{ __html: record.commentContent }}
  />

  // Line 90 — renderContent() IS called in the useMemo:
  const commentContent = renderContent(comment.text || '');

  // However, other components (CommentItem.tsx:208, CommentReply.tsx:155, etc.)
  // call renderContent() inline at the JSX level, which is the safer pattern:
  dangerouslySetInnerHTML={{ __html: renderContent(comment.content) }}
Judge: CONFIRMED — While the current code path does pass through renderContent(),
  the pattern is fragile: the sanitization happens in a useMemo callback separate
  from the rendering site. All other components in the codebase apply DOMPurify
  inline at the JSX level. This inconsistency creates risk of regression — a
  refactor adding a new code path to set commentContent could bypass sanitization.
  The DOMPurify configuration also allows the 'style' attribute
  (ALLOWED_ATTR includes 'style'), which can enable CSS-based data exfiltration
  in some browsers.
Remediation:
  1. Apply renderContent() (DOMPurify sanitization) inline at the JSX level,
     matching the pattern used in CommentItem.tsx and CommentReply.tsx:
     dangerouslySetInnerHTML={{ __html: renderContent(record.commentContent) }}
  2. Remove 'style' from ALLOWED_ATTR in all DOMPurify configurations across
     the codebase to prevent CSS injection vectors.
Reference: references/xss.md
```

```
[MEDIUM] VULN-003 — Weak PIN Protection for QR Code Key Export  [CONFIRMED]
File: src/components/user-center/KeyQRCodeModal.tsx:42-49, 57-58
Description: The QR code key export feature encodes the user's private signing
  key (signKey) into a QR code "protected" by only a 4-digit numeric PIN
  (10,000 possible combinations). The PIN is included in the plaintext JSON
  alongside the signing key — it is not used for encryption.
Impact: Anyone who photographs or scans the QR code obtains the user's private
  signing key in plaintext. The 4-digit PIN provides negligible protection — it
  is included in the data itself (not used as an encryption key) and can be
  brute-forced in milliseconds. A shoulder-surfing attack, screenshot, or
  compromised camera can capture the QR code.
Evidence:
  // src/components/user-center/KeyQRCodeModal.tsx:42-49
  const data = {
    did: tokenData.did,
    signKey: tokenData.signKey,        // PRIVATE KEY in plaintext
    walletAddress: tokenData.walletAddress,
    password: password,                 // 4-digit PIN included in data
    timestamp: Date.now(),
  };
  return JSON.stringify(data);         // Unencrypted JSON → QR code

  // src/components/user-center/KeyQRCodeModal.tsx:57-58
  if (password.length !== 4 || !/^\d{4}$/.test(password)) {
    return; // Only requires 4 digits
  }

  // Compare with file export (ExportDIDInfoModal.tsx) which uses proper
  // AES-GCM encryption with 8-character alphanumeric password via PBKDF2:
  const content = await encryptData(JSON.stringify(tokenData), passwordRef.current);
Judge: CONFIRMED — The QR code contains the raw private key. The password field
  is a verification hint, not a cryptographic protection. The file export path
  (ExportDIDInfoModal) correctly encrypts with AES-GCM + PBKDF2, proving the
  codebase has the capability — it was simply not applied here.
Remediation:
  1. Use the existing encryptData() function from src/lib/encrypt.ts to
     encrypt the QR code data with AES-GCM before encoding.
  2. Require a minimum 8-character alphanumeric password (matching file export).
  3. Remove the plaintext password from the QR code data — it should only
     be used as the encryption key input.
  4. On the scanning side (ScanQRCodeModal.tsx), decrypt using decryptData()
     before processing.
Reference: references/weak_crypto_hash.md
```

## Low Findings

```
[LOW] VULN-004 — Information Disclosure via Backend Error Forwarding  [CONFIRMED]
File: src/app/api/meeting/route.ts:51-56, src/app/api/task/route.ts:90-95,
      src/app/api/proposal/list_self/route.ts:87-92, src/app/api/proposal/replied/route.ts:87-92,
      src/app/api/vote/list_self/route.ts:87-92, src/app/api/notion/route.ts:51-56
Description: All Next.js API route handlers forward raw error messages from the
  backend server or third-party services (Notion API) to the client response.
  This includes axios error messages which may contain internal URLs, server
  hostnames, stack traces, or backend implementation details.
Impact: An attacker can trigger error conditions to learn the backend API server
  address (NEXT_PUBLIC_API_ADDRESS), internal endpoint paths, backend error
  message formats, and potentially database or service error details that aid
  further attacks.
Evidence:
  // src/app/api/meeting/route.ts:51-56 (pattern repeated in all API routes)
  if (axios.isAxiosError(error)) {
    const status = error.response?.status || 500;
    const errorMessage = error.response?.data?.message
      || error.message               // <-- raw axios error message
      || "Failed to fetch meeting list";
    return NextResponse.json(
      { error: errorMessage },       // <-- forwarded to client
      { status }
    );
  }

  // src/app/api/notion/route.ts:51-56 — Notion API error messages forwarded
  const message = lastErr instanceof Error ? lastErr.message : "notion error";
  return NextResponse.json(
    { error: message },              // <-- raw Notion API error to client
    { status: 502 }
  );
Judge: CONFIRMED — All 6 API route handlers follow the same pattern of forwarding
  raw error.message to the client. While NEXT_PUBLIC_API_ADDRESS is already a
  public environment variable, the backend may return error messages containing
  database details, internal service names, or stack traces that should not be
  exposed.
Remediation: Return generic error messages to the client (e.g., "Service
  unavailable") and log the detailed error server-side. Use the existing logger
  to capture the full error for debugging while returning only a sanitized
  message to the client response.
Reference: references/information_disclosure.md
```

## Informational

```
[INFO] VULN-005 — Debug Transaction Tool Accessible in Production
File: src/app/[locale]/debug/send-tx/page.tsx
Description: A debug transaction tool page is present at /[locale]/debug/send-tx
  that allows constructing and sending arbitrary CKB transactions with custom
  outputsData. There is no access control or authentication check on this page.
Impact: In a production deployment, this page allows any authenticated wallet
  user to send arbitrary transactions and update vote meta transaction hashes
  on the server. While this requires wallet connection and signing, it provides
  a convenient interface for transaction manipulation that should not be
  available in production.
Evidence:
  // src/app/[locale]/debug/send-tx/page.tsx — no auth check
  export default function TransactionDebugTool() {
    // ... allows arbitrary outputsData input and transaction sending
    // Also calls updateVoteMetaTxHash with arbitrary voteMetaId
  }
Judge: The page requires wallet connection to function, so it cannot be exploited
  without an authenticated wallet. However, it provides a convenient tool for
  manipulating transactions that is clearly intended for development use only.
  The middleware.ts does not exclude this route, so it is accessible in production.
Remediation: Either:
  1. Remove the debug page from production builds using Next.js environment
     checks or conditional routing.
  2. Add authentication/authorization checks (admin-only access).
  3. Move to a separate development-only tool outside the main application.
Reference: references/information_disclosure.md
```

## Unverifiable Findings

_None._

## Remediation Priority

1. **VULN-001 (Signing Key in localStorage)** — Encrypt the signing key at rest using the existing AES-GCM encryption infrastructure. This is the highest priority as it affects every user and the signing key cannot be rotated without on-chain account recreation.
2. **VULN-003 (Weak QR Code PIN)** — Encrypt QR code data with AES-GCM using a stronger password. This directly exposes private keys to physical proximity attacks.
3. **VULN-002 (XSS Pattern Inconsistency)** — Apply DOMPurify inline at the render site and remove 'style' from allowed attributes. While the current code path is safe, the fragile pattern risks regression.
4. **VULN-004 (Error Message Forwarding)** — Replace raw error forwarding with generic messages in all API route handlers.
5. **VULN-005 (Debug Page)** — Remove or gate the debug transaction tool for production deployments.

---

## Appendix: Analysis Summary

### Technology Stack
- **Framework**: Next.js 15.5.9 with React 19.1.0, TypeScript 5
- **Runtime**: Node.js (server-side API routes) + Browser (client-side SPA)
- **Authentication**: Secp256k1 ECDSA key-pair via @atproto/crypto, session-based JWT via web5-api/AtpAgent
- **HTTP Client**: Axios (client→Next.js API routes→backend)
- **Blockchain**: CKB (Nervos Network) via @ckb-ccc/core, @ckb-ccc/connector-react
- **Identity**: AT Protocol (atproto) with DID:CKB identifiers
- **Sanitization**: DOMPurify 3.3.1 for HTML sanitization
- **Encryption**: Web Crypto API (AES-GCM + PBKDF2) for DID export
- **State**: Zustand for client-side state management

### Areas Analyzed
- All 8 Next.js API routes (server-side handlers)
- All client-side API definitions in src/server/
- Authentication and session management (PDS client, session wrapper)
- Cryptographic key generation, storage, and usage
- All `dangerouslySetInnerHTML` sinks (14 total across 7 components)
- DOMPurify sanitization configuration consistency
- Middleware and routing security
- Export/import flows for DID credentials
- Debug and development tooling

### Clean Areas
- **SQL Injection**: Not applicable — the frontend does not directly access databases. All data access goes through the backend API via parameterized HTTP requests.
- **XSS (general)**: Excellent hygiene — 13 of 14 `dangerouslySetInnerHTML` sinks are properly sanitized with DOMPurify using restrictive ALLOWED_TAGS and ALLOWED_ATTR configurations.
- **SSRF**: API routes construct backend URLs using a server-configured base URL (NEXT_PUBLIC_API_ADDRESS). User input only controls query parameters (did, page, per_page), never the host or path base. URLSearchParams properly encodes parameter values.
- **CSRF**: Not applicable — the application uses Bearer token authentication (JWT) via Authorization headers, not cookies. Session-based authentication is managed through the PDS client's session manager.
- **Open Redirect**: The middleware redirect only uses locale prefixes from a hardcoded allowlist. The `window.open` call in ProposalTimeline validates URLs with `new URL()` and only allows http/https protocols.
- **Path Traversal**: The only file system access is reading `public/chart.csv` via a hardcoded path using `join(process.cwd(), "public", "chart.csv")` — no user input in file paths.
- **Encryption**: The AES-GCM + PBKDF2 (100,000 iterations) implementation in encrypt.ts is correctly implemented with random salt and IV for DID file export.
- **RCE**: No `eval()`, `Function()`, or shell execution found in the codebase.
