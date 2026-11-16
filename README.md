Listing Evidence
An exchange research agent for the Agent Games Wildcard track.

Problem
A token price page, an exchange integration, and an available trading market are different claims. Tickers can also refer to unrelated assets. Research should keep those distinctions visible.

What the agent does
Given a ticker and optional EVM contract/network, it selects official Coinbase Exchange and Kraken public spot feeds, fetches and validates those feeds concurrently, resolves Kraken asset aliases, checks market status, and compares Coinbase network/contract metadata when provided. Its deterministic policy chooses between observed market, restricted/offline market, not observed, unavailable source, and unconfirmed identity. It retains timestamped source snapshots and returns a source-linked report.

Demo
Use the form at / or GET /api/report?symbol=BTC . Compare BTC with WPAX. A missing exact base match produces a bounded "not observed in this feed" result, never a claim about every product or a future listing. An optional contract query must include its network, for example /api/report?symbol=USDC&network=ethereum&contract=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 .

Interface
GET /health : service status.
GET /api/report?symbol=BTC : public, rate-limited research demo.
GET /evidence/<sha256> : retained public source bytes.
POST /agent : signed Agent Games preflight, or listing-evidence.research.v1 tasks with task_id, issued_at and input. Research tasks are idempotent. This custom research schema is not a scored Proof Gatekeeper or Steal the VFY implementation.

Design
This is an independently built deterministic research agent, not a general chat interface. Four allowlisted public feeds, bounded input, source validation, a five-minute cache, exact matching and fail-to-unknown behavior make the result inspectable. It has no wallet permissions, no trading function and no arbitrary URL fetching. It captures the evidence its policy uses so reviewers can reproduce the checks. No external model or API key is needed for the research.

Verification boundary
A SHA-256 snapshot fingerprint shows whether captured bytes match. It does not prove that an exchange published those bytes, that the bytes are true, or that the policy ran correctly. No zero-knowledge proof or zkTLS attestation is implemented. zkVerify could strengthen a future version by verifying a narrowly defined predicate over authenticated source data, but proof verification alone would not establish source truth.

Limits
The scope is public spot-market metadata from two venues. It does not check all exchange products, custody eligibility, jurisdiction/account permissions, future listings, announcements or investment merit. Matching symbols alone leave asset identity unverified. Kraken's selected feeds do not provide a token contract check. Results show source capture times and source failures. This first demo uses temporary hosting and requires a durable host before any uptime-sensitive scored competition.

Privacy
Only official public exchange response snapshots are persisted by the demo. It has no analytics or third-party scripts. Public demo queries are not stored. Signed task IDs, request digests and research responses are retained for idempotency; do not send personal or confidential material. No private conversations or account data are part of this build.

Run locally
Python 3.11+ is sufficient; there are no third-party Python dependencies.

python3 -m unittest discover -s . -p 'test_*.py' -v
python3 server.py

Open http://127.0.0.1:8768 . The service binds loopback. Optional PORT changes the port. The standard public research demo requires no API credentials. Platform HMAC configuration is optional, separate from the Wildcard submission.

Read source captures
Captured public API bytes live in private/evidence.sqlite3 and are served by exact SHA-256 at /evidence/<sha256>. The private directory is excluded from source control. No captured secrets, credentials or account data ship with this source.
