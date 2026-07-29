# Root-action WebAuthn authorization contract

This contract governs approval of a sealed typed root action. It does not
authorize publication, installation, service activation, or a particular
production action.

## Credential boundary

- Approval uses WebAuthn public-key credentials only.
- The normal office credential is a Windows Hello platform credential.
- The normal remote credential is a phone passkey.
- A separately enrolled FIDO2 credential is reserved for recovery.
- Linux root passwords, OPS passwords, TOTP values, and the existing
  `ops_console_token` are not root-action approval credentials or fallbacks.
- Every registration and assertion requires user verification. The verifier
  rejects a response without the WebAuthn UV flag.

Authenticator private keys never enter the repository, root-action database,
OPS database, logs, receipts, agents, or command-line arguments. The root-owned
database stores only credential identifiers, COSE public keys, counters,
credential metadata, challenges, and audit records.

## Authority and exact-action binding

The root broker owns the relying-party identifier, exact allowed HTTPS origin,
credential records, challenge records, approval records, state ledger, and
execution claim. The `svcops` OPS web process is an untrusted presentation and
transport adapter for this boundary; it cannot mint an approval assertion.

An approval challenge is derived from a domain separator, the sealed
`job_digest`, a root-generated random nonce, and an expiry. The root database
stores that exact tuple. Completing an approval must atomically:

1. verify the WebAuthn assertion against the registered public key, RP ID,
   exact origin, stored challenge, and required UV flag;
2. consume the challenge once;
3. append an approval audit record for the same `job_id` and `job_digest`;
4. update the credential counter under compare-and-swap semantics; and
5. claim the pending job exactly once.

The browser response, OPS session, credential identity, or job identifier may
not substitute for the sealed digest. A stale, replayed, expired, wrong-origin,
wrong-RP, wrong-digest, non-UV, revoked-credential, or counter-regressing
assertion fails closed and executes nothing.

## Enrollment and recovery

Ordinary OPS access cannot enroll or revoke credentials. Initial enrollment is
disabled until root creates a bounded, single-use bootstrap session. Later
credential management requires a separately authorized recovery ceremony.
Bootstrap and recovery authorize credential management only; they do not claim
or execute a root action.

Loss of every approval and recovery credential requires an explicit local-root
recovery procedure. There is no password or TOTP downgrade path.

## Dispatch and evidence

Only an enabled operation in the executable registry may have a handler.
`kwrag.network_ensure` remains `disabled_by_product_boundary`, has no handler,
and can never consume an approval or claim execution. The worker receives the
already sealed manifest bytes and the claimed digest; it never receives an
authenticator private key, browser session secret, or approval credential.

Raw output remains root-only. The OPS page and original requester receive only
the canonical sanitized status, immutable history, and terminal receipt. A
local source test, successful registration, valid assertion, or claimed job is
not an operational E2E receipt.

The installed agent MCP exposes only `root_action_submit`,
`root_action_retrieve`, and `root_action_wait`. Submit revalidates the exact
typed manifest and returns the complete four-field recovery handle (`job_id`,
`job_digest`, `request_id`, and `reply_target`). It does not approve or execute. Retrieve is a
read-only snapshot. Wait polls for a bounded interval and returns either the
identity-bound terminal receipt or the unchanged retryable handle. The agent
that submitted the request must keep calling wait itself; the user is never
asked to run a root shell, wait in a terminal, or carry output back. No MCP
authentication, enrollment, approval, arbitrary-shell, or generic privileged
command is exposed.

If the submit response is lost, the MCP adapter returns the handle derived from
the already sealed manifest with `acceptance_state=unknown`. The requester must
retrieve that exact handle before considering any new submission; it may not
change the digest or create a second execution attempt as a recovery shortcut.

## Installation inputs and fail-closed startup

The root service reads `/etc/agent-runtime-ops/root-action-webauthn.env`. It is
not created from repository defaults because the production HTTPS origin is a
host fact. The measured OPS production origin is `https://ops.ji-tech.co.kr`
and its narrow RP ID is `ops.ji-tech.co.kr`. The root-owned file must be mode
`0600` and contain:

```text
ROOT_ACTION_WEBAUTHN_RP_ID=ops.ji-tech.co.kr
ROOT_ACTION_WEBAUTHN_ORIGINS=https://ops.ji-tech.co.kr
ROOT_ACTION_WEBAUTHN_USER_ID=<32 random bytes encoded as 64 lowercase hex characters>
ROOT_ACTION_WEBAUTHN_RP_NAME=JI TECH root action
```

The OPS service must receive the same exact origin as
`OPS_ROOT_ACTION_ORIGIN`. Missing, HTTP, cross-RP, trailing-slash, or mismatched
values fail closed. The systemd unit does not start without the root environment
file, and the OPS mutation endpoints reject requests until their origin value is
configured.

After the approved ops release is installed, root activates this exact policy
through the typed command below. It creates the user ID with the kernel random
source, writes the environment atomically as root-only, refuses to replace a
different existing RP policy, and verifies that systemd reports the broker both
enabled and active. It never prints the user ID.

```text
opsctl root-action auth-activate --rp-id ops.ji-tech.co.kr --origin https://ops.ji-tech.co.kr
```

After the service starts, a kernel-authenticated root peer runs
`opsctl root-action auth-bootstrap` once. Its ten-minute token permits the three
fixed initial registrations only: office Windows Hello, remote phone passkey,
and a cross-platform, device-bound recovery FIDO2 credential. The token is
entered on `/root-actions/setup`; it is never an approval credential.

Source publication, CI, merge, installation, service activation, credential
enrollment, and a real browser-to-receipt observation are separate gates. The
source-level virtual-authenticator E2E does not satisfy any of those runtime
gates.
