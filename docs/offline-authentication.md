# VenVia 0.4 — Offline authentication policy

Approved change: username and password only for every user, including administrators. No MFA, TOTP, SMS or email OTP, external identity provider or online activation dependency. Technical administrator retains an offline recovery key. This supersedes earlier MFA requirements; implementation and tests remain pending.

## Local identity and access
- Local authoritative database and PHP password_hash/password_verify with Argon2id where supported; rehash when policy changes. Never store plaintext passwords or log credentials.
- Allow long passphrases (proposed minimum 15 characters, at least 64 characters supported); no silent truncation. Avoid arbitrary periodic expiry; require change after compromise or administrator reset.
- Persistent local login throttling, generic failure messages, CSRF protection, secure HttpOnly session cookies and session ID rotation. No remote service required.
- Authorized administrators can reset passwords and revoke accounts within their existing role hierarchy. Operational administrator cannot reset, revoke or impersonate the technical administrator. Prevent removal of the sole technical administrator. Reset uses a temporary credential requiring change; never reveal an existing password.
- Revocation and reset invalidate existing sessions and credentials server-side immediately; authorization checks run on every protected request. Audit actor, target, action and local timestamp, never secrets.
- Self-service password change requires current password. External email is optional contact metadata, not a recovery dependency.

## Technical administrator recovery
- Generate a cryptographically random recovery key (at least 256 bits) during initial setup; display/download once for offline storage. Store only its digest in the protected database. Do not include the plaintext key in logs, exports or backups. Use constant-time comparison and persistent rate limits.
- A dedicated recovery form over trusted local HTTPS accepts the key and a new password, atomically consumes the old key, invalidates sessions and issues a replacement key. No internet, SMS or email required. Recovery is only for the technical administrator, not a bypass for ordinary users.
- Loss of both password and recovery key does not justify a hidden master password or unauthenticated reset.

## Offline acceptance criteria
Disconnect WAN while retaining LAN, reboot server and clients, login as each role, change/reset password, revoke access and verify existing sessions fail, recover technical admin and verify old key cannot be reused. Test database persistence, rate limiting and audit. Validate HTTPS chain, hostname and expiration independently. DNS must resolve locally; initial public certificate issuance and renewal can require WAN. A locally trusted CA is a proposed option for extended offline operation, not an authorized certificate bypass. Cross-store sync and online channels may be temporarily unavailable during WAN outage.
