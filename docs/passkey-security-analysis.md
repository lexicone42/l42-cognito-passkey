# Passkey Security Analysis

**Date**: 2026-02-19
**Version**: 0.18.0
**Context**: Security review prompted by Cloudbrothers "Are Passkeys As Secure As You Think" (Disobey 2026) and device attestation integration planning.

## Current Posture

### What We Do Well

| Control | Implementation |
|---|---|
| **Server-side sessions** | HttpOnly cookies via Token Handler pattern — tokens never accessible to JS |
| **CSRF protection** | `X-L42-CSRF` header on all authenticated requests |
| **CSP guidance** | Nonce-based CSP, no `'unsafe-inline'` |
| **User verification** | `userVerification: 'preferred'` — biometric/PIN when available |
| **Discoverable credentials** | `residentKey: 'required'` — conditional UI / autofill compatible |
| **Cedar authorization** | Server-side policy evaluation, fail-closed (503) |

### Known Gaps

| Gap | Risk | Status |
|---|---|---|
| **No attestation enforcement** | Can't distinguish YubiKey from synced iCloud passkey | **Partially mitigated (v0.19.0)**: `attestation: 'direct'` option available; server-side AAGUID validation pending |
| **No BE/BS flag inspection** | Can't policy-gate "device-bound credentials only" | **Mitigated (v0.19.0)**: BE/BS flags parsed and included in OCSF events + credential responses |
| **Fallback authentication** | AiTM proxy strips passkey UI, shows password form | **Documented**: See `docs/cognito-setup.md` "Passkey-Only Deployment" section |
| **Browser extension hijacking** | `webAuthenticationProxy` API allows interception | Cannot mitigate client-side; recommend extension allowlists |
| **Synced passkey cloud compromise** | iCloud/Google account takeover → passkey access | **Partially mitigated**: AAGUID extraction + attestation option available; Cedar AAGUID allowlist pending |

## Attack Vectors

### 1. AiTM / Authentication Downgrade

**How it works**: Phishing proxy (Evilginx, Mamba 2FA, Tycoon 2FA) sits between user and real login page. Proxy modifies HTML/CSS/JS to remove passkey authentication prompts, forcing fallback to password. Once password entered, proxy captures session token.

**Our exposure**: If the Cognito User Pool allows password login alongside passkeys, the passkey's phishing resistance is bypassed. "Your weakest authentication method defines your real security."

**Mitigation**: Disable `ALLOW_USER_SRP_AUTH` and `ALLOW_USER_PASSWORD_AUTH` in Cognito User Pool for passkey-only deployments. This is the single highest-impact mitigation.

### 2. Cloud Account Compromise (Synced Passkeys)

**How it works**: Synced passkeys (iCloud Keychain, Google Password Manager, 1Password) replicate credentials across devices. Compromising the cloud account grants access to all synced passkeys.

**Our exposure**: We default to `attestation: 'none'` and allow all authenticator types.

**Mitigation**: For high-assurance deployments, require device-bound passkeys via attestation + AAGUID allowlist. For consumer deployments, accept synced passkeys (convenience > marginal risk).

### 3. QR/Cross-Device (caBLE/Hybrid) Exploitation

**How it works**: Fake QR code presented during login tricks user into authenticating on attacker's session. The "PoisonSeed" campaign (July 2025) exploited this at scale.

**Our exposure**: Low — Cognito's WebAuthn flow uses `navigator.credentials.get()` directly, not the hybrid/caBLE transport. Users would need to explicitly scan a QR code.

### 4. Browser Extension Hijacking

**How it works**: Chrome's `webAuthenticationProxy` API allows extensions to intercept `navigator.credentials.create()` and `.get()` calls. SquareX research showed extensions can reinitiate registration, force password fallback, or silently complete assertions.

**Our exposure**: Yes — this is a browser-level threat. CSP doesn't help because extensions run in a separate execution context.

**Mitigation**: Enterprise deployments should enforce browser extension allowlists. Cannot be mitigated in library code.

### 5. Session Token Theft (Post-Auth)

**How it works**: After valid passkey authentication, the session cookie or token is stolen via XSS, compromised browser extension, or malware.

**Our exposure**: Mitigated by HttpOnly cookies and CSRF tokens. Still vulnerable if XSS exists in the application.

### 6. Fallback Method Weakness

**How it works**: Account recovery via email link, SMS code, or security questions bypasses passkey security entirely.

**Our exposure**: Cognito-dependent. If the User Pool allows password recovery via email, that's the weakest link.

**Mitigation**: Use "magic link to registered email" or "second passkey/FIDO2 key" as recovery methods. Document this in deployment guidance.

## Device Attestation

### What Attestation Provides

At registration time, the authenticator can include an **attestation statement** proving its identity:

- **AAGUID**: 128-bit identifier for the authenticator make/model
- **Attestation signature**: Signed by manufacturer's key, verifiable against FIDO Metadata Service
- **Attestation format**: packed, tpm, android-key, apple, none

### Authenticator Data Flags (Available Without Attestation)

Byte 32 of `authenticatorData` contains flags that are always present:

| Bit | Flag | Meaning |
|-----|------|---------|
| 0 | UP | User Present |
| 2 | UV | User Verified |
| 3 | BE | Backup Eligible — credential CAN be synced |
| 4 | BS | Backup State — credential IS currently synced |
| 6 | AT | Attested Credential Data included |
| 7 | ED | Extension Data included |

The BE/BS combination tells you:

| BE | BS | Meaning |
|----|-----|---------|
| 0 | 0 | Device-bound, single-device credential (e.g., YubiKey) |
| 1 | 0 | Eligible for sync but not yet synced |
| 1 | 1 | Synced/multi-device credential (e.g., iCloud Keychain) |
| 0 | 1 | Invalid combination per spec |

### AWS Cognito Limitation

Cognito does **not** process attestation server-side. It stores the credential but doesn't validate attestation statements or expose AAGUID/backup flags. Any attestation-based policy must be implemented in our backend (Rust/Express).

### Implementation Levels

**Level 1 — Flag Parsing (client-side, informational)**
Parse authenticatorData to extract AAGUID and BE/BS flags. Include in OCSF events and expose to backend. ~50 lines of code.

**Level 2 — Attestation Request**
Allow deployers to set `attestation: 'direct'` in registration options. The attestation object already flows through to Cognito (which ignores it), but our backend can validate it.

**Level 3 — Server-Side Validation**
In the Rust backend: parse attestationObject (CBOR), verify attestation signature chain, check AAGUID against allowlist, enforce BE/BS policy. Requires CBOR parsing and certificate chain validation.

**Level 4 — FIDO MDS Integration**
Download FIDO Alliance Metadata Service blob, map AAGUIDs to authenticator metadata (manufacturer, security level, key protection type). Full enterprise-grade solution.

## Recommendations (Priority Order)

1. ~~**Document "disable password fallback"**~~ — **DONE**: See `docs/cognito-setup.md` "Passkey-Only Deployment" section. Covers CDK, CloudFormation, boto3, AWS Console steps + dev workflow + account recovery.

2. ~~**Parse BE/BS flags from authenticatorData**~~ — **DONE (v0.19.0)**: `parseAuthenticatorData()` extracts UP, UV, BE, BS, AT, ED flags + signCount + AAGUID. Integrated into `buildCredentialResponse()` and `buildAssertionResponse()`. Included in OCSF events as `metadata.backup_eligible`, `metadata.backup_state`, `metadata.aaguid`. 38 dedicated tests.

3. ~~**Add `attestation` option to `registerPasskey()`**~~ — **DONE (v0.19.0)**: `options.attestation` parameter on `registerPasskey()` and `upgradeToPasskey()`. Supports `'none'` (default), `'indirect'`, `'direct'`, `'enterprise'`. Attestation level included in OCSF metadata.

4. **AAGUID allowlist in Cedar** — Cedar policy to enforce device-type restrictions at registration time. Requires the Rust backend to extract AAGUID from the attestation object server-side and pass it as a Cedar context attribute.

5. **FIDO MDS integration** — Full meal. Only needed for enterprise/high-assurance deployments. Post-1.0 work.

## Sources

- [How Attackers Bypass Synced Passkeys — The Hacker News](https://thehackernews.com/2025/10/how-attackers-bypass-synced-passkeys.html)
- [Passkeys aren't attack-proof — CSO Online](https://www.csoonline.com/article/2513273/passkeys-arent-attack-proof-not-until-properly-implemented.html)
- [Attestation Guide — Yubico](https://developers.yubico.com/Passkeys/Passkey_relying_party_implementation_guidance/Attestation/)
- [Mitigating AiTM Token Theft — The Cloud Technologist](https://thecloudtechnologist.com/2025/03/16/mitigating-aitm-token-theft-in-2025-why-its-time-to-adopt-passkeys/)
- [Passkey Phishing — Risky Business](https://risky.biz/risky-bulletin-passkeys-are-phishable-but-quite-difficult-through/)
- [Hackers Break Passkeys via AitM — CyberSecurityNews](https://cybersecuritynews.com/passkeys-via-aitm-phishing-attacks/)
- [AWS Cognito Passkeys + Corbado — AWS Blog](https://aws.amazon.com/blogs/apn/maximizing-passkey-adoption-with-amazon-cognito-and-corbado/)
- [AAGUID Explained — Corbado](https://www.corbado.com/glossary/aaguid)
- [Cloudbrothers Passkey Preview — Entra ID](https://cloudbrothers.info/passkey-public-preview-entra-id/)
- [FIDO2 Key Restrictions — Cloudbrothers](https://cloudbrothers.info/en/journey-passwordless-restrict-fido2/)
